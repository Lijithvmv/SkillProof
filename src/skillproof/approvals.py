"""SQLite-backed human approval workflow with append-only audit events.

Authentication and authorization belong to the embedding application. Callers
must pass the authenticated principal identifier as submitter_id/actor_id.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


ApprovalAction = Literal["approve", "reject", "request_changes"]
TARGET_STATE = {"approve": "approved", "reject": "rejected", "request_changes": "changes_requested"}


class ApprovalError(ValueError):
    """Invalid approval workflow operation."""


class SQLiteApprovalStore:
    """Durable approval records and an audit event table protected from mutation."""

    def __init__(self, database: str | Path):
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.database, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.executescript("""
                PRAGMA foreign_keys = ON;
                CREATE TABLE IF NOT EXISTS approval_requests (
                    request_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    submitter_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    report_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('pending_review','approved','rejected','changes_requested')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL REFERENCES approval_requests(request_id),
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    comment TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS approval_events_no_update
                BEFORE UPDATE ON approval_events BEGIN SELECT RAISE(ABORT, 'approval events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS approval_events_no_delete
                BEFORE DELETE ON approval_events BEGIN SELECT RAISE(ABORT, 'approval events are append-only'); END;
            """)
            columns = {row[1] for row in self._connection.execute("PRAGMA table_info(approval_requests)")}
            if "tenant_id" not in columns:
                self._connection.execute("ALTER TABLE approval_requests ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'")
            self._connection.execute("CREATE INDEX IF NOT EXISTS idx_approval_requests_tenant ON approval_requests(tenant_id, request_id)")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    @staticmethod
    def _hash_report(report: dict[str, Any]) -> str:
        serialized = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def submit_for_review(self, report: dict[str, Any], *, submitter_id: str, tenant_id: str = "default") -> dict[str, Any]:
        if not submitter_id.strip() or not tenant_id.strip():
            raise ApprovalError("submitter_id and tenant_id are required")
        if report.get("decision") != "eligible_for_human_approval":
            raise ApprovalError("only reports eligible for human approval can enter review")
        if report.get("automatic_certification") is not False:
            raise ApprovalError("report must explicitly disable automatic certification")
        request_id = str(uuid.uuid4())
        now = self._now()
        digest = self._hash_report(report)
        policy_id = str(report.get("policy_id") or "unspecified")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT INTO approval_requests (request_id, tenant_id, submitter_id, policy_id, report_hash, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'pending_review', ?, ?)",
                    (request_id, tenant_id, submitter_id, policy_id, digest, now, now),
                )
                self._connection.execute(
                    "INSERT INTO approval_events (request_id, actor_id, action, comment, occurred_at) VALUES (?, ?, 'submitted', '', ?)",
                    (request_id, submitter_id, now),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self.get_request(request_id, tenant_id=tenant_id)

    def decide(self, request_id: str, *, actor_id: str, action: ApprovalAction, comment: str = "", tenant_id: str = "default") -> dict[str, Any]:
        if action not in TARGET_STATE:
            raise ApprovalError(f"unsupported approval action: {action}")
        if not actor_id.strip() or not tenant_id.strip():
            raise ApprovalError("actor_id and tenant_id are required")
        if len(comment) > 4000:
            raise ApprovalError("comment must be 4000 characters or fewer")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute("SELECT * FROM approval_requests WHERE request_id = ? AND tenant_id = ?", (request_id, tenant_id)).fetchone()
                if row is None:
                    raise ApprovalError("approval request not found")
                if row["state"] != "pending_review":
                    raise ApprovalError("approval request is already in a terminal state")
                if row["submitter_id"] == actor_id:
                    raise ApprovalError("submitter cannot approve or reject their own request")
                self._connection.execute(
                    "UPDATE approval_requests SET state = ?, updated_at = ? WHERE request_id = ? AND tenant_id = ?",
                    (TARGET_STATE[action], now, request_id, tenant_id),
                )
                self._connection.execute(
                    "INSERT INTO approval_events (request_id, actor_id, action, comment, occurred_at) VALUES (?, ?, ?, ?, ?)",
                    (request_id, actor_id, action, comment, now),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self.get_request(request_id, tenant_id=tenant_id)

    def get_request(self, request_id: str, *, tenant_id: str = "default") -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute("SELECT * FROM approval_requests WHERE request_id = ? AND tenant_id = ?", (request_id, tenant_id)).fetchone()
            if row is None:
                raise ApprovalError("approval request not found")
            events = self._connection.execute(
                "SELECT actor_id, action, comment, occurred_at FROM approval_events WHERE request_id = ? ORDER BY event_id",
                (request_id,),
            ).fetchall()
        return {**dict(row), "events": [dict(event) for event in events]}

    def close(self) -> None:
        with self._lock:
            self._connection.close()
