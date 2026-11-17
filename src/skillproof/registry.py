"""Tenant-scoped skill version catalog with approval-gated promotion.

Each registered version can carry its capability manifest. The registry then compares it with the tenant's active
version of the same skill and ranks what the new version adds (block / ask / note). A version whose additions include
a block-level item can only be promoted when the approver acknowledges that exact change by its hash.

The host application supplies authenticated tenant/actor IDs and resolves
artifact_uri through its own object store. Package bytes are not stored here.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillproof.capabilities import diff_manifests
from skillproof.triage import triage

class RegistryError(ValueError):
    """Invalid registry operation."""


EMPTY_MANIFEST: dict[str, Any] = {"capabilities": {}, "scopes": {}}
MAX_CHANGE_ITEMS = 50


def _canonical_hash(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SQLiteSkillRegistry:
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
                CREATE TABLE IF NOT EXISTS skill_versions (
                    version_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    package_fingerprint TEXT NOT NULL,
                    assurance_hash TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    artifact_uri TEXT,
                    state TEXT NOT NULL CHECK (state IN ('pending_review','not_eligible','active','superseded')),
                    registered_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (tenant_id, skill_name, package_fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_skill_versions_tenant_name ON skill_versions(tenant_id, skill_name, created_at DESC);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_single_active_skill ON skill_versions(tenant_id, skill_name) WHERE state='active';
                CREATE TABLE IF NOT EXISTS registry_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id TEXT NOT NULL REFERENCES skill_versions(version_id),
                    tenant_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS registry_events_no_update
                BEFORE UPDATE ON registry_events BEGIN SELECT RAISE(ABORT, 'registry events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS registry_events_no_delete
                BEFORE DELETE ON registry_events BEGIN SELECT RAISE(ABORT, 'registry events are append-only'); END;
            """)
            columns = {row[1] for row in self._connection.execute("PRAGMA table_info(skill_versions)")}
            for column in ("assurance_json", "capabilities_json", "change_json"):
                if column not in columns:
                    self._connection.execute(f"ALTER TABLE skill_versions ADD COLUMN {column} TEXT")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def register(
        self, tenant_id: str, skill_report: dict[str, Any], assurance_report: dict[str, Any],
        *, actor_id: str, artifact_uri: str | None = None, capability_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        tenant_id, actor_id = tenant_id.strip(), actor_id.strip()
        if not tenant_id or not actor_id:
            raise RegistryError("tenant_id and actor_id are required")
        fingerprint = skill_report.get("package_fingerprint")
        name = (skill_report.get("metadata") or {}).get("name")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise RegistryError("skill report requires a valid package SHA-256 fingerprint")
        if not isinstance(name, str) or not name.strip():
            raise RegistryError("skill report requires a skill metadata name")
        if artifact_uri is not None and (len(artifact_uri) > 2048 or "\x00" in artifact_uri):
            raise RegistryError("artifact_uri must be 2048 characters or fewer")
        if capability_manifest is not None and not isinstance(capability_manifest.get("capabilities"), dict):
            raise RegistryError("capability manifest must come from build_manifest()")
        assurance_hash = _canonical_hash(assurance_report)
        state = "pending_review" if assurance_report.get("decision") == "eligible_for_human_approval" else "not_eligible"
        summary = {
            "schema_version": skill_report.get("schema_version"),
            "structural_score": skill_report.get("structural_score"),
            "instruction_quality_score": (skill_report.get("instruction_quality") or {}).get("quality_score"),
            "security_score": (skill_report.get("security") or {}).get("security_score"),
            "security_status": (skill_report.get("security") or {}).get("status"),
            "assurance_decision": assurance_report.get("decision"),
            "policy_id": assurance_report.get("policy_id"),
        }
        version_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT * FROM skill_versions WHERE tenant_id=? AND skill_name=? AND package_fingerprint=?",
                    (tenant_id, name, fingerprint),
                ).fetchone()
                if existing:
                    if existing["assurance_hash"] != assurance_hash:
                        raise RegistryError("this package fingerprint is already registered with a different assurance report")
                    self._connection.execute("COMMIT")
                    return self._decode(existing)
                change = None
                if capability_manifest is not None:
                    change = self._change(tenant_id, name, capability_manifest)
                    summary["capability_decision"] = change["decision"]
                    summary["capability_counts"] = change["counts"]
                self._connection.execute(
                    "INSERT INTO skill_versions (version_id, tenant_id, skill_name, package_fingerprint, assurance_hash, "
                    "summary_json, artifact_uri, state, registered_by, created_at, updated_at, assurance_json, "
                    "capabilities_json, change_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (version_id, tenant_id, name, fingerprint, assurance_hash,
                     json.dumps(summary, sort_keys=True, separators=(",", ":")), artifact_uri,
                     state, actor_id, now, now, _dump(assurance_report), _dump(capability_manifest), _dump(change)),
                )
                self._event(version_id, tenant_id, actor_id, "registered", state, now)
                if change is not None:
                    self._event(version_id, tenant_id, actor_id, "capabilities_compared",
                                f"{change['decision']} against {change['against']} {change['change_hash'][:12]}", now)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self.get_version(tenant_id, version_id)

    def promote(
        self, tenant_id: str, version_id: str, assurance_report: dict[str, Any],
        approval_record: dict[str, Any], *, actor_id: str, capability_ack: str | None = None,
    ) -> dict[str, Any]:
        tenant_id, actor_id = tenant_id.strip(), actor_id.strip()
        if not tenant_id or not actor_id:
            raise RegistryError("tenant_id and actor_id are required")
        if assurance_report.get("decision") != "eligible_for_human_approval":
            raise RegistryError("only assurance-eligible versions can be promoted")
        if approval_record.get("state") != "approved":
            raise RegistryError("an approved human review is required for promotion")
        if approval_record.get("tenant_id") != tenant_id:
            raise RegistryError("approval record belongs to a different tenant")
        if approval_record.get("report_hash") != _canonical_hash(assurance_report):
            raise RegistryError("approval record does not match the registered assurance report")
        events = approval_record.get("events") or []
        if not events or events[-1].get("action") != "approve" or events[-1].get("actor_id") == approval_record.get("submitter_id"):
            raise RegistryError("approval record must contain a separate human reviewer's approve event")
        now = self._now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM skill_versions WHERE tenant_id=? AND version_id=?", (tenant_id, version_id)
                ).fetchone()
                if row is None:
                    raise RegistryError("skill version not found in this tenant")
                if row["state"] != "pending_review":
                    raise RegistryError(f"version cannot be promoted from state '{row['state']}'")
                if row["assurance_hash"] != _canonical_hash(assurance_report):
                    raise RegistryError("assurance report does not match the registered version")
                if row["capabilities_json"]:
                    # Compare again: another version may have become active since this one was registered.
                    change = self._change(tenant_id, row["skill_name"], json.loads(row["capabilities_json"]))
                    if change["decision"] == "block" and capability_ack != change["change_hash"]:
                        reasons = "; ".join(f"{i['category']}: {i['value']}" for i in change["items"] if i["level"] == "block")[:500]
                        raise RegistryError(
                            "this version adds block-level capabilities (" + reasons + "); the approver must "
                            f"acknowledge capability change {change['change_hash']}")
                    self._connection.execute("UPDATE skill_versions SET change_json=? WHERE version_id=?", (_dump(change), version_id))
                    if change["decision"] == "block":
                        self._event(version_id, tenant_id, actor_id, "capabilities_acknowledged", change["change_hash"], now)
                active = self._connection.execute(
                    "SELECT version_id FROM skill_versions WHERE tenant_id=? AND skill_name=? AND state='active'",
                    (tenant_id, row["skill_name"]),
                ).fetchall()
                for old in active:
                    self._connection.execute("UPDATE skill_versions SET state='superseded', updated_at=? WHERE version_id=?", (now, old["version_id"]))
                    self._event(old["version_id"], tenant_id, actor_id, "superseded", version_id, now)
                self._connection.execute("UPDATE skill_versions SET state='active', updated_at=? WHERE version_id=?", (now, version_id))
                self._event(version_id, tenant_id, actor_id, "promoted", approval_record.get("request_id", ""), now)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return self.get_version(tenant_id, version_id)

    def _change(self, tenant_id: str, skill_name: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """What this manifest adds over the tenant's active version of the skill, ranked by triage."""
        active = self._connection.execute(
            "SELECT version_id, capabilities_json FROM skill_versions WHERE tenant_id=? AND skill_name=? AND state='active'",
            (tenant_id, skill_name),
        ).fetchone()
        if active is None:
            against, against_id, old = "nothing_active", None, EMPTY_MANIFEST
        elif not active["capabilities_json"]:
            against, against_id, old = "active_version_without_manifest", active["version_id"], EMPTY_MANIFEST
        else:
            against, against_id, old = "active_version", active["version_id"], json.loads(active["capabilities_json"])
        diff = diff_manifests(old, manifest)
        ranked = triage(diff, new_manifest=manifest)
        change = {
            "against": against,
            "against_version_id": against_id,
            "status": diff["status"],
            "decision": ranked["decision"],
            "counts": ranked["counts"],
            "items": ranked["items"][:MAX_CHANGE_ITEMS],
            "items_total": len(ranked["items"]),
            "combinations": ranked["combinations"],
            "removed": diff["removed"],
            "meaning": ranked["meaning"],
        }
        change["change_hash"] = _canonical_hash(change)
        return change

    def catalogue(self, tenant_id: str) -> list[dict[str, Any]]:
        """One entry per skill in the tenant: the active version and every version waiting for a decision."""
        with self._lock:
            rows = self._connection.execute(
                "SELECT version_id, skill_name, package_fingerprint, state, summary_json, created_at, updated_at "
                "FROM skill_versions WHERE tenant_id=? ORDER BY skill_name, created_at DESC, rowid DESC",
                (tenant_id,),
            ).fetchall()
        skills: dict[str, dict[str, Any]] = {}
        for row in rows:
            entry = skills.setdefault(row["skill_name"], {"skill_name": row["skill_name"], "active": None, "waiting": [], "versions": 0})
            entry["versions"] += 1
            summary = json.loads(row["summary_json"])
            brief = {
                "version_id": row["version_id"], "package_fingerprint": row["package_fingerprint"], "state": row["state"],
                "assurance_decision": summary.get("assurance_decision"),
                "capability_decision": summary.get("capability_decision"),
                "capability_counts": summary.get("capability_counts"),
                "security_status": summary.get("security_status"),
                "created_at": row["created_at"], "updated_at": row["updated_at"],
            }
            if row["state"] == "active":
                entry["active"] = brief
            elif row["state"] in {"pending_review", "not_eligible"}:
                entry["waiting"].append(brief)
        return list(skills.values())

    def get_assurance(self, tenant_id: str, version_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT assurance_json FROM skill_versions WHERE tenant_id=? AND version_id=?", (tenant_id, version_id)
            ).fetchone()
        if row is None:
            raise RegistryError("skill version not found in this tenant")
        if not row["assurance_json"]:
            raise RegistryError("this version was registered before assurance reports were stored")
        return json.loads(row["assurance_json"])

    def _event(self, version_id: str, tenant_id: str, actor_id: str, action: str, detail: str, timestamp: str) -> None:
        self._connection.execute(
            "INSERT INTO registry_events (version_id, tenant_id, actor_id, action, detail, occurred_at) VALUES (?, ?, ?, ?, ?, ?)",
            (version_id, tenant_id, actor_id, action, detail, timestamp),
        )

    def _decode(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["summary"] = json.loads(result.pop("summary_json"))
        for column, key in (("assurance_json", "assurance"), ("capabilities_json", "capabilities"), ("change_json", "capability_change")):
            raw = result.pop(column, None)
            result[key] = json.loads(raw) if raw else None
        result["events"] = [dict(event) for event in self._connection.execute(
            "SELECT actor_id, action, detail, occurred_at FROM registry_events WHERE version_id=? ORDER BY event_id", (row["version_id"],)
        ).fetchall()]
        return result

    def get_version(self, tenant_id: str, version_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute("SELECT * FROM skill_versions WHERE tenant_id=? AND version_id=?", (tenant_id, version_id)).fetchone()
            if row is None:
                raise RegistryError("skill version not found in this tenant")
            return self._decode(row)

    def list_versions(self, tenant_id: str, skill_name: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM skill_versions WHERE tenant_id=? AND skill_name=? ORDER BY created_at DESC, rowid DESC",
                (tenant_id, skill_name),
            ).fetchall()
            return [self._decode(row) for row in rows]

    def get_active(self, tenant_id: str, skill_name: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM skill_versions WHERE tenant_id=? AND skill_name=? AND state='active'",
                (tenant_id, skill_name),
            ).fetchone()
            if row is None:
                raise RegistryError("no active version found")
            return self._decode(row)

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _dump(value: dict[str, Any] | None) -> str | None:
    return None if value is None else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
