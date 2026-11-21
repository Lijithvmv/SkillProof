"""Background evaluation jobs: the service produces a skill version's run evidence itself.

A version arrives with static evidence only. An evaluation job builds conformance tests from the skill's own rules,
runs the agent with and without the skill on the configured local model, records the experiment in the tenant's
history and assesses the version again on it. Jobs run one at a time (a local model shares one GPU).

Two tables. `evaluation_jobs` holds each job and its result, with the same tenant row-level security as the rest of
the catalogue. `job_queue` holds only job and tenant ids, no content, so the worker can find the next job without
reading any tenant's data; it then works inside that job's tenant.
"""
from __future__ import annotations

from skillproof.errors import Conflict, NotFound

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillproof.storage import Database, tenant_policy

STATES = ("queued", "running", "done", "failed")
COMMON = """
    CREATE TABLE IF NOT EXISTS evaluation_jobs (
        job_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        version_id TEXT NOT NULL,
        skill_name TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('queued','running','done','failed')),
        requested_by TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        result_json TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_evaluation_jobs_version ON evaluation_jobs(tenant_id, version_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS job_queue (
        job_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        claimed_at TEXT
    );
"""


class JobError(Conflict):
    """Invalid job operation."""


class JobNotFound(JobError, NotFound):
    """The job item asked for does not exist in this tenant."""


class JobStore:
    def __init__(self, database: str | Path):
        self.db = Database(database)
        self.db.script(COMMON + (tenant_policy("evaluation_jobs") if self.db.postgres else ""))

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def enqueue(self, tenant_id: str, version_id: str, skill_name: str, payload: dict[str, Any], *, requested_by: str) -> dict[str, Any]:
        """Queue an evaluation of one version. A version with a job still queued or running gets that job back."""
        if not tenant_id.strip() or not requested_by.strip():
            raise JobError("tenant_id and requested_by are required")
        now = self._now()
        with self.db.transaction(tenant_id, write=True) as db:
            open_job = db.execute("SELECT job_id FROM evaluation_jobs WHERE tenant_id=? AND version_id=? AND state IN ('queued','running')",
                                  (tenant_id, version_id)).fetchone()
            if open_job:
                job_id = open_job["job_id"]
            else:
                job_id = str(uuid.uuid4())
                db.execute("INSERT INTO evaluation_jobs (job_id, tenant_id, version_id, skill_name, state, requested_by, payload_json, created_at) "
                           "VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)",
                           (job_id, tenant_id, version_id, skill_name, requested_by, json.dumps(payload, ensure_ascii=False), now))
                db.execute("INSERT INTO job_queue (job_id, tenant_id, created_at) VALUES (?, ?, ?)", (job_id, tenant_id, now))
        return self.get(tenant_id, job_id)

    def claim(self) -> tuple[str, dict[str, Any]] | None:
        """Take the oldest queued job and mark it running. Returns (tenant_id, job with payload) or None."""
        now = self._now()
        with self.db.transaction(None, write=True) as db:
            row = db.execute("SELECT job_id, tenant_id FROM job_queue WHERE claimed_at IS NULL "
                             "ORDER BY created_at, job_id LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE job_queue SET claimed_at=? WHERE job_id=?", (now, row["job_id"]))
        tenant_id, job_id = row["tenant_id"], row["job_id"]
        with self.db.transaction(tenant_id, write=True) as db:
            db.execute("UPDATE evaluation_jobs SET state='running', started_at=? WHERE job_id=?", (now, job_id))
            job = db.execute("SELECT * FROM evaluation_jobs WHERE job_id=?", (job_id,)).fetchone()
        return (tenant_id, self._decode(job, payload=True)) if job else None

    def _close(self, tenant_id: str, job_id: str, sql: str, params: tuple) -> dict[str, Any]:
        with self.db.transaction(tenant_id, write=True) as db:
            db.execute(sql, params)
        with self.db.transaction(None, write=True) as db:
            db.execute("DELETE FROM job_queue WHERE job_id=?", (job_id,))
        return self.get(tenant_id, job_id)

    def finish(self, tenant_id: str, job_id: str, result: dict[str, Any]) -> dict[str, Any]:
        return self._close(tenant_id, job_id, "UPDATE evaluation_jobs SET state='done', result_json=?, finished_at=? WHERE job_id=?",
                           (json.dumps(result, ensure_ascii=False), self._now(), job_id))

    def fail(self, tenant_id: str, job_id: str, error: str) -> dict[str, Any]:
        return self._close(tenant_id, job_id, "UPDATE evaluation_jobs SET state='failed', error=?, finished_at=? WHERE job_id=?",
                           (error[:2000], self._now(), job_id))

    def recover(self) -> int:
        """Jobs a stopped server had claimed go back to waiting. Returns how many."""
        with self.db.transaction(None, write=True) as db:
            claimed = db.execute("SELECT job_id, tenant_id FROM job_queue WHERE claimed_at IS NOT NULL").fetchall()
            db.execute("UPDATE job_queue SET claimed_at=NULL WHERE claimed_at IS NOT NULL")
        for row in claimed:
            with self.db.transaction(row["tenant_id"], write=True) as db:
                db.execute("UPDATE evaluation_jobs SET state='queued', started_at=NULL WHERE job_id=?", (row["job_id"],))
        return len(claimed)

    def get(self, tenant_id: str, job_id: str) -> dict[str, Any]:
        with self.db.transaction(tenant_id) as db:
            row = db.execute("SELECT * FROM evaluation_jobs WHERE tenant_id=? AND job_id=?", (tenant_id, job_id)).fetchone()
        if row is None:
            raise JobNotFound("job not found in this tenant")
        return self._decode(row)

    def for_version(self, tenant_id: str, version_id: str) -> list[dict[str, Any]]:
        with self.db.transaction(tenant_id) as db:
            rows = db.execute("SELECT * FROM evaluation_jobs WHERE tenant_id=? AND version_id=? ORDER BY created_at DESC",
                              (tenant_id, version_id)).fetchall()
        return [self._decode(r) for r in rows]

    @staticmethod
    def _decode(row: Any, *, payload: bool = False) -> dict[str, Any]:
        job = {k: row[k] for k in ("job_id", "tenant_id", "version_id", "skill_name", "state", "requested_by", "error",
                                   "created_at", "started_at", "finished_at")}
        job["result"] = json.loads(row["result_json"]) if row["result_json"] else None
        if payload:
            job["payload"] = json.loads(row["payload_json"])
        return job

    def close(self) -> None:
        self.db.close()
