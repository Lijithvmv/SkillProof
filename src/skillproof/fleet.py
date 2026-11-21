"""Fleet: which machines run which skill versions, compared with what the catalogue approved.

Each machine reports the skills installed on it (name and package fingerprint, never contents) with
`skillproof fleet-report`. The server compares every skill with the tenant's active version: `approved` (same
fingerprint), `running_unapproved` (an approved version exists, the installed one differs) or `never_approved`. The
latest report per machine is kept with each skill's status, and a skill newly running unapproved on a machine raises
the `fleet.running_unapproved` alert. Tables have tenant row-level security.
"""
from __future__ import annotations

from skillproof.errors import Conflict, NotFound

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skillproof.storage import Database, tenant_policy

SCHEMA = """
    CREATE TABLE IF NOT EXISTS fleet_hosts (
        tenant_id TEXT NOT NULL,
        host TEXT NOT NULL,
        reported_by TEXT NOT NULL,
        reported_at TEXT NOT NULL,
        skills_json TEXT NOT NULL,
        counts_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, host)
    );
"""
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,252}$")
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
MAX_SKILLS = 2000


class FleetError(Conflict):
    """Invalid fleet report."""


class FleetNotFound(FleetError, NotFound):
    """The fleet item asked for does not exist in this tenant."""


class FleetStore:
    def __init__(self, database: str | Path):
        self.db = Database(database)
        self.db.script(SCHEMA + (tenant_policy("fleet_hosts") if self.db.postgres else ""))

    def record(self, tenant_id: str, host: str, skills: list[dict[str, Any]], *, reported_by: str) -> dict[str, Any]:
        if not HOST.match(host or ""):
            raise FleetError("host must be a machine name (letters, digits, dot, dash, underscore)")
        if len(skills) > MAX_SKILLS:
            raise FleetError(f"at most {MAX_SKILLS} skills per report")
        counts = {s: sum(k["status"] == s for k in skills) for s in ("approved", "running_unapproved", "never_approved")}
        now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self.db.transaction(tenant_id, write=True) as db:
            previous = db.execute("SELECT skills_json FROM fleet_hosts WHERE tenant_id=? AND host=?", (tenant_id, host)).fetchone()
            db.execute("INSERT INTO fleet_hosts (tenant_id, host, reported_by, reported_at, skills_json, counts_json) VALUES (?, ?, ?, ?, ?, ?) "
                       "ON CONFLICT (tenant_id, host) DO UPDATE SET reported_by=excluded.reported_by, reported_at=excluded.reported_at, "
                       "skills_json=excluded.skills_json, counts_json=excluded.counts_json",
                       (tenant_id, host, reported_by, now, json.dumps(skills), json.dumps(counts)))
        before = {(s["skill_name"], s["installed_fingerprint"]) for s in json.loads(previous["skills_json"]) if s["status"] == "running_unapproved"} if previous else set()
        newly = [s for s in skills if s["status"] == "running_unapproved" and (s["skill_name"], s["installed_fingerprint"]) not in before]
        return {"host": host, "reported_at": now, "counts": counts, "newly_unapproved": newly}

    def hosts(self, tenant_id: str) -> list[dict[str, Any]]:
        with self.db.transaction(tenant_id) as db:
            rows = db.execute("SELECT host, reported_by, reported_at, counts_json, skills_json FROM fleet_hosts WHERE tenant_id=? ORDER BY host",
                              (tenant_id,)).fetchall()
        return [{"host": r["host"], "reported_by": r["reported_by"], "reported_at": r["reported_at"], "counts": json.loads(r["counts_json"]),
                 "running_unapproved": [s for s in json.loads(r["skills_json"]) if s["status"] == "running_unapproved"]} for r in rows]

    def close(self) -> None:
        self.db.close()


def compare(versions_by_name: dict[str, list[dict[str, Any]]], installed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each installed skill's status against the tenant's versions of that name."""
    out = []
    for item in installed:
        name, fingerprint = str(item.get("skill_name", "")).strip(), str(item.get("fingerprint", "")).strip()
        if not name or not FINGERPRINT.match(fingerprint):
            raise FleetError("each skill needs a skill_name and a 64-hex package fingerprint")
        versions = versions_by_name.get(name, [])
        active = next((v for v in versions if v["state"] == "active"), None)
        known = next((v for v in versions if v["package_fingerprint"] == fingerprint), None)
        status = "never_approved" if active is None else "approved" if active["package_fingerprint"] == fingerprint else "running_unapproved"
        entry = {"skill_name": name, "installed_fingerprint": fingerprint, "status": status,
                 "approved_version_id": active["version_id"] if active else None,
                 "installed_version_id": known["version_id"] if known else None}
        if status == "running_unapproved" and known and known.get("capability_change"):
            change = known["capability_change"]
            entry["adds_over_approved"] = {"decision": change.get("decision"), "counts": change.get("counts")}
        out.append(entry)
    return out
