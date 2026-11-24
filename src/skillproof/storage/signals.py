"""Signals from real use: how often each skill runs, and the friction agents hit with it (papercuts).

Usage: agents' hooks record each skill run on the machine (`skillproof usage-hook`); `skillproof signals-report` sends
daily counts per skill, version and trigger ("agent": the agent chose the skill; "user": a person typed its command).
No prompt text, file contents or arguments are kept: names, fingerprints, counts and machine names only.

Papercuts: an agent that struggles with a skill (a flag the help lists and the tool rejects, a command that exits 0 on
an error, a query that returns nothing when it should match) files what it tried, what it expected, what happened and
what would fix it. Papercuts are grouped by skill for its owner, and closed with a note when fixed.

Both tables have tenant row-level security; papercuts are append-only except for their status.
"""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from skillproof.errors import Conflict, NotFound
from skillproof.storage import Database, migrate, tenant_policy

SCHEMA = """
    CREATE TABLE IF NOT EXISTS skill_usage (
        tenant_id TEXT NOT NULL,
        skill_name TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        day TEXT NOT NULL,
        host TEXT NOT NULL,
        chosen_by TEXT NOT NULL,
        invocations INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, skill_name, fingerprint, day, host, chosen_by)
    );
    CREATE TABLE IF NOT EXISTS papercuts (
        papercut_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        skill_name TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        tried TEXT NOT NULL,
        expected TEXT NOT NULL,
        happened TEXT NOT NULL,
        suggested_fix TEXT NOT NULL,
        host TEXT NOT NULL,
        reported_by TEXT NOT NULL,
        reported_at TEXT NOT NULL,
        status TEXT NOT NULL,
        resolution TEXT NOT NULL,
        resolved_by TEXT NOT NULL,
        resolved_at TEXT NOT NULL
    );
"""
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._\-]{0,199}$")
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,252}$")
FINGERPRINT = re.compile(r"^(?:[0-9a-f]{64})?$")
TRIGGERS = {"agent", "user"}
MAX_EVENTS = 5000
MAX_TEXT = 2000


class SignalError(Conflict):
    """An invalid usage report or papercut."""


class SignalNotFound(SignalError, NotFound):
    """The papercut asked for does not exist in this tenant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _text(value: Any, field: str, required: bool = True) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise SignalError(f"{field} is required")
    if len(text) > MAX_TEXT or "\x00" in text:
        raise SignalError(f"{field} must be text of at most {MAX_TEXT} characters")
    return text


class SignalStore:
    def __init__(self, database: str | Path):
        self.db = Database(database)
        migrate(self.db, "signals", [(1, "skill usage counts and papercuts", SCHEMA,
                                      SCHEMA + tenant_policy("skill_usage") + tenant_policy("papercuts"))])

    def record_usage(self, tenant_id: str, host: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Add daily counts. Each event: skill_name, fingerprint (may be empty), day (YYYY-MM-DD), trigger, count."""
        if not HOST.match(host or ""):
            raise SignalError("host must be a machine name (letters, digits, dot, dash, underscore)")
        if len(events) > MAX_EVENTS:
            raise SignalError(f"at most {MAX_EVENTS} usage rows per report")
        rows = []
        today = date.today()
        for event in events:
            name, fingerprint = str(event.get("skill_name") or ""), str(event.get("fingerprint") or "")
            trigger, count, day = str(event.get("trigger") or ""), event.get("count"), str(event.get("day") or "")
            if not NAME.match(name) or not FINGERPRINT.match(fingerprint) or trigger not in TRIGGERS:
                raise SignalError(f"invalid usage row for {name[:60]!r}: name, fingerprint or trigger")
            if not isinstance(count, int) or isinstance(count, bool) or not 0 < count <= 100_000:
                raise SignalError("count must be a whole number from 1 to 100000")
            try:
                when = date.fromisoformat(day)
            except ValueError as exc:
                raise SignalError("day must be YYYY-MM-DD") from exc
            if not today - timedelta(days=400) <= when <= today + timedelta(days=1):
                raise SignalError("day is outside the last 400 days")
            rows.append((tenant_id, name, fingerprint, day, host, trigger, count))
        with self.db.transaction(tenant_id, write=True) as db:
            for row in rows:
                # A machine resends its whole spool; the newest count for the same key replaces the older one.
                db.execute("INSERT INTO skill_usage (tenant_id, skill_name, fingerprint, day, host, chosen_by, invocations) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, skill_name, fingerprint, day, host, chosen_by) "
                           "DO UPDATE SET invocations=excluded.invocations", row)
        return {"host": host, "rows": len(rows)}

    def file_papercut(self, tenant_id: str, report: dict[str, Any], *, reported_by: str) -> dict[str, Any]:
        name, fingerprint, host = str(report.get("skill_name") or ""), str(report.get("fingerprint") or ""), str(report.get("host") or "")
        if not NAME.match(name) or not FINGERPRINT.match(fingerprint) or (host and not HOST.match(host)):
            raise SignalError("a papercut needs a skill name, and a valid fingerprint and host when given")
        row = {"papercut_id": str(uuid.uuid4()), "tenant_id": tenant_id, "skill_name": name, "fingerprint": fingerprint,
               "tried": _text(report.get("tried"), "tried"), "expected": _text(report.get("expected"), "expected"),
               "happened": _text(report.get("happened"), "happened"),
               "suggested_fix": _text(report.get("suggested_fix"), "suggested_fix", required=False),
               "host": host, "reported_by": reported_by, "reported_at": _now(), "status": "open", "resolution": "",
               "resolved_by": "", "resolved_at": ""}
        with self.db.transaction(tenant_id, write=True) as db:
            db.execute(f"INSERT INTO papercuts ({', '.join(row)}) VALUES ({', '.join('?' for _ in row)})", tuple(row.values()))
        return {k: v for k, v in row.items() if k != "tenant_id"}

    def resolve_papercut(self, tenant_id: str, papercut_id: str, resolution: str, *, resolved_by: str) -> dict[str, Any]:
        note = _text(resolution, "resolution")
        with self.db.transaction(tenant_id, write=True) as db:
            row = db.execute("SELECT status FROM papercuts WHERE tenant_id=? AND papercut_id=?", (tenant_id, papercut_id)).fetchone()
            if row is None:
                raise SignalNotFound("papercut not found in this tenant")
            if row["status"] != "open":
                raise SignalError("this papercut is already resolved")
            db.execute("UPDATE papercuts SET status='resolved', resolution=?, resolved_by=?, resolved_at=? WHERE tenant_id=? AND papercut_id=?",
                       (note, resolved_by, _now(), tenant_id, papercut_id))
        return self.papercut(tenant_id, papercut_id)

    def papercut(self, tenant_id: str, papercut_id: str) -> dict[str, Any]:
        with self.db.transaction(tenant_id) as db:
            row = db.execute("SELECT * FROM papercuts WHERE tenant_id=? AND papercut_id=?", (tenant_id, papercut_id)).fetchone()
        if row is None:
            raise SignalNotFound("papercut not found in this tenant")
        return {k: row[k] for k in row.keys() if k != "tenant_id"}

    def skill(self, tenant_id: str, skill_name: str, days: int = 30) -> dict[str, Any]:
        """One skill's use over the last `days` days and its papercuts (open first)."""
        since = (date.today() - timedelta(days=days)).isoformat()
        with self.db.transaction(tenant_id) as db:
            usage = db.execute("SELECT fingerprint, day, host, chosen_by, invocations FROM skill_usage WHERE tenant_id=? AND skill_name=? "
                               "AND day >= ? ORDER BY day", (tenant_id, skill_name, since)).fetchall()
            cuts = db.execute("SELECT * FROM papercuts WHERE tenant_id=? AND skill_name=? ORDER BY status DESC, reported_at DESC",
                              (tenant_id, skill_name)).fetchall()
        by_day: dict[str, int] = {}
        by_trigger = {"agent": 0, "user": 0}
        by_version: dict[str, int] = {}
        for row in usage:
            by_day[row["day"]] = by_day.get(row["day"], 0) + row["invocations"]
            by_trigger[row["chosen_by"]] += row["invocations"]
            by_version[row["fingerprint"] or "unknown"] = by_version.get(row["fingerprint"] or "unknown", 0) + row["invocations"]
        return {"skill_name": skill_name, "days": days, "invocations": sum(by_trigger.values()), "by_trigger": by_trigger,
                "machines": len({row["host"] for row in usage}), "by_day": by_day, "by_version": by_version,
                "papercuts": [{k: r[k] for k in r.keys() if k != "tenant_id"} for r in cuts]}

    def summary(self, tenant_id: str, days: int = 30) -> list[dict[str, Any]]:
        """Every skill with use or papercuts: invocations, machines and open papercuts, most used first."""
        since = (date.today() - timedelta(days=days)).isoformat()
        with self.db.transaction(tenant_id) as db:
            usage = db.execute("SELECT skill_name, SUM(invocations) AS n, COUNT(DISTINCT host) AS machines, "
                               "SUM(CASE WHEN chosen_by='agent' THEN invocations ELSE 0 END) AS by_agent FROM skill_usage "
                               "WHERE tenant_id=? AND day >= ? GROUP BY skill_name", (tenant_id, since)).fetchall()
            cuts = db.execute("SELECT skill_name, SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) AS open, COUNT(*) AS total "
                              "FROM papercuts WHERE tenant_id=? GROUP BY skill_name", (tenant_id,)).fetchall()
        skills: dict[str, dict[str, Any]] = {}
        for row in usage:
            skills[row["skill_name"]] = {"skill_name": row["skill_name"], "invocations": int(row["n"]), "machines": int(row["machines"]),
                                         "chosen_by_agent": int(row["by_agent"]), "open_papercuts": 0, "papercuts": 0}
        for row in cuts:
            entry = skills.setdefault(row["skill_name"], {"skill_name": row["skill_name"], "invocations": 0, "machines": 0,
                                                          "chosen_by_agent": 0, "open_papercuts": 0, "papercuts": 0})
            entry["open_papercuts"], entry["papercuts"] = int(row["open"]), int(row["total"])
        return sorted(skills.values(), key=lambda s: (-s["invocations"], -s["open_papercuts"], s["skill_name"]))

    def close(self) -> None:
        self.db.close()
