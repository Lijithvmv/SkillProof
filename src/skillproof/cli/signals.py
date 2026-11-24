"""Signals from real use: record skill runs from agent hooks, send them, and file papercuts.

- `usage-hook` is run by an agent's hook (Claude Code: PostToolUse on the Skill tool, and UserPromptSubmit). It reads
  the hook event on standard input and appends one line per skill run to a local spool: the day, the skill's name and
  whether the agent chose it or a person typed its command. It keeps no prompt text and never fails the agent.
- `signals-report` sends the spool's daily counts (with each installed skill's package fingerprint) to the server.
- `papercut` files what an agent tried, expected and saw when a skill gave it trouble, and what would fix it.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from skillproof.cli.catalogue import _machine_auth, machine_token
from skillproof.engines.installed import default_roots
from skillproof.services.imports import installed_families

Result = tuple[dict[str, Any], int]
SKILL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._\-]{0,199}$")
SPOOL_DAYS = 30


def default_spool() -> Path:
    return Path(os.environ.get("SKILLPROOF_USAGE_SPOOL") or Path.home() / ".skillproof" / "usage.jsonl")


def skill_run(event: dict[str, Any]) -> tuple[str, str] | None:
    """(skill name, trigger) for a hook event that runs a skill, else None. Only the name is taken from a prompt."""
    name = str(event.get("hook_event_name") or "")
    if name in {"PostToolUse", "PreToolUse"} and event.get("tool_name") == "Skill":
        skill = str((event.get("tool_input") or {}).get("skill") or "").strip().lstrip("/")
        return (skill, "agent") if SKILL_NAME.match(skill) else None
    if name == "UserPromptSubmit":
        first = str(event.get("prompt") or "").strip().split(maxsplit=1)
        if first and first[0].startswith("/") and SKILL_NAME.match(first[0][1:]):
            return first[0][1:], "user"
    return None


def run_usage_hook(args) -> int:
    """Never raises and never prints (an exit code alone writes no output): a hook that fails must not disturb the agent."""
    try:
        event = json.loads(sys.stdin.read() or "{}")
        found = skill_run(event if isinstance(event, dict) else {})
        if found:
            spool = Path(args.spool) if args.spool else default_spool()
            spool.parent.mkdir(parents=True, exist_ok=True)
            with spool.open("a", encoding="utf-8") as out:
                out.write(json.dumps({"day": date.today().isoformat(), "skill_name": found[0], "trigger": found[1]}) + "\n")
    except Exception:  # noqa: BLE001  (a hook must never break the session it observes)
        pass
    return 0


def spooled_counts(spool: Path, *, today: date | None = None) -> list[dict[str, Any]]:
    """Daily counts per skill and trigger from the spool (the last 30 days)."""
    since = (today or date.today()) - timedelta(days=SPOOL_DAYS)
    counts: Counter[tuple[str, str, str]] = Counter()
    if spool.exists():
        for line in spool.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
                if date.fromisoformat(row["day"]) >= since and SKILL_NAME.match(row["skill_name"]) and row["trigger"] in {"agent", "user"}:
                    counts[(row["day"], row["skill_name"], row["trigger"])] += 1
            except (ValueError, KeyError, TypeError):
                continue
    return [{"day": d, "skill_name": n, "trigger": t, "count": c} for (d, n, t), c in sorted(counts.items())]


def _post(server: str, path: str, token: str, body: dict[str, Any], machine: str) -> dict[str, Any]:
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse

    parsed = urlparse(server)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError("the server must be an https URL (plain http only to this machine)")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:  # a local development server with sign-in off
        headers.update({"X-SkillProof-Dev-User": f"reporter@{machine}", "X-SkillProof-Dev-Role": "reporter"})
    request = urllib.request.Request(server.rstrip("/") + path, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"server answered HTTP {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}") from exc


def run_signals_report(args) -> Result:
    import socket

    try:
        machine = args.host or socket.gethostname()
        rows = spooled_counts(Path(args.spool) if args.spool else default_spool())
        roots = [Path(r) for r in args.root] or default_roots()
        _, names, packages, _ = installed_families(roots) if roots else (None, {}, {}, None)
        fingerprints = {name: packages[key][2] for key, name in names.items()}
        events = [{**row, "fingerprint": fingerprints.get(row["skill_name"].split(":")[-1], "")} for row in rows]
        if not events:
            return {"host": machine, "rows": 0, "note": "no skill runs recorded in the last 30 days"}, 0
        return _post(args.server, "/api/v1/signals/usage", machine_token(args), {"host": machine, "events": events}, machine), 0
    except (OSError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)}, 4


def run_papercut(args) -> Result:
    import socket

    try:
        machine = args.host or socket.gethostname()
        body = {"skill_name": args.skill, "tried": args.tried, "expected": args.expected, "happened": args.happened,
                "suggested_fix": args.fix or "", "host": machine}
        return _post(args.server, "/api/v1/signals/papercuts", machine_token(args), body, machine), 0
    except (OSError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)}, 4


def add(commands, conf) -> None:
    hook = commands.add_parser("usage-hook", help="Run from an agent hook: record a skill run (day, name, agent- or user-chosen) in a "
                               "local spool. Reads the hook event on standard input; keeps no prompt text; never fails.")
    hook.add_argument("--spool", help="Spool file (default: ~/.skillproof/usage.jsonl or SKILLPROOF_USAGE_SPOOL).")
    hook.set_defaults(run=run_usage_hook)

    report = commands.add_parser("signals-report", help="Send this machine's skill-run counts (last 30 days, names, fingerprints, "
                                 "counts) to a SkillProof server.")
    report.add_argument("--server", required=True)
    _machine_auth(report)
    report.add_argument("--host", default=None, help="Machine name to report as (default: this computer's name).")
    report.add_argument("--spool", help="Spool file (default: ~/.skillproof/usage.jsonl).")
    report.add_argument("--root", action="append", default=[], help="Folder of installed skills, for fingerprints; repeat.")
    report.add_argument("--output", default="-")
    report.set_defaults(run=run_signals_report)

    cut = commands.add_parser("papercut", help="Report friction with a skill: what was tried, what was expected, what happened and "
                              "what would fix it. Filed for the skill's owner.")
    cut.add_argument("--server", required=True)
    _machine_auth(cut)
    cut.add_argument("--skill", required=True)
    cut.add_argument("--tried", required=True)
    cut.add_argument("--expected", required=True)
    cut.add_argument("--happened", required=True)
    cut.add_argument("--fix", default="")
    cut.add_argument("--host", default=None)
    cut.add_argument("--output", default="-")
    cut.set_defaults(run=run_papercut)
