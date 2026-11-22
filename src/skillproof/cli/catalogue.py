"""Installed skills and the catalogue: watch installed skills, check a lockfile update, import installed skills into the
catalogue, check installed against approved, and report a machine's skills to a server (fleet)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from skillproof.engines.apm_lock import check_lockfile
from skillproof.services.imports import check_installed, import_installed, installed_families
from skillproof.governance import AssurancePolicy
from skillproof.engines.installed import default_roots, scan_installed
from skillproof.wiring import close_governance

from skillproof.cli.common import DEFAULT_CATALOGUE, catalogue_at, checker, importer

Result = tuple[dict[str, Any], int]


def _roots(args) -> list[Path]:
    roots = [Path(r) for r in args.root] or default_roots()
    if not roots:
        raise ValueError("No skill folders found; pass --root.")
    return roots


def run_lock_check(args) -> Result:
    try:
        result = check_lockfile(args.lockfile, cache=args.cache, to=args.to)
        return result, 1 if result["updates_adding_capabilities"] else 0
    except (OSError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)}, 4


def run_watch_installed(args) -> Result:
    try:
        result = scan_installed(_roots(args), args.state)
        return result, 1 if result["changes_adding_capabilities"] else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_catalogue_import(args) -> Result:
    try:
        roots = _roots(args)
        governance = catalogue_at(Path(args.data_dir))
        try:
            policy = AssurancePolicy.model_validate(json.loads(Path(args.policy).read_text(encoding="utf-8"))) if args.policy else None
            result = import_installed(governance, importer(args.tenant), roots, policy)
        finally:
            close_governance(governance)
        return result, 1 if result["updates_with_block"] else 0
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}, 4


def run_catalogue_check(args) -> Result:
    try:
        roots = _roots(args)
        governance = catalogue_at(Path(args.data_dir))
        try:
            result = check_installed(governance, checker(args.tenant), roots)
        finally:
            close_governance(governance)
        return result, 1 if result["running_unapproved"] or (args.strict and result["never_approved"]) else 0
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}, 4


def send_fleet_report(server: str, token: str, host: str | None, roots: list[Path], *, send=None) -> dict[str, Any]:
    """Collect installed skills (catalogue names and package fingerprints, as catalogue-import computes them) and POST them."""
    import socket
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse

    parsed = urlparse(server)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError("the server must be an https URL (plain http only to this machine)")
    _, names, packages, errors = installed_families(roots)
    machine = host or socket.gethostname()
    body = json.dumps({"host": machine, "skills": [{"skill_name": name, "fingerprint": packages[key][2]}
                                                   for key, name in sorted(names.items(), key=lambda p: p[1])]}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:  # a local development server with sign-in off
        headers.update({"X-SkillProof-Dev-User": f"reporter@{machine}", "X-SkillProof-Dev-Role": "reporter"})
    url = server.rstrip("/") + "/api/v1/fleet/reports"
    if send is not None:
        return send(url, body, headers)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"server answered HTTP {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}") from exc
    result["unreadable"] = errors
    return result


def run_fleet_report(args) -> Result:
    try:
        result = send_fleet_report(args.server, os.environ.get(args.token_env, "").strip(), args.host, _roots(args))
        return result, 1 if result.get("counts", {}).get("running_unapproved") else 0
    except (OSError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)}, 4


def add(commands, conf) -> None:
    lock = commands.add_parser("lock-check", help="For each git dependency in an apm.lock.yaml, report what updating from the locked commit would add. Exit 1 when an update adds capabilities.")
    lock.add_argument("lockfile")
    lock.add_argument("--cache", default=str(Path.home() / ".skillproof" / "repos"), help="Where bare clones are kept (nothing is checked out).")
    lock.add_argument("--to", help="Commit, tag or branch to compare against. Default: tip of the locked branch, or newest semver tag for a locked tag.")
    lock.add_argument("--output", default="-")
    lock.set_defaults(run=run_lock_check)

    watch = commands.add_parser("watch-installed", help="Diff installed skills against the last scan and report what each update adds. Exit 1 when an update adds capabilities.")
    watch.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common Claude, Codex, Cursor and VS Code locations that exist.")
    watch.add_argument("--state", default=str(Path.home() / ".skillproof" / "installed-state.json"), help="Local state file (manifests of the last scan, not skill contents).")
    watch.add_argument("--output", default="-")
    watch.set_defaults(run=run_watch_installed)

    feed = commands.add_parser("catalogue-import", help="Register the skills installed on this machine in the catalogue. Unchanged skills are skipped; a changed skill becomes a new version ranked block / ask / note against the one before. Exit 1 when an update has a block-level addition.")
    feed.add_argument("--data-dir", default=conf.data_dir or str(DEFAULT_CATALOGUE), help="Catalogue storage (the same folder the API uses as SKILLPROOF_DATA_DIR).")
    feed.add_argument("--tenant", default="local", help="Catalogue tenant to register into (the API's local development tenant is 'local').")
    feed.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common Claude, Codex, Cursor and VS Code locations that exist.")
    feed.add_argument("--policy", help="Assurance policy JSON (thresholds) for the imported versions; the tenant's stored policy otherwise.")
    feed.add_argument("--output", default="-")
    feed.set_defaults(run=run_catalogue_import)

    check = commands.add_parser("catalogue-check", help="Compare the skills installed on this machine with the versions the catalogue approved. Registers nothing. Exit 1 when an installed skill differs from its approved version (running unapproved); with --strict also when a skill was never approved.")
    check.add_argument("--data-dir", default=conf.data_dir or str(DEFAULT_CATALOGUE), help="Catalogue storage (the same folder the API uses as SKILLPROOF_DATA_DIR).")
    check.add_argument("--tenant", default="local")
    check.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common agent locations that exist.")
    check.add_argument("--strict", action="store_true", help="Also fail when an installed skill has no approved version.")
    check.add_argument("--output", default="-")
    check.set_defaults(run=run_catalogue_check)

    report = commands.add_parser("fleet-report", help="Send this machine's installed skills (names and package fingerprints, never contents) to a SkillProof server, which compares them with the approved versions. Exit 1 when a skill runs unapproved.")
    report.add_argument("--server", required=True, help="Server base URL, e.g. https://skillproof.example.org")
    report.add_argument("--token-env", default="SKILLPROOF_TOKEN", help="Environment variable holding the bearer access token (a reporter-role token).")
    report.add_argument("--host", default=None, help="Machine name to report as (default: this computer's name).")
    report.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common agent locations that exist.")
    report.add_argument("--output", default="-")
    report.set_defaults(run=run_fleet_report)
