"""Installed skills and the catalogue: watch installed skills, check a lockfile update, import installed skills into the
catalogue, check installed against approved, and report a machine's skills to a server (fleet)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from skillproof.engines.apm_lock import check_lockfile
from skillproof.services.imports import _skill_name as skill_name_of, check_installed, import_installed, installed_families
from skillproof.governance import AssurancePolicy
from skillproof.engines.installed import default_roots, scan_installed
from skillproof.wiring import close_governance

from skillproof.cli.common import DEFAULT_CATALOGUE, catalogue_at, checker, importer

Result = tuple[dict[str, Any], int]


def _https_or_loopback(url: str, label: str) -> None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError(f"the {label} must be an https URL (plain http only to this machine)")


def client_credentials_token(*, client_id: str, secret: str, token_url: str = "", issuer: str = "", scope: str = "",
                             post=None) -> str:
    """An access token for this machine from the identity provider (OAuth 2.0 client credentials grant). The token
    endpoint is `token_url`, or found through the issuer's OpenID discovery document. Never uses a person's sign-in."""
    import urllib.error
    import urllib.request
    from urllib.parse import urlencode

    if not client_id or not secret:
        raise ValueError("a machine client id and secret are needed for the client credentials grant")
    if not token_url:
        if not issuer:
            raise ValueError("pass --token-url or --issuer to find the token endpoint")
        _https_or_loopback(issuer, "issuer")
        with urllib.request.urlopen(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=30) as response:
            token_url = json.loads(response.read()).get("token_endpoint") or ""
        if not token_url:
            raise RuntimeError("the issuer's discovery document has no token_endpoint")
    _https_or_loopback(token_url, "token endpoint")
    form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if scope:
        form["scope"] = scope
    body = urlencode(form).encode()
    if post is not None:
        return post(token_url, body)
    request = urllib.request.Request(token_url, data=body, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            token = json.loads(response.read()).get("access_token")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"the token endpoint answered HTTP {exc.code}: {exc.read()[:200].decode('utf-8', 'replace')}") from exc
    if not isinstance(token, str) or not token:
        raise RuntimeError("the token endpoint returned no access_token")
    return token


def machine_token(args) -> str:
    """The bearer token a machine command uses: from the client credentials grant when a client id is given, else
    from the environment variable named by --token-env (empty for a local development server)."""
    if getattr(args, "client_id", None):
        return client_credentials_token(client_id=args.client_id, secret=os.environ.get(args.client_secret_env, "").strip(),
                                        token_url=args.token_url or "", issuer=args.issuer or "", scope=args.scope or "")
    return os.environ.get(args.token_env, "").strip()


def _machine_auth(parser) -> None:
    parser.add_argument("--token-env", default="SKILLPROOF_TOKEN", help="Environment variable holding a bearer access token (a reporter-role token).")
    parser.add_argument("--client-id", help="Machine client id: get a token from the identity provider (client credentials) instead of --token-env.")
    parser.add_argument("--client-secret-env", default="SKILLPROOF_CLIENT_SECRET", help="Environment variable holding the machine client's secret (never passed on the command line).")
    parser.add_argument("--issuer", help="Identity provider issuer; its token endpoint is found by OpenID discovery.")
    parser.add_argument("--token-url", help="Token endpoint, when not using --issuer.")
    parser.add_argument("--scope", help="Scope to request with the client credentials grant, if the provider needs one.")


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
    families, names, packages, errors = installed_families(roots)
    machine = host or socket.gethostname()
    body = json.dumps({"host": machine, "skills": [{"skill_name": name, "fingerprint": packages[key][2],
                                                    "own_name": skill_name_of(packages[key][0], families[key][1])}
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
        result = send_fleet_report(args.server, machine_token(args), args.host, _roots(args))
        return result, 1 if result.get("counts", {}).get("running_unapproved") else 0
    except (OSError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)}, 4


class LocalApproved:
    """The approved set and packages from a catalogue folder on this machine."""

    def __init__(self, governance, principal):
        self.governance, self.principal = governance, principal

    def approved(self) -> list[dict[str, Any]]:
        return self.governance.approved_set(self.principal)

    def package(self, version_id: str) -> tuple[str, bytes]:
        version, blob = self.governance.package_bytes(self.principal, version_id)
        return version["package_fingerprint"], blob


class ServerApproved:
    """The approved set and packages from a SkillProof server (a reporter-role token is enough)."""

    def __init__(self, server: str, token: str):
        from urllib.parse import urlparse

        parsed = urlparse(server)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("the server must be an https URL (plain http only to this machine)")
        self.server = server.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {"X-SkillProof-Dev-User": "sync", "X-SkillProof-Dev-Role": "reporter"}

    def _get(self, path: str):
        import urllib.error
        import urllib.request

        request = urllib.request.Request(self.server + path, headers=self.headers)
        try:
            return urllib.request.urlopen(request, timeout=60)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"server answered HTTP {exc.code} for {path}: {exc.read()[:300].decode('utf-8', 'replace')}") from exc

    def approved(self) -> list[dict[str, Any]]:
        with self._get("/api/v1/registry/approved") as response:
            return json.loads(response.read())["approved"]

    def package(self, version_id: str) -> tuple[str, bytes]:
        with self._get(f"/api/v1/registry/versions/{version_id}/package") as response:
            return response.headers.get("X-SkillProof-Fingerprint", ""), response.read()


def run_sync(args) -> Result:
    from skillproof.logs import log
    from skillproof.services import distribution

    try:
        roots = _roots(args)
        governance = None
        if args.server:
            source = ServerApproved(args.server, machine_token(args))
        else:
            governance = catalogue_at(Path(args.data_dir))
            source = LocalApproved(governance, checker(args.tenant))
        try:
            targets = [distribution.install_target(t) for t in args.install_into]
            scanned = roots + [t for t in targets if t.exists() and t not in roots]  # see what each target already holds
            families, names, packages, errors = installed_families(scanned)
            installed = [distribution.Installed(name=name, folder=families[key][1], fingerprint=packages[key][2],
                                                skill_name=skill_name_of(packages[key][0], families[key][1])) for key, name in names.items()]
            actions = distribution.plan(source.approved(), installed, strict=args.strict, install_into=targets)
            if args.apply:
                distribution.apply(actions, source, Path(args.quarantine), log=lambda event, fields: log(event, **fields))
        finally:
            if governance is not None:
                close_governance(governance)
        result = distribution.summary(actions, args.apply)
        result["unreadable"] = errors
        pending = result["to_replace"] + result["to_install"] + (result["unapproved"] if args.strict else 0) + result["blocked"]
        return result, 1 if result["failed"] or (not args.apply and pending) or (args.apply and result["blocked"]) else 0
    except (OSError, ValueError, RuntimeError) as exc:
        return {"error": str(exc)}, 4


def add(commands, conf) -> None:
    sync = commands.add_parser("sync", help="Make this machine run what the catalogue approved: replace installed skills that are not the approved version (the old folder is moved to quarantine, never deleted), report unapproved ones (quarantine them with --strict). Shows the plan unless --apply. Exit 1 when something is (or, without --apply, would be) changed or cannot be fixed.")
    sync.add_argument("--server", help="SkillProof server URL; omit to use the local catalogue in --data-dir.")
    _machine_auth(sync)
    sync.add_argument("--data-dir", default=conf.data_dir or str(DEFAULT_CATALOGUE), help="Local catalogue storage, when no --server is given.")
    sync.add_argument("--tenant", default="local")
    sync.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common agent locations that exist.")
    sync.add_argument("--strict", action="store_true", help="Also quarantine installed skills that have no approved version.")
    sync.add_argument("--install-into", action="append", default=[], metavar="AGENT_OR_FOLDER",
                      help="Also install approved skills missing from this skills folder, so every agent runs the approved set: "
                           "claude (~/.claude/skills), agents (~/.agents/skills), codex (~/.codex/skills) or a folder path; repeat.")
    sync.add_argument("--apply", action="store_true", help="Carry out the plan (default: report it only).")
    sync.add_argument("--quarantine", default=str(Path.home() / ".skillproof" / "quarantine"), help="Where replaced or unapproved skill folders are moved.")
    sync.add_argument("--output", default="-")
    sync.set_defaults(run=run_sync)

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
    _machine_auth(report)
    report.add_argument("--host", default=None, help="Machine name to report as (default: this computer's name).")
    report.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common agent locations that exist.")
    report.add_argument("--output", default="-")
    report.set_defaults(run=run_fleet_report)
