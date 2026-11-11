"""Watch installed skills: report what each update adds, each time the scan runs.

Skills reach a machine from many places (editor builds, extensions, agent apps, plugin caches) and change when
those update, usually without anyone reading the new version. This scan finds every SKILL.md under the given
roots, builds a capability manifest per skill folder, and compares it with the last scan.

A skill is identified by its install path with version and hash segments removed, because updates often land in a
new folder (a new editor build, a new extension version) rather than overwriting the old one. Several copies of one
skill on disk at once are ordered by file time; on first sight, each older copy is diffed against the next, so the
history already on disk is reported too.

The state file stores, per skill, the path, a content fingerprint and the manifest (capability facts and where
they were found), not the skill files themselves.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from skillproof.capabilities import build_manifest, diff_manifests
from skillproof.ingestion import MAX_FILE_SIZE, MAX_FILES, PackageError

STATE_VERSION = 1
SKIP_PARTS = {"node_modules", ".git", "__pycache__", "site-packages"}
HASH_SEGMENT = re.compile(r"[0-9a-f]{8,}(?:-[0-9a-f]{4,})*", re.I)
VERSION_SEGMENT = re.compile(r"\d+\.\d+(?:\.\d+)*(?:-[\w.-]+)?")
NAME = re.compile(r"^name:\s*['\"]?([^'\"\r\n]+)", re.M)


def family_key(skill_dir: Path) -> str:
    """The install path with versions and hashes replaced by '#': stays the same across an update."""
    path = skill_dir.resolve().as_posix().lower()
    return VERSION_SEGMENT.sub("#", HASH_SEGMENT.sub("#", path))


def find_skill_dirs(roots: list[Path]) -> list[Path]:
    found = []
    for root in roots:
        if not root.exists():
            continue
        for skill_md in root.rglob("SKILL.md"):
            if not SKIP_PARTS.intersection(skill_md.parts):
                found.append(skill_md.parent)
    return sorted(set(found))


def _read_installed(skill_dir: Path) -> tuple[dict[str, bytes], dict[str, str]]:
    """Like read_package_bytes, but an oversized file does not hide the rest of the skill: it is fingerprinted and
    listed as not scanned. On one machine 9 of 195 installed skills held a file over the limit (Office templates,
    and a 2 MB+ JavaScript file), and the strict reader dropped those skills entirely."""
    files: dict[str, bytes] = {}
    oversize: dict[str, str] = {}
    for item in sorted(skill_dir.rglob("*")):
        relative = item.relative_to(skill_dir)
        if SKIP_PARTS.intersection(relative.parts) or item.is_symlink() or not item.is_file():
            continue
        name = relative.as_posix()
        if item.stat().st_size > MAX_FILE_SIZE:
            oversize[name] = hashlib.sha256(item.read_bytes()).hexdigest()
            continue
        files[name] = item.read_bytes()
        if len(files) > MAX_FILES:
            raise PackageError(f"more than {MAX_FILES} files; not a single skill folder")
    return files, oversize


def _snapshot(skill_dir: Path) -> dict[str, Any]:
    files, oversize = _read_installed(skill_dir)
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name])
    for name in sorted(oversize):  # a change inside an unscanned file still changes the fingerprint
        digest.update(name.encode() + b"\0" + oversize[name].encode())
    manifest = build_manifest(files)
    manifest["not_scanned"] = sorted(oversize)
    text = files.get("SKILL.md", b"").decode("utf-8", "replace")
    match = NAME.search(text[:2000])
    return {
        "path": str(skill_dir),
        "name": match.group(1).strip() if match else skill_dir.name,
        "fingerprint": digest.hexdigest(),
        "mtime": (skill_dir / "SKILL.md").stat().st_mtime,
        "manifest": manifest,
    }


def _change(old: dict[str, Any], new: dict[str, Any], source: str) -> dict[str, Any]:
    diff = diff_manifests(old["manifest"], new["manifest"])
    return {
        "skill": new["name"],
        "source": source,  # "on_disk_history" (copies found together) or "since_last_scan"
        "old": old["path"],
        "new": new["path"],
        "status": diff["status"],
        "added": {category: sorted(values) for category, values in diff["added"].items()},
        "added_by_source": diff["added_by_source"],
        "removed": diff["removed"],
        "not_scanned": new["manifest"].get("not_scanned", []),
    }


def scan_installed(roots: list[str | Path], state_path: str | Path) -> dict[str, Any]:
    state_file = Path(state_path)
    state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {"version": STATE_VERSION, "skills": {}}
    if state.get("version") != STATE_VERSION:
        raise ValueError(f"unsupported state file version: {state.get('version')}")
    known: dict[str, dict[str, Any]] = state["skills"]
    first_run = not known

    families: dict[str, list[dict[str, Any]]] = {}
    unreadable = []
    for skill_dir in find_skill_dirs([Path(r) for r in roots]):
        try:
            snap = _snapshot(skill_dir)
        except (PackageError, OSError) as exc:
            unreadable.append({"path": str(skill_dir), "error": str(exc)[:200]})
            continue
        families.setdefault(family_key(skill_dir), []).append(snap)

    changes, new_skills, unchanged = [], [], 0
    for key, copies in families.items():
        copies.sort(key=lambda c: c["mtime"])
        distinct = []  # drop identical copies, keep the oldest of each content
        for copy in copies:
            if not distinct or copy["fingerprint"] != distinct[-1]["fingerprint"]:
                distinct.append(copy)
        previous = known.get(key)
        if previous is None:
            for old, new in zip(distinct, distinct[1:]):
                changes.append(_change(old, new, "on_disk_history"))
            caps = {c: sorted(v) for c, v in distinct[-1]["manifest"]["capabilities"].items() if v}
            new_skills.append({"skill": distinct[-1]["name"], "path": distinct[-1]["path"], "capabilities": caps})
        elif previous["fingerprint"] != distinct[-1]["fingerprint"]:
            changes.append(_change(previous, distinct[-1], "since_last_scan"))
        else:
            unchanged += 1
        latest = distinct[-1]
        known[key] = {k: latest[k] for k in ("path", "name", "fingerprint", "manifest")} | {"seen_at": time.strftime("%Y-%m-%dT%H:%M:%S")}

    missing = sorted(known[k]["path"] for k in known if k not in families)
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    flagged = [c for c in changes if c["status"] == "new_capabilities"]
    return {
        "method": "installed_skill_watch",
        "roots": [str(r) for r in roots],
        "first_run": first_run,
        "skills_seen": len(families),
        "unchanged": unchanged,
        "changed": len(changes),
        "changes_adding_capabilities": len(flagged),
        "changes": flagged + [c for c in changes if c["status"] != "new_capabilities"],
        # On a first run every skill is new; listing all their capabilities would bury the updates.
        "new_skills": [] if first_run else new_skills,
        "new_skill_count": len(new_skills),
        "no_longer_found": missing,
        "unreadable": unreadable,
        "skills_with_unscanned_files": sorted(c["path"] for copies in families.values() for c in copies if c["manifest"].get("not_scanned")),
        "limitations": (
            "Capability facts are static (extracted text, after decoding), not observed behaviour. Copies are ordered "
            "by SKILL.md file time, which an installer can reset. A skill counts as the same skill only if its install "
            "path matches after removing version and hash segments; a move to a new location reads as a new skill."
        ),
    }


def default_roots() -> list[Path]:
    """Common places agent skills are installed for the current user; only existing ones are scanned."""
    home = Path.home()
    candidates = [
        home / ".claude", home / ".codex", home / ".cursor", home / ".agents", home / ".vscode" / "extensions",
        home / "AppData" / "Local" / "Programs" / "Microsoft VS Code", home / "AppData" / "Roaming" / "Claude",
        home / ".config" / "Claude", home / "Library" / "Application Support" / "Claude",
    ]
    return [p for p in candidates if p.exists()]
