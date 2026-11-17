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
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from skillproof.capabilities import build_manifest, diff_manifests
from skillproof.ingestion import MAX_FILE_SIZE, MAX_FILES, PackageError
from skillproof.triage import triage

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


def find_plugin_dirs(roots: list[Path]) -> list[Path]:
    """Plugin roots: a folder holding .claude-plugin/plugin.json, or the parent of a hooks/ folder whose JSON
    registers hooks. Hooks live here, not in skill folders, so a skill-only scan never sees them."""
    found = set()
    for root in roots:
        if not root.exists():
            continue
        for manifest in root.rglob("plugin.json"):
            if manifest.parent.name == ".claude-plugin" and not SKIP_PARTS.intersection(manifest.parts):
                found.add(manifest.parent.parent)
        for hooks_file in root.rglob("*hooks*.json"):
            if hooks_file.parent.name == "hooks" and not SKIP_PARTS.intersection(hooks_file.parts):
                found.add(hooks_file.parent.parent)
    return sorted(found)


PLUGIN_PARTS = ("hooks", ".claude-plugin", "plugin.json", ".mcp.json", "hooks.json")
PLUGIN_REF = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT(?::-[^}]*)?\}?[/\\]+([^\"'\s\\$]+)")


def _plugin_snapshot(plugin_dir: Path) -> dict[str, Any]:
    """The plugin-level files that decide what runs without a skill being used: hook definitions and their
    scripts, the plugin manifest, and MCP server config. Skills inside the plugin are scanned as skills."""
    files: dict[str, bytes] = {}
    for part in PLUGIN_PARTS:
        target = plugin_dir / part
        items = [target] if target.is_file() else sorted(target.rglob("*")) if target.is_dir() else []
        for item in items:
            relative = item.relative_to(plugin_dir)
            if SKIP_PARTS.intersection(relative.parts) or item.is_symlink() or not item.is_file() or item.stat().st_size > MAX_FILE_SIZE:
                continue
            files[relative.as_posix()] = item.read_bytes()
    # A hook can run a script anywhere in the plugin ("${CLAUDE_PLUGIN_ROOT}/scripts/telemetry.sh" in
    # code-modernization); read every file the hook definitions point at, inside the plugin root only.
    base = plugin_dir.resolve()
    for name, raw in list(files.items()):
        if not name.endswith(".json"):
            continue
        for ref in PLUGIN_REF.findall(raw.decode("utf-8", "replace")):
            target = (plugin_dir / ref).resolve()
            if target.is_relative_to(base) and target.is_file() and not target.is_symlink() and target.stat().st_size <= MAX_FILE_SIZE:
                files.setdefault(target.relative_to(base).as_posix(), target.read_bytes())
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name])
    name = plugin_dir.name
    try:
        data = json.loads(files.get(".claude-plugin/plugin.json", b"{}"))
        name = str(data.get("name") or name) if isinstance(data, dict) else name
    except ValueError:
        pass
    newest = max((plugin_dir / f).stat().st_mtime for f in files) if files else 0.0
    return {"path": str(plugin_dir), "name": f"plugin:{name}", "fingerprint": digest.hexdigest(), "mtime": newest,
            "manifest": build_manifest(files) | {"not_scanned": []}}


def _change(old: dict[str, Any], new: dict[str, Any], source: str) -> dict[str, Any]:
    diff = diff_manifests(old["manifest"], new["manifest"])
    change = {
        "skill": new["name"],
        "source": source,  # "on_disk_history" (copies found together) or "since_last_scan"
        "old": old["path"],
        "new": new["path"],
        "status": diff["status"],
        "added": {category: sorted(values) for category, values in diff["added"].items()},
        "added_by_source": diff["added_by_source"],
        "removed": diff["removed"],
        "hooks_repointed": diff.get("hooks_repointed", []),
        "not_scanned": new["manifest"].get("not_scanned", []),
    }
    ranked = triage(diff)
    change["triage"] = {"decision": ranked["decision"], "counts": ranked["counts"], "combinations": ranked["combinations"],
                        "top": [{k: item[k] for k in ("level", "category", "value", "reasons", "locations")} for item in ranked["items"][:10]]}
    if old["manifest"].get("manifest_version") != new["manifest"].get("manifest_version"):
        # The stored manifest came from an older extractor, which may simply have missed what the new one reads
        # (2026-11-17: pptx "gained" npm:react, react-dom, sharp; the same line was in every older copy, and the
        # same-extractor diff was empty). The old files are not stored, so the change cannot be re-checked:
        # report it as re-baselined, list the differences as unverified, and do not raise an alert.
        change["status"] = "extractor_upgraded"
        change["unverified_added"], change["added"] = change["added"], {}
        change["triage"] = {"decision": "none", "counts": {}, "combinations": [], "top": [], "note": "extractor upgraded; not ranked"}
    return change


def scan_installed(roots: list[str | Path], state_path: str | Path) -> dict[str, Any]:
    state_file = Path(state_path)
    try:
        state = json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else {"version": STATE_VERSION, "skills": {}}
    except json.JSONDecodeError as exc:
        raise ValueError(f"state file {state_file} is empty or damaged ({exc}); restore a copy or delete it to start a new baseline") from exc
    if state.get("version") != STATE_VERSION:
        raise ValueError(f"unsupported state file version: {state.get('version')}")
    known: dict[str, dict[str, Any]] = state["skills"]
    first_run = not known
    # Plugins were added to the scan later; their first scan is a baseline, not a list of "new plugins".
    plugins_baseline = not state.get("plugins_tracked")

    families: dict[str, list[dict[str, Any]]] = {}
    unreadable = []
    for skill_dir in find_skill_dirs([Path(r) for r in roots]):
        try:
            snap = _snapshot(skill_dir)
        except (PackageError, OSError) as exc:
            unreadable.append({"path": str(skill_dir), "error": str(exc)[:200]})
            continue
        families.setdefault(family_key(skill_dir), []).append(snap)
    plugin_count = 0
    for plugin_dir in find_plugin_dirs([Path(r) for r in roots]):
        try:
            snap = _plugin_snapshot(plugin_dir)
        except (PackageError, OSError, ValueError) as exc:
            unreadable.append({"path": str(plugin_dir), "error": str(exc)[:200]})
            continue
        plugin_count += 1
        families.setdefault("plugin::" + family_key(plugin_dir), []).append(snap)

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
            if not (key.startswith("plugin::") and plugins_baseline):
                new_skills.append({"skill": distinct[-1]["name"], "path": distinct[-1]["path"], "capabilities": caps})
        elif previous["fingerprint"] != distinct[-1]["fingerprint"]:
            changes.append(_change(previous, distinct[-1], "since_last_scan"))
        else:
            unchanged += 1
        latest = distinct[-1]
        known[key] = {k: latest[k] for k in ("path", "name", "fingerprint", "manifest")} | {"seen_at": time.strftime("%Y-%m-%dT%H:%M:%S")}

    missing = sorted(known[k]["path"] for k in known if k not in families)
    state["plugins_tracked"] = True
    state_file.parent.mkdir(parents=True, exist_ok=True)
    # Write to a temp file and replace: a full disk once left the state file empty mid-write, and every later
    # scheduled run then failed. With replace, a failed write leaves the previous state intact.
    temp = state_file.with_name(state_file.name + ".tmp")
    try:
        temp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        if state_file.exists() and state_file.stat().st_size:
            # Keep the previous good state one step back, so a bad scan (or a later bug) can be undone.
            shutil.copy2(state_file, state_file.with_name(state_file.name + ".bak"))
        os.replace(temp, state_file)
    finally:
        temp.unlink(missing_ok=True)
    flagged = [c for c in changes if c["status"] == "new_capabilities"]
    order = {"block": 0, "ask": 1, "note": 2, "none": 3}
    flagged.sort(key=lambda c: order.get(c.get("triage", {}).get("decision", "none"), 3))  # most severe first
    return {
        "method": "installed_skill_watch",
        "roots": [str(r) for r in roots],
        "first_run": first_run,
        "skills_seen": sum(not k.startswith("plugin::") for k in families),
        "plugins_seen": sum(k.startswith("plugin::") for k in families),
        "plugin_folders": plugin_count,
        "plugins_baseline": plugins_baseline and not first_run,
        "extractor_upgraded": sum(c["status"] == "extractor_upgraded" for c in changes),
        "unchanged": unchanged,
        "changed": len(changes),
        "changes_adding_capabilities": len(flagged),
        "changes_by_decision": {d: sum(c.get("triage", {}).get("decision") == d for c in flagged) for d in ("block", "ask", "note")},
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
