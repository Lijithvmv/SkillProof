"""Before applying an update: what would each locked skill package be able to do that it cannot do now?

Package managers for agent assets (Microsoft APM's apm.lock.yaml, for one) pin every dependency to a commit and
detect drift as changed bytes, hashes, refs or commits. That says THAT something changed. This check says WHAT the
change adds at capability level: for each locked git dependency it reads the tree at the locked commit and at the
update target, builds a capability manifest for every skill folder in it, and diffs them.

Fields used from apm.lock.yaml (per entry in `dependencies`): repo_url, resolved_commit, resolved_ref, and
virtual_path / is_virtual for a package inside a monorepo. Registry-sourced entries (no commit) are reported as
skipped. Repositories are cloned bare into a local cache: nothing is checked out and no repository code runs.
"""
from __future__ import annotations

import io
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from skillproof.capabilities import build_manifest, diff_manifests
from skillproof.ingestion import MAX_FILE_SIZE

SEMVER_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def _git(repo: Path | None, *args: str) -> str:
    command = ["git", *(["--git-dir", str(repo)] if repo else []), "-c", "core.hooksPath=/dev/null", *args]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {result.stderr.strip()[:300]}")
    return result.stdout


def _cache_dir(cache: Path, repo_url: str) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", repo_url.rstrip("/").removesuffix(".git"))[-120:]
    return cache / f"{name}.git"


def _fetch(cache: Path, repo_url: str) -> Path:
    repo = _cache_dir(cache, repo_url)
    if repo.exists():
        _git(repo, "fetch", "--quiet", "--tags", "--force", "origin", "+refs/heads/*:refs/remotes/origin/*")
    else:
        cache.mkdir(parents=True, exist_ok=True)
        _git(None, "clone", "--quiet", "--bare", repo_url, str(repo))
        _git(repo, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
        _git(repo, "fetch", "--quiet", "--tags", "origin")
    return repo


def _target(repo: Path, resolved_ref: str | None, to: str | None) -> tuple[str, str]:
    """(commit, how it was chosen)."""
    if to:
        return _git(repo, "rev-parse", f"{to}^{{commit}}").strip(), f"--to {to}"
    if resolved_ref and SEMVER_TAG.match(resolved_ref):
        tags = [t for t in _git(repo, "tag", "--list").split() if SEMVER_TAG.match(t)]
        newest = max(tags, key=lambda t: tuple(int(x) for x in SEMVER_TAG.match(t).groups()))
        return _git(repo, "rev-parse", f"{newest}^{{commit}}").strip(), f"newest semver tag {newest}"
    ref = resolved_ref or "HEAD"
    for candidate in (f"refs/remotes/origin/{ref}", ref):
        try:
            return _git(repo, "rev-parse", f"{candidate}^{{commit}}").strip(), f"tip of {ref}"
        except RuntimeError:
            continue
    raise RuntimeError(f"cannot resolve an update target for ref {ref!r}")


def _tree(repo: Path, commit: str, subpath: str) -> dict[str, bytes]:
    """Files under subpath at commit, relative to subpath (git archive, read in memory)."""
    args = ["archive", "--format=tar", commit] + ([subpath] if subpath else [])
    raw = subprocess.run(["git", "--git-dir", str(repo), *args], capture_output=True, timeout=600)
    if raw.returncode != 0:
        if b"did not match any files" in raw.stderr or b"pathspec" in raw.stderr:
            return {}
        raise RuntimeError(f"git archive failed: {raw.stderr.decode(errors='replace').strip()[:300]}")
    files = {}
    prefix = PurePosixPath(subpath) if subpath else None
    with tarfile.open(fileobj=io.BytesIO(raw.stdout)) as archive:
        for member in archive.getmembers():
            if not member.isfile() or member.size > MAX_FILE_SIZE:
                continue
            path = PurePosixPath(member.name)
            relative = path.relative_to(prefix) if prefix else path
            files[relative.as_posix()] = archive.extractfile(member).read()
    return files


def _skills(files: dict[str, bytes]) -> dict[str, dict[str, bytes]]:
    """Split a tree into skill folders (each folder holding a SKILL.md). A tree with no SKILL.md is one package."""
    roots = sorted({str(PurePosixPath(p).parent) for p in files if PurePosixPath(p).name == "SKILL.md"}, key=len)
    if not roots:
        return {".": files} if files else {}
    skills: dict[str, dict[str, bytes]] = {}
    for root in roots:
        base = "" if root == "." else root + "/"
        if any(root != other and (other == "." or root.startswith(other + "/")) for other in roots):
            continue  # nested SKILL.md belongs to the outer skill
        skills[root] = {p[len(base):]: b for p, b in files.items() if p.startswith(base)}
    return skills


def check_lockfile(lockfile: str | Path, *, cache: str | Path, to: str | None = None) -> dict[str, Any]:
    data = yaml.safe_load(Path(lockfile).read_text(encoding="utf-8")) or {}
    results, skipped = [], []
    for entry in data.get("dependencies") or []:
        repo_url, locked = entry.get("repo_url"), entry.get("resolved_commit")
        if not repo_url or not locked:
            skipped.append({"repo_url": repo_url, "reason": "no resolved_commit (registry or local entry)"})
            continue
        subpath = (entry.get("virtual_path") or "").strip("/") if entry.get("is_virtual") or entry.get("virtual_path") else ""
        try:
            repo = _fetch(Path(cache), repo_url)
            target, how = _target(repo, entry.get("resolved_ref"), to)
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            skipped.append({"repo_url": repo_url, "reason": str(exc)[:300]})
            continue
        item: dict[str, Any] = {"repo_url": repo_url, "virtual_path": subpath or None, "locked_commit": locked,
                                "target_commit": target, "target_chosen_by": how, "skills": []}
        if target == locked:
            item["status"] = "up_to_date"
            results.append(item)
            continue
        old, new = _skills(_tree(repo, locked, subpath)), _skills(_tree(repo, target, subpath))
        for name in sorted(set(old) | set(new)):
            if name not in new:
                item["skills"].append({"skill": name, "status": "removed_in_update"})
                continue
            before = build_manifest(old.get(name, {}))
            diff = diff_manifests(before, build_manifest(new[name]))
            item["skills"].append({
                "skill": name,
                "status": diff["status"] if name in old else ("new_skill_with_capabilities" if diff["added"] else "new_skill"),
                "added": {c: sorted(v) for c, v in diff["added"].items()},
                "added_by_source": diff["added_by_source"],
                "removed": diff["removed"],
            })
        adds = [s for s in item["skills"] if s.get("added")]
        item["status"] = "update_adds_capabilities" if adds else "update_adds_nothing"
        results.append(item)
    return {
        "method": "lockfile_update_capability_check",
        "lockfile": str(lockfile),
        "dependencies_checked": len(results),
        "updates_adding_capabilities": sum(r["status"] == "update_adds_capabilities" for r in results),
        "results": results,
        "skipped": skipped,
        "limitations": (
            "Capability facts are static text extraction (after decoding), not observed behaviour. The update target "
            "is a guess unless --to is given: the tip of a locked branch, or the newest semver tag for a locked tag; "
            "the package manager's own resolution may differ. Files over the size limit are not read."
        ),
    }
