"""One identity for a skill package, however it arrives.

A package is the set of its files: relative path -> raw bytes. Its fingerprint is SHA-256 over every file in path order,
`path + NUL + bytes`; a file too large to read is represented by `path + NUL + sha256-hex` of its bytes, so a change
inside it still changes the fingerprint. Uploads (ZIP), installed folders, evaluation jobs and fleet reports all use
this function: the same files give the same fingerprint, so a version approved by upload matches its installed copy.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from skillproof.ingestion import MAX_FILE_SIZE, MAX_FILES, PackageError, read_skill_zip_bytes

SKIP_PARTS = {"node_modules", ".git", "__pycache__", "site-packages"}


def fingerprint(files: dict[str, bytes], oversize: dict[str, str] | None = None) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name])
    for name in sorted(oversize or {}):
        digest.update(name.encode() + b"\0" + (oversize or {})[name].encode())
    return digest.hexdigest()


def read_folder(folder: Path) -> tuple[dict[str, bytes], dict[str, str]]:
    """Files of an installed skill folder, and the files too large to read (path -> sha256), as fingerprint() takes them.
    Dependency, VCS and cache folders and symbolic links are left out."""
    files: dict[str, bytes] = {}
    oversize: dict[str, str] = {}
    for item in sorted(folder.rglob("*")):
        relative = item.relative_to(folder)
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


def read_zip(data: bytes) -> dict[str, bytes]:
    """Files of an uploaded ZIP after the intake safety checks (see ingestion.read_skill_zip_bytes), rooted at the
    skill folder: a ZIP made by zipping `release-notes/` holds `release-notes/SKILL.md`, the installed folder holds
    `SKILL.md`; both are the same package."""
    return rooted(read_skill_zip_bytes(data))


def zip_folder(data: bytes) -> str | None:
    """The folder a ZIP wraps its skill in (`release-notes` for `release-notes/SKILL.md`), or None."""
    files = read_skill_zip_bytes(data)
    inner = rooted(files)
    if inner is files:
        return None
    first = next(iter(files))
    return first.split("/", 1)[0] if "/" in first else None


def rooted(files: dict[str, bytes]) -> dict[str, bytes]:
    """Paths relative to the folder holding the main (shallowest) SKILL.md, when every file is inside that folder."""
    skill_files = sorted((p for p in files if p.rsplit("/", 1)[-1] == "SKILL.md"), key=lambda p: (p.count("/"), p))
    if not skill_files or "/" not in skill_files[0]:
        return files
    prefix = skill_files[0].rsplit("/", 1)[0] + "/"
    if not all(p.startswith(prefix) for p in files):
        return files
    return {p[len(prefix):]: raw for p, raw in files.items()}


def as_text(files: dict[str, bytes]) -> dict[str, str]:
    """UTF-8 text of each file (BOM removed); files that are not text are empty strings."""
    text: dict[str, str] = {}
    for path, raw in files.items():
        try:
            text[path] = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text[path] = ""
    return text


def skill_md(text: dict[str, str]) -> str:
    """The package's main SKILL.md text (the shortest SKILL.md path), or ''."""
    paths = [p for p in text if p.rsplit("/", 1)[-1] == "SKILL.md"]
    return text[min(paths, key=len)] if paths else ""
