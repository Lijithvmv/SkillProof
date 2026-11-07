from __future__ import annotations

import stat
import zipfile
from pathlib import PurePosixPath


class PackageError(ValueError):
    pass


MAX_FILES = 500
MAX_FILE_SIZE = 2_000_000
MAX_TOTAL_SIZE = 10_000_000


def read_skill_zip(data: bytes) -> dict[str, str]:
    files: dict[str, str] = {}
    total = 0
    try:
        archive = zipfile.ZipFile(__import__("io").BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise PackageError("Upload is not a valid ZIP archive.") from exc
    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_FILES:
            raise PackageError(f"ZIP contains more than {MAX_FILES} entries.")
        for info in entries:
            raw = info.filename.replace("\\", "/")
            path = PurePosixPath(raw)
            mode = info.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or (path.parts and ":" in path.parts[0]):
                raise PackageError(f"Unsafe ZIP path: {raw}")
            if stat.S_ISLNK(mode):
                raise PackageError(f"Symlink entries are not allowed: {raw}")
            if info.is_dir():
                continue
            normalized = str(path).lstrip("./")
            if normalized in files:
                raise PackageError(f"Duplicate ZIP path: {normalized}")
            if info.file_size > MAX_FILE_SIZE:
                raise PackageError(f"File exceeds {MAX_FILE_SIZE} bytes: {normalized}")
            total += info.file_size
            if total > MAX_TOTAL_SIZE:
                raise PackageError(f"ZIP expands beyond {MAX_TOTAL_SIZE} bytes.")
            try:
                files[normalized] = archive.read(info).decode("utf-8-sig")
            except UnicodeDecodeError:
                # Non-text assets remain represented in the manifest without being interpreted.
                files[normalized] = ""
    # Handle archives that wrap a skill directory in one extra packaging folder.
    roots = {PurePosixPath(path).parts[0] for path in files if len(PurePosixPath(path).parts) > 1}
    skill_depths = [len(PurePosixPath(path).parts) for path in files if PurePosixPath(path).name == "SKILL.md"]
    if len(roots) == 1 and skill_depths and max(skill_depths) >= 3:
        root = next(iter(roots))
        nested = {str(PurePosixPath(path).relative_to(root)): content for path, content in files.items()}
        if any(PurePosixPath(path).name == "SKILL.md" for path in nested):
            files = nested
    return files
