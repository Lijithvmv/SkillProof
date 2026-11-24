"""Reading a package (folder or ZIP) as raw bytes, within the size limits."""
from __future__ import annotations

import re
import stat
import zipfile

from io import BytesIO
from pathlib import Path, PurePosixPath

from skillproof.ingestion import MAX_FILE_SIZE, MAX_FILES, MAX_TOTAL_SIZE, PackageError


# --------------------------------------------------------------------------------------------- loading

def _check_total(files: dict[str, bytes]) -> None:
    if len(files) > MAX_FILES:
        raise PackageError(f"Package has more than {MAX_FILES} files.")
    if sum(len(v) for v in files.values()) > MAX_TOTAL_SIZE:
        raise PackageError(f"Package is larger than {MAX_TOTAL_SIZE} bytes.")


def read_package_bytes(path: str | Path) -> dict[str, bytes]:
    """Read a skill directory or ZIP into {relative posix path: raw bytes}, with the ingestion size limits."""
    root = Path(path)
    files: dict[str, bytes] = {}
    if root.is_dir():
        for item in sorted(root.rglob("*")):
            relative = item.relative_to(root)
            if any(part in {".git", "__pycache__", "node_modules"} for part in relative.parts):
                continue
            if item.is_symlink():
                raise PackageError(f"Symlinks are not allowed: {relative.as_posix()}")
            if item.is_file():
                if item.stat().st_size > MAX_FILE_SIZE:
                    raise PackageError(f"File exceeds {MAX_FILE_SIZE} bytes: {relative.as_posix()}")
                files[relative.as_posix()] = item.read_bytes()
                _check_total(files)
        return files
    try:
        archive = zipfile.ZipFile(BytesIO(root.read_bytes()))
    except (zipfile.BadZipFile, OSError) as exc:
        raise PackageError(f"{path} is neither a directory nor a valid ZIP archive.") from exc
    with archive:
        for info in archive.infolist():
            raw = info.filename.replace("\\", "/")
            parts = PurePosixPath(raw).parts
            if PurePosixPath(raw).is_absolute() or ".." in parts or (parts and ":" in parts[0]):
                raise PackageError(f"Unsafe ZIP path: {raw}")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise PackageError(f"Symlink entries are not allowed: {raw}")
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE_SIZE:
                raise PackageError(f"File exceeds {MAX_FILE_SIZE} bytes: {raw}")
            files[re.sub(r"^(?:\./|/)+", "", str(PurePosixPath(raw)))] = archive.read(info)  # keep a name's own leading dot
            _check_total(files)
    return files
