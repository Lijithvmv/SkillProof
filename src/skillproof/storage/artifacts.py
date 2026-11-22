"""The exact bytes of every registered package, so the catalogue can distribute what it approved.

A package is stored once per tenant under its fingerprint, as a deterministic ZIP (files in path order, fixed
timestamps), and only after the bytes are checked to have that fingerprint. Reading it back re-checks the
fingerprint, so a damaged or swapped blob is refused rather than installed. A package with files too large to read
(installed folders only) has no complete bytes and is not stored: it cannot be distributed. Row-level security keeps
tenants apart on PostgreSQL.
"""
from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from skillproof import package
from skillproof.errors import Conflict, NotFound
from skillproof.storage.database import Database, migrate, tenant_policy

SQLITE = """
    CREATE TABLE IF NOT EXISTS package_artifacts (
        tenant_id TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        size INTEGER NOT NULL,
        files INTEGER NOT NULL,
        content BLOB NOT NULL,
        stored_by TEXT NOT NULL,
        stored_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, fingerprint)
    );
"""
POSTGRES = SQLITE.replace("BLOB", "BYTEA") + tenant_policy("package_artifacts")
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


class ArtifactError(Conflict):
    """A package cannot be stored or served as asked."""


class ArtifactNotFound(ArtifactError, NotFound):
    """No stored package with that fingerprint in this tenant."""


def pack(files: dict[str, bytes]) -> bytes:
    """A deterministic ZIP of the package: the same files always give the same bytes."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[name])
    return out.getvalue()


def unpack(data: bytes, fingerprint: str) -> dict[str, bytes]:
    """The package's files, after the intake safety checks and only if they have the expected fingerprint."""
    files = package.read_zip(data)
    if package.fingerprint(files) != fingerprint:
        raise ArtifactError("the package bytes do not have the approved fingerprint; refusing them")
    return files


class ArtifactStore:
    def __init__(self, database: str | Path):
        self.db = Database(database)
        migrate(self.db, "artifacts", [(1, "package bytes per tenant and fingerprint", SQLITE, POSTGRES)])

    def put(self, tenant_id: str, files: dict[str, bytes], *, actor_id: str, oversize: dict[str, str] | None = None) -> str:
        """Store a package and return its fingerprint. Idempotent: the same package is stored once."""
        if oversize:
            raise ArtifactError(f"{len(oversize)} file(s) are over the size limit, so the package cannot be stored or distributed")
        fingerprint = package.fingerprint(files)
        blob = pack(files)
        if package.fingerprint(package.read_zip(blob)) != fingerprint:  # the archive must reproduce the package exactly
            raise ArtifactError("the package does not survive packing unchanged (path or encoding issue); not stored")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db.transaction(tenant_id, write=True) as db:
            if db.execute("SELECT 1 FROM package_artifacts WHERE tenant_id=? AND fingerprint=?", (tenant_id, fingerprint)).fetchone() is None:
                db.execute("INSERT INTO package_artifacts (tenant_id, fingerprint, size, files, content, stored_by, stored_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?)", (tenant_id, fingerprint, len(blob), len(files), blob, actor_id, now))
        return fingerprint

    def get(self, tenant_id: str, fingerprint: str) -> bytes:
        """The stored ZIP, re-checked against its fingerprint before it is returned."""
        with self.db.transaction(tenant_id) as db:
            row = db.execute("SELECT content FROM package_artifacts WHERE tenant_id=? AND fingerprint=?", (tenant_id, fingerprint)).fetchone()
        if row is None:
            raise ArtifactNotFound("no stored package with that fingerprint in this tenant")
        blob = bytes(row["content"])
        unpack(blob, fingerprint)
        return blob

    def has(self, tenant_id: str, fingerprint: str) -> bool:
        with self.db.transaction(tenant_id) as db:
            return db.execute("SELECT 1 FROM package_artifacts WHERE tenant_id=? AND fingerprint=?", (tenant_id, fingerprint)).fetchone() is not None

    def close(self) -> None:
        self.db.close()
