"""One storage layer for the catalogue, approvals and evaluation history: SQLite or PostgreSQL.

A store is opened with a file path (SQLite, one machine) or a `postgresql://` URL. The stores write their SQL once,
with `?` placeholders; this layer adapts it to the backend. Schemas are kept per dialect by each store.

PostgreSQL enforces tenant isolation itself: every table holding tenant data has row-level security (FORCE, so the
owning role obeys it too), and every transaction first sets `skillproof.tenant`. A query run without a tenant sees
and changes nothing. Connect as a role that is not a superuser and cannot bypass row-level security.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def is_postgres_url(target: str | Path) -> bool:
    return str(target).startswith(("postgresql://", "postgres://"))


class Database:
    def __init__(self, target: str | Path):
        self.target = str(target)
        self._lock = threading.RLock()
        if is_postgres_url(self.target):
            import psycopg2
            import psycopg2.extras

            self.dialect = "postgres"
            self._extras = psycopg2.extras
            self._connection = psycopg2.connect(self.target)
            self._connection.autocommit = True
        else:
            self.dialect = "sqlite"
            if self.target != ":memory:":
                Path(self.target).parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(self.target, check_same_thread=False, isolation_level=None)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")

    @property
    def postgres(self) -> bool:
        return self.dialect == "postgres"

    @property
    def insertion_order(self) -> str:
        """Column that breaks ties in insertion order (SQLite's rowid; a sequence column in PostgreSQL)."""
        return "seq" if self.postgres else "rowid"

    def execute(self, sql: str, params: tuple | list = ()) -> Any:
        if self.postgres:
            cursor = self._connection.cursor(cursor_factory=self._extras.RealDictCursor)
            cursor.execute(sql.replace("?", "%s"), tuple(params))
            return cursor
        return self._connection.execute(sql, tuple(params))

    def script(self, sql: str) -> None:
        with self._lock:
            if self.postgres:
                with self._connection.cursor() as cursor:
                    cursor.execute(sql)
            else:
                self._connection.executescript(sql)

    def columns(self, table: str) -> set[str]:
        if self.postgres:
            rows = self.execute("SELECT column_name FROM information_schema.columns WHERE table_name = ?", (table,)).fetchall()
            return {row["column_name"] for row in rows}
        return {row[1] for row in self._connection.execute(f"PRAGMA table_info({table})")}

    @contextmanager
    def transaction(self, tenant_id: str | None = None, *, write: bool = False) -> Iterator["Database"]:
        """Run statements as one transaction; in PostgreSQL the tenant is set first so row-level security applies."""
        with self._lock:
            if self.postgres:
                self.execute("BEGIN" if write else "BEGIN READ ONLY")
                if tenant_id is not None:
                    self.execute("SELECT set_config('skillproof.tenant', ?, true)", (tenant_id,))
            else:
                self.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield self
            except BaseException:
                self.execute("ROLLBACK")
                raise
            self.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def tenant_policy(table: str, condition: str = "tenant_id = current_setting('skillproof.tenant', true)") -> str:
    """PostgreSQL DDL: row-level security on a table, enforced for every role including the owner."""
    return (f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
            f"DROP POLICY IF EXISTS {table}_tenant ON {table}; "
            f"CREATE POLICY {table}_tenant ON {table} USING ({condition}) WITH CHECK ({condition});")


def append_only(table: str, message: str) -> str:
    """PostgreSQL DDL: refuse UPDATE and DELETE on an audit table."""
    return (f"CREATE OR REPLACE FUNCTION {table}_append_only() RETURNS trigger LANGUAGE plpgsql AS "
            f"$$ BEGIN RAISE EXCEPTION '{message}'; END $$; "
            f"DROP TRIGGER IF EXISTS {table}_no_change ON {table}; "
            f"CREATE TRIGGER {table}_no_change BEFORE UPDATE OR DELETE ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION {table}_append_only();")
