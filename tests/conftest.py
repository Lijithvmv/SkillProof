"""Run the storage-backed tests on PostgreSQL too.

With SKILLPROOF_TEST_PG_URL set (see scripts/pg_test_server.py), every store a test opens with a file path is opened
on that server instead, in a fresh schema per test and path, so the same tests check both backends. The URL's role
must not be a superuser and must not bypass row-level security.
"""
from __future__ import annotations

import hashlib
import os
import urllib.parse

import pytest

PG_URL = os.environ.get("SKILLPROOF_TEST_PG_URL", "").strip()


def pytest_report_header(config):
    return f"storage backend: {'postgresql ' + PG_URL.split('@')[-1] if PG_URL else 'sqlite'}"


@pytest.fixture(autouse=True)
def _postgres_backend(request, monkeypatch):
    if not PG_URL or request.node.get_closest_marker("sqlite_only"):
        yield
        return
    import psycopg2

    from skillproof import storage

    original = storage.Database.__init__
    schemas: list[str] = []

    def redirected(self, target):
        target = str(target)
        if storage.is_postgres_url(target) or target == ":memory:":
            return original(self, target)
        schema = "t_" + hashlib.sha256((request.node.nodeid + "|" + os.path.abspath(target)).encode()).hexdigest()[:24]
        if schema not in schemas:
            with psycopg2.connect(PG_URL) as admin, admin.cursor() as cursor:
                cursor.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}")
            schemas.append(schema)
        separator = "&" if "?" in PG_URL else "?"
        return original(self, PG_URL + separator + "options=" + urllib.parse.quote(f"-csearch_path={schema}"))

    monkeypatch.setattr(storage.Database, "__init__", redirected)
    yield
    for schema in schemas:
        connection = psycopg2.connect(PG_URL)
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        connection.close()


def pytest_configure(config):
    config.addinivalue_line("markers", "sqlite_only: the test inspects the SQLite file directly")
