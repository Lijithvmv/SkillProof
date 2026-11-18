"""Local PostgreSQL server for SkillProof's Postgres tests.

    python scripts/pg_test_server.py init     # create the cluster, the app role and the test database
    python scripts/pg_test_server.py start | stop | status | url

The server listens on 127.0.0.1 only (port SKILLPROOF_PG_PORT, default 55460) and trusts local connections: it is a
test fixture, not a deployment. Tests connect as `skillproof_app`, a role that is not a superuser and cannot bypass
row-level security, so tenant isolation is tested as production would enforce it. Binaries come from
SKILLPROOF_PG_BIN (a PostgreSQL 15+ bin folder); data lives in SKILLPROOF_PG_DATA (default ~/.skillproof/pg-test).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

BIN = Path(os.environ.get("SKILLPROOF_PG_BIN", ""))
DATA = Path(os.environ.get("SKILLPROOF_PG_DATA", str(Path.home() / ".skillproof" / "pg-test")))
PORT = os.environ.get("SKILLPROOF_PG_PORT", "55460")
APP_ROLE, DATABASE = "skillproof_app", "skillproof_test"


def tool(name: str) -> str:
    exe = BIN / (name + (".exe" if os.name == "nt" else ""))
    if not exe.exists():
        raise SystemExit(f"{exe} not found: set SKILLPROOF_PG_BIN to a PostgreSQL bin folder")
    return str(exe)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), check=check, capture_output=True, text=True)


def url() -> str:
    return f"postgresql://{APP_ROLE}@127.0.0.1:{PORT}/{DATABASE}"


def psql(sql: str) -> None:
    run(tool("psql"), "-h", "127.0.0.1", "-p", PORT, "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", sql)


def main(command: str) -> int:
    if command == "init":
        if (DATA / "PG_VERSION").exists():
            print(f"cluster already exists at {DATA}")
            return 0
        DATA.parent.mkdir(parents=True, exist_ok=True)
        run(tool("initdb"), "-D", str(DATA), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--locale=C")
        with open(DATA / "postgresql.conf", "a", encoding="utf-8") as conf:
            conf.write(f"\nlisten_addresses = '127.0.0.1'\nport = {PORT}\nfsync = off\n")
        main("start")
        psql(f"CREATE ROLE {APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS")
        psql(f"CREATE DATABASE {DATABASE} OWNER {APP_ROLE}")
        print(url())
    elif command == "start":
        # Not captured: on Windows the server inherits the pipes and a captured pg_ctl never returns.
        subprocess.run([tool("pg_ctl"), "-D", str(DATA), "-l", str(DATA / "server.log"), "-w", "start"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, check=False)
        print(run(tool("pg_ctl"), "-D", str(DATA), "status", check=False).stdout.strip().splitlines()[0])
    elif command == "stop":
        print(run(tool("pg_ctl"), "-D", str(DATA), "-w", "stop", check=False).stdout.strip())
    elif command == "status":
        print(run(tool("pg_ctl"), "-D", str(DATA), "status", check=False).stdout.strip())
    elif command == "url":
        print(url())
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
