"""Running as a service: configuration, readiness, backups with hashes and retention, restore, service files."""
import json
import os
import shutil
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import PG_URL
from skillproof.api.main import app
from skillproof.approvals import ApprovalStore
from skillproof.authorization import GovernanceAccess
from skillproof.cli import main
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SkillRegistry
from skillproof.service import ServiceError, backup, load_config, restore, service_file
from test_registry import assurance_report, skill_report


def write_config(folder: Path, port: int = 1, **extra) -> Path:
    lines = ["[server]", f"port = {port}", "[storage]", 'data_dir = "data"', "[backup]", 'dir = "backups"', f"keep = {extra.get('keep', 14)}"]
    path = folder / "skillproof.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.mark.sqlite_only
def test_backup_is_consistent_hashed_and_pruned(tmp_path):
    config = load_config(write_config(tmp_path, keep=2))
    assert Path(config["storage"]["data_dir"]) == (tmp_path / "data").resolve()
    registry = SkillRegistry(Path(config["storage"]["data_dir"]) / "registry.db")
    registry.register("acme", skill_report("alpha", "a"), assurance_report(), actor_id="alice")
    first = backup(config)
    assert first["kind"] == "sqlite" and "registry.db" in first["files"]
    for _ in range(2):
        backup(config)
    kept = sorted(p.name for p in (tmp_path / "backups").glob("skillproof-*"))
    assert len(kept) == 2 and first["backup"].split(os.sep)[-1] not in kept  # the oldest was pruned
    manifest = json.loads((Path(first["backup"]).parent / kept[-1] / "manifest.json").read_text())
    assert manifest["files"]["registry.db"]["sha256"]
    registry.close()


@pytest.mark.sqlite_only
def test_restore_checks_hashes_and_refuses_a_running_server(tmp_path):
    config = load_config(write_config(tmp_path))
    data = Path(config["storage"]["data_dir"])
    registry = SkillRegistry(data / "registry.db")
    registry.register("acme", skill_report("alpha", "a"), assurance_report(), actor_id="alice")
    saved = backup(config)["backup"]
    registry.register("acme", skill_report("beta", "b"), assurance_report(), actor_id="alice")  # after the backup
    registry.close()

    damaged = tmp_path / "damaged"
    shutil.copytree(saved, damaged)
    (damaged / "registry.db").write_bytes(b"not a database")
    with pytest.raises(ServiceError, match="hash"):
        restore(config, damaged)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    config["server"]["port"] = listener.getsockname()[1]
    with pytest.raises(ServiceError, match="stop it"):
        restore(config, saved)
    listener.close()
    config["server"]["port"] = 1

    result = restore(config, saved)
    assert result["restored"] == ["registry.db"] or "registry.db" in result["restored"]
    assert (data / "registry.db.pre-restore").exists()
    reopened = SkillRegistry(data / "registry.db")
    assert {s["skill_name"] for s in reopened.catalogue("acme")} == {"alpha"}  # beta was after the backup
    reopened.close()


def test_readiness_reports_storage(tmp_path):
    client = TestClient(app)
    app.state.governance = None
    saved = {k: os.environ.pop(k, None) for k in ("SKILLPROOF_DATA_DIR", "SKILLPROOF_DATABASE_URL")}
    try:
        assert client.get("/health/ready").status_code == 503
        app.state.governance = GovernanceAccess(registry=SkillRegistry(tmp_path / "r.db"), approvals=ApprovalStore(tmp_path / "a.db"),
                                                history=EvaluationHistoryStore(tmp_path / "h.db"))
        ready = client.get("/health/ready")
        assert ready.status_code == 200 and ready.json()["status"] == "ready"
        assert ready.json()["storage"] == ("postgres" if PG_URL else "sqlite")
    finally:
        governance = app.state.governance
        app.state.governance = None
        if governance:
            governance.registry.close(); governance.approvals.close(); governance.history.close()
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


def test_configuration_and_service_files(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text("[server]\nport = 1\n", encoding="utf-8")
    with pytest.raises(ServiceError, match="storage"):
        load_config(bad)
    path = write_config(tmp_path)
    unit = service_file(path, "systemd")
    assert "ExecStart=" in unit and "serve --config" in unit and "Restart=on-failure" in unit
    assert "<BootTrigger>" in service_file(path, "windows-task")
    out = tmp_path / "backup.json"
    assert main(["backup", "--config", str(path), "--output", str(out)]) == 0
    assert json.loads(out.read_text())["kind"] == "sqlite"


@pytest.mark.skipif(not (PG_URL and os.environ.get("SKILLPROOF_PG_BIN")), reason="needs the PostgreSQL test server and its pg_dump")
def test_postgres_backup_uses_pg_dump(tmp_path):
    path = tmp_path / "pg.toml"
    pg_dump = Path(os.environ["SKILLPROOF_PG_BIN"]) / ("pg_dump.exe" if os.name == "nt" else "pg_dump")
    path.write_text(f'[storage]\ndatabase_url = "{PG_URL}"\n[backup]\ndir = "b"\npg_dump = "{pg_dump.as_posix()}"\n', encoding="utf-8")
    result = backup(load_config(path))
    assert result["kind"] == "postgres" and result["files"]["skillproof.dump"]["bytes"] > 0
