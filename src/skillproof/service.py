"""Run SkillProof as a service: one configuration file, health checks, backups and restore.

    skillproof serve --config skillproof.toml          # the API, with scheduled backups when configured
    skillproof backup --config skillproof.toml         # one backup now
    skillproof restore --config skillproof.toml --from <backup folder>
    skillproof service-file --config skillproof.toml --kind systemd|windows-task

The configuration file sets the environment the API reads (storage, authentication), so the same settings apply to
the API and to the catalogue commands. Values already in the environment are not overridden unless the file sets them.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import logging

from skillproof.logs import configure as configure_logging, log

STORE_FILES = ("registry.db", "approvals.db", "history.db", "jobs.db", "notify.db", "fleet.db")
ENV_KEYS = {
    ("storage", "database_url"): "SKILLPROOF_DATABASE_URL",
    ("storage", "data_dir"): "SKILLPROOF_DATA_DIR",
    ("auth", "mode"): "SKILLPROOF_AUTH_MODE",
    ("auth", "issuer"): "SKILLPROOF_OIDC_ISSUER",
    ("auth", "audience"): "SKILLPROOF_OIDC_AUDIENCE",
    ("auth", "jwks_url"): "SKILLPROOF_OIDC_JWKS_URL",
    ("auth", "client_id"): "SKILLPROOF_OIDC_CLIENT_ID",
    ("auth", "scope"): "SKILLPROOF_OIDC_SCOPE",
    ("auth", "role_claim"): "SKILLPROOF_OIDC_ROLE_CLAIM",
    ("auth", "tenant_claim"): "SKILLPROOF_OIDC_TENANT_CLAIM",
    ("server", "environment"): "SKILLPROOF_ENV",
    ("evaluation", "model"): "SKILLPROOF_EVAL_MODEL",
    ("evaluation", "draft_model"): "SKILLPROOF_EVAL_DRAFT_MODEL",
    ("evaluation", "ollama_url"): "SKILLPROOF_OLLAMA_URL",
    ("evaluation", "tasks"): "SKILLPROOF_EVAL_TASKS",
    ("evaluation", "repeats"): "SKILLPROOF_EVAL_REPEATS",
}


class ServiceError(RuntimeError):
    """A service command cannot run with this configuration."""


def load_config(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    with path.open("rb") as handle:
        config = tomllib.load(handle)
    storage = config.setdefault("storage", {})
    if not storage.get("database_url") and not storage.get("data_dir"):
        raise ServiceError("[storage] needs database_url (PostgreSQL) or data_dir (SQLite)")
    if storage.get("data_dir"):
        storage["data_dir"] = str((path.parent / storage["data_dir"]).resolve()) if not Path(storage["data_dir"]).is_absolute() else storage["data_dir"]
    backup = config.setdefault("backup", {})
    if backup.get("dir") and not Path(backup["dir"]).is_absolute():
        backup["dir"] = str((path.parent / backup["dir"]).resolve())
    config.setdefault("server", {}).setdefault("host", "127.0.0.1")
    config["server"].setdefault("port", 8045)
    return config


def apply_config(config: dict[str, Any]) -> None:
    """Set the environment the API reads from the configuration file."""
    for (section, key), variable in ENV_KEYS.items():
        value = (config.get(section) or {}).get(key)
        if value not in (None, ""):
            os.environ[variable] = str(value)
    if (config.get("storage") or {}).get("database_url"):
        os.environ.pop("SKILLPROOF_DATA_DIR", None)  # one storage, never both


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def backup(config: dict[str, Any]) -> dict[str, Any]:
    """One consistent backup into [backup] dir, with a manifest of file hashes; keeps the newest `keep` backups."""
    settings = config.get("backup") or {}
    if not settings.get("dir"):
        raise ServiceError("[backup] dir is not set")
    root = Path(settings["dir"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = root / f"skillproof-{stamp}"
    work = root / f".partial-{stamp}"
    work.mkdir(parents=True)
    storage = config["storage"]
    files: dict[str, dict[str, Any]] = {}
    try:
        if storage.get("database_url"):
            pg_dump = settings.get("pg_dump") or shutil.which("pg_dump")
            if not pg_dump:
                raise ServiceError("PostgreSQL backup needs pg_dump: set [backup] pg_dump to its path")
            out = work / "skillproof.dump"
            subprocess.run([pg_dump, "--format=custom", "--no-owner", "--file", str(out), storage["database_url"]],
                           check=True, capture_output=True, timeout=3600)
            files[out.name] = {"sha256": _sha256(out), "bytes": out.stat().st_size}
            kind = "postgres"
        else:
            data = Path(storage["data_dir"])
            for name in STORE_FILES:
                source = data / name
                if not source.exists():
                    continue
                out = work / name
                src, dst = sqlite3.connect(source), sqlite3.connect(out)
                try:
                    src.backup(dst)  # SQLite's online backup: a consistent copy while the server runs
                finally:
                    dst.close()  # `with sqlite3.connect()` would not close: Windows then refuses the folder rename
                    src.close()
                files[name] = {"sha256": _sha256(out), "bytes": out.stat().st_size}
            kind = "sqlite"
        manifest = {"format": "skillproof-backup-1", "kind": kind, "created_at": stamp, "files": files}
        (work / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        work.replace(target)  # complete backups only ever appear under their final name
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    keep = int(settings.get("keep", 14))
    backups = sorted(p for p in root.glob("skillproof-*") if (p / "manifest.json").exists())
    for old in backups[:-keep] if keep > 0 else []:
        shutil.rmtree(old)
    return {"backup": str(target), **manifest, "kept": min(len(backups), keep) if keep > 0 else len(backups)}


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((host, port)) == 0


def restore(config: dict[str, Any], source: str | Path) -> dict[str, Any]:
    """Put a SQLite backup back after checking every file's hash. Refuses while the server answers on its port; the
    files it replaces are kept beside it as *.pre-restore."""
    source = Path(source)
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format") != "skillproof-backup-1":
        raise ServiceError("not a SkillProof backup")
    if manifest.get("kind") != "sqlite":
        raise ServiceError("restore a PostgreSQL backup with pg_restore into the configured database")
    if config["storage"].get("database_url"):
        raise ServiceError("this configuration uses PostgreSQL; a SQLite backup cannot be restored into it")
    server = config["server"]
    if _port_open(server["host"], int(server["port"])):
        raise ServiceError(f"the server answers on {server['host']}:{server['port']}; stop it before restoring")
    for name, meta in manifest["files"].items():
        if _sha256(source / name) != meta["sha256"]:
            raise ServiceError(f"{name} does not match its recorded hash; the backup is damaged")
    data = Path(config["storage"]["data_dir"])
    data.mkdir(parents=True, exist_ok=True)
    restored = []
    for name in manifest["files"]:
        current = data / name
        staged = data / (name + ".restoring")
        shutil.copy2(source / name, staged)
        if current.exists():
            current.replace(data / (name + ".pre-restore"))
        staged.replace(current)
        restored.append(name)
    return {"restored": restored, "from": str(source), "data_dir": str(data)}


def _backup_loop(config: dict[str, Any], hours: float, stop: threading.Event) -> None:
    while not stop.wait(hours * 3600):
        try:
            result = backup(config)
            log("backup", path=result["backup"], files=len(result.get("files", {})))
        except Exception as exc:  # a failed backup is reported, never stops the server
            log("backup_failed", logging.ERROR, error=str(exc))


def migrate_all(config: dict[str, Any]) -> dict[str, Any]:
    """Open every store with migrations allowed (applying pending steps), then report each store's applied versions."""
    apply_config(config)
    os.environ["SKILLPROOF_SCHEMA"] = "apply"
    from skillproof.api.main import governance_from_environment

    governance = governance_from_environment()
    if governance is None:
        raise ServiceError("no storage configured")
    stores = {"registry": governance.registry.db, "approvals": governance.approvals.db, "history": governance.history.db,
              "jobs": governance.jobs.db, "notify": governance.notifications.db, "fleet": governance.fleet.db}
    report = {}
    for name, db in stores.items():
        rows = db.execute("SELECT version FROM schema_migrations WHERE store = ? ORDER BY version", (name,)).fetchall()
        report[name] = [row["version"] for row in rows]
        db.close()
    return {"schema": report}


def serve(config: dict[str, Any]) -> None:
    apply_config(config)
    configure_logging((config.get("server") or {}).get("log_level"))
    import uvicorn

    from skillproof.api.main import app

    stop = threading.Event()
    hours = float((config.get("backup") or {}).get("interval_hours") or 0)
    if hours > 0 and (config.get("backup") or {}).get("dir"):
        threading.Thread(target=_backup_loop, args=(config, hours, stop), daemon=True, name="skillproof-backups").start()
    try:
        uvicorn.run(app, host=config["server"]["host"], port=int(config["server"]["port"]), log_level="info")
    finally:
        stop.set()


def service_file(config_path: str | Path, kind: str) -> str:
    config_path = Path(config_path).resolve()
    command = f'"{sys.executable}" -m skillproof.cli serve --config "{config_path}"'
    if kind == "systemd":
        return (
            "[Unit]\nDescription=SkillProof skill catalogue\nAfter=network-online.target\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={command}\nRestart=on-failure\nRestartSec=5\n"
            "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\n"
            f"ReadWritePaths={config_path.parent}\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
    if kind == "windows-task":
        return (
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
            "<Task version=\"1.4\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
            "  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>\n"
            "  <Settings><RestartOnFailure><Interval>PT1M</Interval><Count>10</Count></RestartOnFailure>"
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>\n"
            f"  <Actions><Exec><Command>{sys.executable}</Command>"
            f"<Arguments>-m skillproof.cli serve --config \"{config_path}\"</Arguments></Exec></Actions>\n"
            "</Task>\n"
        )
    raise ServiceError("kind must be systemd or windows-task")
