"""Running SkillProof: serve the API, apply migrations, back up and restore, and print a service definition."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

Result = tuple[dict[str, Any], int]


def run_serve(args) -> int:
    from skillproof.service import ServiceError, load_config, serve

    try:
        serve(load_config(args.config))
        return 0
    except (OSError, ValueError, ServiceError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 4


def run_service_file(args) -> int:
    from skillproof.service import ServiceError, service_file

    try:
        sys.stdout.write(service_file(args.config, args.kind))
        return 0
    except ServiceError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 4


def run_migrate(args) -> Result:
    from skillproof.service import ServiceError, load_config, migrate_all

    try:
        return migrate_all(load_config(args.config)), 0
    except (OSError, ValueError, ServiceError) as exc:
        return {"error": str(exc)}, 4


def run_backup_or_restore(args) -> Result:
    from skillproof.service import ServiceError, backup, load_config, restore

    try:
        config = load_config(args.config)
        return (backup(config) if args.command == "backup" else restore(config, args.source)), 0
    except (OSError, ValueError, ServiceError, subprocess.CalledProcessError) as exc:
        return {"error": str(exc)}, 4


def add(commands, conf) -> None:
    serve_cmd = commands.add_parser("serve", help="Run the API from a configuration file (storage, sign-in, scheduled backups).")
    serve_cmd.add_argument("--config", required=True)
    serve_cmd.set_defaults(run=run_serve)
    migrate_cmd = commands.add_parser("migrate", help="Apply pending schema steps to every store, then exit. Run it with a schema-owning role before starting a service that runs with SKILLPROOF_SCHEMA=verify.")
    migrate_cmd.add_argument("--config", required=True)
    migrate_cmd.add_argument("--output", default="-")
    migrate_cmd.set_defaults(run=run_migrate)
    backup_cmd = commands.add_parser("backup", help="Back up the catalogue, approvals and history now (consistent copy, hashed manifest, retention).")
    backup_cmd.add_argument("--config", required=True)
    backup_cmd.add_argument("--output", default="-")
    backup_cmd.set_defaults(run=run_backup_or_restore)
    restore_cmd = commands.add_parser("restore", help="Restore a SQLite backup after checking its hashes. The server must be stopped.")
    restore_cmd.add_argument("--config", required=True)
    restore_cmd.add_argument("--from", dest="source", required=True)
    restore_cmd.add_argument("--output", default="-")
    restore_cmd.set_defaults(run=run_backup_or_restore)
    unit_cmd = commands.add_parser("service-file", help="Print a systemd unit or a Windows scheduled-task definition that runs 'serve'.")
    unit_cmd.add_argument("--config", required=True)
    unit_cmd.add_argument("--kind", choices=("systemd", "windows-task"), default="systemd")
    unit_cmd.set_defaults(run=run_service_file)
