"""Helpers every command group shares: JSON output, opening the catalogue a command works on, the principals the
local commands act as, and reading a skill's SKILL.md exactly as the catalogue fingerprints it."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

from skillproof.authorization import GovernanceAccess, Principal
from skillproof.config import settings
from skillproof.wiring import open_governance

DEFAULT_CATALOGUE = Path.home() / ".skillproof" / "catalogue"


def write_json(payload: dict[str, Any], destination: str, stdout: TextIO | None = None) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)
    if destination == "-":
        (stdout or sys.stdout).write(rendered + "\n")
    else:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")


def read_annotation_rows(path: str) -> list[dict[str, Any]]:
    """Annotations as a JSON array or JSONL; rows not yet scored (human_score null) are skipped."""
    text = Path(path).read_text(encoding="utf-8")
    rows = json.loads(text) if text.lstrip().startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"{path}: every annotation must be a JSON object")
    return [row for row in rows if row.get("human_score") is not None]


def catalogue_at(data_dir: Path) -> GovernanceAccess:
    """The catalogue a local command works on: the configured PostgreSQL database (the same one the API uses) when
    set, else the SQLite files in data_dir."""
    governance = open_governance(database_url=settings().database_url, data_dir=data_dir)
    assert governance is not None
    return governance


def importer(tenant: str) -> Principal:
    return Principal(user_id="installed-skill-import", tenant_id=tenant, role="evaluator")


def checker(tenant: str) -> Principal:
    return Principal(user_id="installed-skill-check", tenant_id=tenant, role="viewer")


def skill_text(folder: str) -> str:
    path = Path(folder)
    path = path if path.name == "SKILL.md" else path / "SKILL.md"
    return path.read_bytes().decode("utf-8-sig")  # the same decoding the catalogue fingerprints
