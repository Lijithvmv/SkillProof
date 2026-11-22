"""Make a machine run what the catalogue approved (`skillproof sync`).

For every installed skill (the same catalogue names and package fingerprints as catalogue-import):
- `approved`        the installed folder is the approved version: nothing to do;
- `replace`         an approved version exists and the installed folder differs (changed after approval, or an
                    unapproved update): the folder is moved to quarantine and the approved package installed in its
                    place;
- `unapproved`      nothing is approved under that name: reported, and quarantined only with `strict`;
- `blocked`         an approved version exists but its package is not stored (not distributable): reported, untouched.

Nothing is deleted: a quarantined folder is moved, intact, under the quarantine folder with a record of why, and can be
moved back. An installed package is written beside the target first, its fingerprint re-checked on disk, and only then
moved into place; if anything fails, the original folder is restored. Without `apply` the plan is reported and nothing
changes.
"""
from __future__ import annotations

import json
import shutil
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from skillproof import package
from skillproof.storage.artifacts import unpack


class ApprovedSource(Protocol):
    def approved(self) -> list[dict[str, Any]]: ...

    def package(self, version_id: str) -> tuple[str, bytes]: ...  # (fingerprint the server vouches for, zip bytes)


@dataclass
class Installed:
    name: str
    folder: Path
    fingerprint: str


def plan(approved: list[dict[str, Any]], installed: list[Installed], *, strict: bool = False) -> list[dict[str, Any]]:
    by_name = {a["skill_name"]: a for a in approved}
    actions = []
    for item in sorted(installed, key=lambda i: i.name):
        target = by_name.get(item.name)
        base = {"skill_name": item.name, "folder": str(item.folder), "installed_fingerprint": item.fingerprint}
        if target is None:
            actions.append({**base, "action": "quarantine" if strict else "unapproved",
                            "reason": "no approved version in the catalogue"})
        elif target["fingerprint"] == item.fingerprint:
            actions.append({**base, "action": "approved", "version_id": target["version_id"]})
        elif not target.get("distributable", True):
            actions.append({**base, "action": "blocked", "version_id": target["version_id"], "approved_fingerprint": target["fingerprint"],
                            "reason": "the approved version's package is not stored, so it cannot be installed"})
        else:
            actions.append({**base, "action": "replace", "version_id": target["version_id"], "approved_fingerprint": target["fingerprint"],
                            "reason": "the installed folder is not the approved version"})
    return actions


def _quarantine(folder: Path, quarantine_root: Path, record: dict[str, Any]) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = quarantine_root / stamp / folder.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(folder), str(destination))
    (destination.parent / f"{folder.name}.skillproof-quarantine.json").write_text(
        json.dumps({**record, "original_folder": str(folder), "host": socket.gethostname(), "quarantined_at": stamp,
                    "restore": f"move {destination} back to {folder}"}, indent=2), encoding="utf-8")
    return destination


def _write_package(files: dict[str, bytes], folder: Path) -> None:
    folder.mkdir(parents=True)
    for name, raw in files.items():
        path = folder / name
        if not path.resolve().is_relative_to(folder.resolve()):
            raise ValueError(f"package path escapes the skill folder: {name}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def apply(actions: list[dict[str, Any]], source: ApprovedSource, quarantine_root: Path,
          log: Callable[[str, dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
    """Carry out a plan. Each action gets an `outcome`; a failure restores the folder it touched."""
    for action in actions:
        folder = Path(action["folder"])
        try:
            if action["action"] == "quarantine":
                action["quarantined_to"] = str(_quarantine(folder, quarantine_root, action))
                action["outcome"] = "quarantined"
            elif action["action"] == "replace":
                vouched, blob = source.package(action["version_id"])
                if vouched != action["approved_fingerprint"]:
                    raise ValueError("the server's fingerprint for the package differs from the approved one")
                files = unpack(blob, action["approved_fingerprint"])  # refuses bytes that are not the approved package
                staging = folder.with_name(folder.name + ".skillproof-incoming")
                if staging.exists():
                    raise ValueError(f"{staging} already exists; a previous sync did not finish")
                _write_package(files, staging)
                on_disk, oversize = package.read_folder(staging)
                if package.fingerprint(on_disk, oversize) != action["approved_fingerprint"]:
                    shutil.rmtree(staging)
                    raise ValueError("the written package does not match the approved fingerprint on disk")
                moved = _quarantine(folder, quarantine_root, action)
                try:
                    staging.rename(folder)
                except OSError:
                    shutil.move(str(moved), str(folder))  # put the original back
                    raise
                action["quarantined_to"] = str(moved)
                action["outcome"] = "installed_approved"
            else:
                action["outcome"] = "unchanged"
        except Exception as exc:  # noqa: BLE001 - one skill failing must not stop the rest
            action["outcome"] = "failed"
            action["error"] = f"{type(exc).__name__}: {exc}"[:500]
        if log:
            log("sync_action", {k: action.get(k) for k in ("skill_name", "action", "outcome", "error")})
    return actions


def summary(actions: list[dict[str, Any]], applied: bool) -> dict[str, Any]:
    count = lambda key, value: sum(a.get(key) == value for a in actions)  # noqa: E731
    return {"method": "catalogue_sync", "applied": applied, "skills": len(actions),
            "approved": count("action", "approved"), "to_replace": count("action", "replace"),
            "unapproved": count("action", "unapproved") + count("action", "quarantine"), "blocked": count("action", "blocked"),
            "installed_approved": count("outcome", "installed_approved"), "quarantined": count("outcome", "quarantined"),
            "failed": count("outcome", "failed"), "actions": actions}
