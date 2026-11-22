"""Which events raise which alert, with what payload. Alerts are best effort by design: queuing one never raises, so
an alert can never block or undo the action it reports. Payloads carry ids, names, levels and counts, never skill
contents (delivery and signing: skillproof.storage.notify)."""
from __future__ import annotations

from typing import Any

from skillproof.authorization import GovernanceAccess, Principal
from skillproof.models import FleetEntry, SkillVersion


def emit(governance: GovernanceAccess, tenant_id: str, event: str, payload: dict[str, Any]) -> None:
    if governance.notifications is None:
        return
    try:
        governance.notifications.emit(tenant_id, event, payload)
    except Exception:  # noqa: BLE001 - an alert must not break what it reports
        pass


def version_registered(governance: GovernanceAccess, principal: Principal, version: SkillVersion) -> None:
    change = version.get("capability_change") or {}
    if change.get("decision") == "block" and version.get("created_at") == version.get("updated_at"):  # new, not a re-upload
        emit(governance, principal.tenant_id, "version.block_level_addition", {
            "version_id": version["version_id"], "skill_name": version["skill_name"], "counts": change.get("counts"),
            "against": change.get("against"), "change_hash": change.get("change_hash"),
            "block_items": [f"{i['category']}: {i['value']}" for i in change.get("items", []) if i["level"] == "block"][:10]})


def version_promoted(governance: GovernanceAccess, principal: Principal, version: SkillVersion, request_id: str) -> None:
    emit(governance, principal.tenant_id, "version.promoted", {"version_id": version["version_id"], "skill_name": version["skill_name"],
                                                               "promoted_by": principal.user_id, "approval_request_id": request_id})


def version_rolled_back(governance: GovernanceAccess, principal: Principal, skill_name: str, restored: SkillVersion, reason: str) -> None:
    emit(governance, principal.tenant_id, "version.rolled_back", {"skill_name": skill_name, "restored_version_id": restored["version_id"],
                                                                  "by": principal.user_id, "reason": reason[:500]})


def fleet_unapproved(governance: GovernanceAccess, tenant_id: str, host: str, entry: FleetEntry) -> None:
    emit(governance, tenant_id, "fleet.running_unapproved", {"host": host, **entry})
