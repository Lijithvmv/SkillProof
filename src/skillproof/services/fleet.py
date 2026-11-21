"""A machine reports the skills it runs; each is compared with the tenant's approved version, the latest report per
machine is stored, and a skill newly running unapproved raises an alert."""
from __future__ import annotations

from typing import Any

from skillproof.authorization import GovernanceAccess, Principal
from skillproof.fleet import compare
from skillproof.services import alerts


def report(governance: GovernanceAccess, principal: Principal, host: str, installed: list[dict[str, Any]]) -> dict[str, Any]:
    names = {str(item.get("skill_name", "")).strip() for item in installed}
    compared = compare(governance.fleet_versions(principal, names), installed)
    result = governance.record_fleet_report(principal, host, compared)
    for entry in result["newly_unapproved"]:
        alerts.fleet_unapproved(governance, principal.tenant_id, host, entry)
    return result
