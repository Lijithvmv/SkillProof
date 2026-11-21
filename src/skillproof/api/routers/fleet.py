"""Fleet: machines report their installed skills; the server compares them with the approved versions."""
from __future__ import annotations


from typing import Any

from fastapi import Request
from pydantic import BaseModel, Field


from fastapi import APIRouter
from skillproof.services import fleet as fleet_service
from skillproof.api.deps import current_governance, current_principal, guarded

router = APIRouter()


class InstalledSkill(BaseModel):
    skill_name: str = Field(min_length=1, max_length=200)
    fingerprint: str = Field(min_length=64, max_length=64)


class FleetReport(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    skills: list[InstalledSkill] = Field(max_length=2000)


@router.post("/api/v1/fleet/reports")
def fleet_report(body: FleetReport, request: Request) -> dict[str, Any]:
    """A machine reports the skills installed on it (names and fingerprints only); the server answers with each one's status."""
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: fleet_service.report(governance, principal, body.host, [s.model_dump() for s in body.skills]))


@router.get("/api/v1/fleet")
def fleet(request: Request) -> dict[str, Any]:
    """Every reporting machine: when it last reported and which skills it runs that the catalogue did not approve."""
    principal = current_principal(request)
    governance = current_governance(request)
    return {"hosts": guarded(lambda: governance.fleet_hosts(principal))}
