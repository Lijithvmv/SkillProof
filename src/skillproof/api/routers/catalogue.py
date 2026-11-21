"""The catalogue: register versions, compare, approval requests and decisions, promote, roll back, false-alarm marks."""
from __future__ import annotations


import json
from typing import Any, Literal

from fastapi import File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from skillproof import package
from skillproof.services import catalogue
from skillproof.ingestion import PackageError
from skillproof.evidence import EvidenceError

from fastapi import APIRouter
from skillproof.api.deps import current_governance, current_principal, guarded

router = APIRouter()


class BehaviouralEvidence(BaseModel):
    """Evidence only a run can produce. Static scores always come from SkillProof's own analysis of the upload."""
    behavioral_lift_pp: float | None = Field(default=None, ge=-100, le=10000)
    paired_runs: int | None = Field(default=None, ge=0)
    measured_models: int | None = Field(default=None, ge=0)
    cost_overhead_percent: float | None = Field(default=None, ge=-100, le=100000)


@router.post("/api/v1/registry/versions")
async def register_version(
    request: Request,
    file: UploadFile = File(...),
    evidence_json: str | None = Form(default=None),
    artifact_uri: str | None = Form(default=None),
    experiment_ids: str | None = Form(default=None, description="Comma-separated ids of recorded experiments that ran this SKILL.md."),
    evaluate: bool = Form(default=False, description="Queue a run-evidence job for this version (server runs evaluations)."),
) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip skill package.")
    data = await file.read(10_000_001)
    if len(data) > 10_000_000:
        raise HTTPException(status_code=413, detail="ZIP upload exceeds 10 MB.")
    try:
        raw = package.read_zip(data)
        declared = BehaviouralEvidence(**json.loads(evidence_json)).model_dump() if evidence_json else None
    except PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"evidence_json is invalid: {exc}") from exc
    cited = [e.strip() for e in (experiment_ids or "").split(",") if e.strip()]
    if cited and evidence_json:
        raise HTTPException(status_code=422, detail="Cite experiments or declare evidence, not both.")
    try:
        assessment = guarded(lambda: catalogue.assess_package(governance, principal, raw, declared=declared, cite=cited,
                                                               folder=package.zip_folder(data)))
    except EvidenceError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:  # no SKILL.md name, or a package the engine cannot read
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    version = guarded(lambda: catalogue.register(governance, principal, assessment, artifact_uri=artifact_uri))
    result = {"version": version, "analysis": assessment.report}
    if evaluate:
        result["job"] = guarded(lambda: governance.request_evaluation(principal, version["version_id"], assessment.skill_md))
    return result


@router.get("/api/v1/registry/catalogue")
def registry_catalogue(request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return {"tenant_id": principal.tenant_id, "skills": guarded(lambda: governance.catalogue(principal))}


@router.get("/api/v1/registry/skills/{skill_name}/versions")
def registry_skill_versions(skill_name: str, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return {"skill_name": skill_name, "versions": guarded(lambda: governance.list_skill_versions(principal, skill_name))}


@router.get("/api/v1/registry/versions/{version_id}")
def registry_version(version_id: str, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.get_skill(principal, version_id))


@router.post("/api/v1/registry/versions/{version_id}/approval-requests")
def registry_request_approval(version_id: str, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.submit_version_for_approval(principal, version_id))


@router.get("/api/v1/registry/versions/{version_id}/approval-requests")
def registry_version_approvals(version_id: str, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return {"version_id": version_id, "requests": guarded(lambda: governance.version_approvals(principal, version_id))}


class DecisionRequest(BaseModel):
    action: Literal["approve", "reject", "request_changes"]
    comment: str = Field(default="", max_length=4000)


@router.post("/api/v1/approvals/{request_id}/decision")
def approval_decision(request_id: str, body: DecisionRequest, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.decide_approval(principal, request_id, body.action, comment=body.comment))


class PromoteRequest(BaseModel):
    approval_request_id: str = Field(min_length=1, max_length=64)
    capability_ack: str | None = Field(default=None, max_length=64,
                                       description="change_hash of the capability change, required when it has block-level items.")


@router.post("/api/v1/registry/versions/{version_id}/promote")
def registry_promote(version_id: str, body: PromoteRequest, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.promote_version(
        principal, version_id, body.approval_request_id, capability_ack=body.capability_ack))


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


@router.post("/api/v1/registry/skills/{skill_name}/rollback")
def registry_rollback(skill_name: str, body: RollbackRequest, request: Request) -> dict[str, Any]:
    """Make the last approved version of a skill active again, with the reason in the audit trail."""
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.rollback_skill(principal, skill_name, body.reason))


class FalseAlarmRequest(BaseModel):
    category: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=500)


@router.post("/api/v1/registry/versions/{version_id}/false-alarms")
def registry_mark_false_alarm(version_id: str, body: FalseAlarmRequest, request: Request) -> dict[str, Any]:
    """A reviewer marks one raised item as not a real capability; the same evidence is not raised again."""
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.mark_false_alarm(principal, version_id, body.category, body.value, body.reason))


@router.get("/api/v1/registry/false-alarms")
def registry_false_alarms(request: Request) -> dict[str, Any]:
    """Every reviewer mark in the tenant as labelled items (verdict F), the feed for tuning the engine."""
    principal = current_principal(request)
    governance = current_governance(request)
    return {"tenant_id": principal.tenant_id, "labels": guarded(lambda: governance.false_alarm_labels(principal))}
