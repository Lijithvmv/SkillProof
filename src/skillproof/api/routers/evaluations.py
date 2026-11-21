"""Run evidence: evaluation jobs for a version, and recorded experiments."""
from __future__ import annotations


import re
from pathlib import Path
from typing import Any

from fastapi import Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field

from skillproof import package
from skillproof.ingestion import PackageError

from fastapi import APIRouter
from skillproof.api.deps import current_governance, current_principal, guarded, require_roles

router = APIRouter()


@router.post("/api/v1/registry/versions/{version_id}/evaluate")
async def registry_evaluate(version_id: str, request: Request, file: UploadFile | None = File(default=None)) -> dict[str, Any]:
    """Queue a run-evidence job for a version. The SKILL.md comes from the uploaded ZIP of this exact version, or from
    the installed folder the version was imported from; either must match the version's package fingerprint."""
    principal = current_principal(request)
    governance = current_governance(request)
    version = guarded(lambda: governance.get_skill(principal, version_id))
    if file is not None:
        data = await file.read(10_000_001)
        if len(data) > 10_000_000:
            raise HTTPException(status_code=413, detail="ZIP upload exceeds 10 MB.")
        try:
            raw = package.read_zip(data)
        except PackageError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if package.fingerprint(raw) != version["package_fingerprint"]:
            raise HTTPException(status_code=409, detail="The uploaded package is not this version.")
        skill_md = package.skill_md(package.as_text(raw))
    else:
        skill_md = _installed_skill_md(version)
    return guarded(lambda: governance.request_evaluation(principal, version_id, skill_md))


def _installed_skill_md(version: dict[str, Any]) -> str:
    """SKILL.md of an imported version, read from its folder after checking the folder is still that version."""
    from urllib.parse import unquote, urlparse

    uri = version.get("artifact_uri") or ""
    if not uri.startswith("file:"):
        raise HTTPException(status_code=422, detail="Upload this version's ZIP to evaluate it (no local folder is known).")
    path = unquote(urlparse(uri).path)
    folder = Path(path[1:] if re.match(r"^/[A-Za-z]:", path) else path)
    try:
        files, oversize = package.read_folder(folder)
    except (OSError, PackageError) as exc:
        raise HTTPException(status_code=422, detail=f"The installed folder cannot be read: {exc}") from exc
    if package.fingerprint(files, oversize) != version["package_fingerprint"]:
        raise HTTPException(status_code=409, detail="The installed folder has changed since this version was registered.")
    return package.skill_md(package.as_text(files))


@router.get("/api/v1/registry/versions/{version_id}/jobs")
def registry_version_jobs(version_id: str, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return {"version_id": version_id, "jobs": guarded(lambda: governance.version_jobs(principal, version_id))}


class ExperimentRecord(BaseModel):
    skill_name: str = Field(min_length=1, max_length=200)
    report: dict[str, Any] = Field(description="An execute_experiment() result; only its summary metrics are stored.")


@router.get("/api/v1/evaluations/experiments")
def list_experiments(skill_name: str, request: Request) -> dict[str, Any]:
    """Recorded runs of a skill in this tenant: lift, adherence per claim, models and cost, newest first."""
    principal = current_principal(request)
    governance = current_governance(request)
    rows = guarded(lambda: governance.list_evaluations(principal, skill_key=skill_name, limit=100))
    return {"skill_name": skill_name, "experiments": [
        {"experiment_id": r["experiment_id"], "instructions_fingerprint": r["instructions_fingerprint"], "created_at": r["created_at"],
         "lift_pp": (r["summary"].get("comparison") or {}).get("skill_lift_percentage_points"),
         "interpretation": (r["summary"].get("comparison") or {}).get("interpretation"),
         "paired_by_task": (r["summary"].get("comparison") or {}).get("paired_by_task"),
         "adherence": (r["summary"].get("comparison") or {}).get("adherence"),
         "models": [m.get("model") for m in (r["summary"].get("model_compatibility") or {}).get("models", [])]} for r in rows]}


@router.post("/api/v1/evaluations/experiments", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
async def record_experiment(body: ExperimentRecord, request: Request) -> dict[str, Any]:
    """Store an experiment's metrics in the tenant's history for a skill, so catalogue versions can cite it by id."""
    principal = current_principal(request)
    governance = current_governance(request)
    try:
        stored = guarded(lambda: governance.record_evaluation(principal, body.report, skill_key=body.skill_name))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"experiment_id": stored["experiment_id"], "instructions_fingerprint": stored["instructions_fingerprint"],
            "skill_name": body.skill_name, "lift_pp": (stored["summary"].get("comparison") or {}).get("skill_lift_percentage_points")}
