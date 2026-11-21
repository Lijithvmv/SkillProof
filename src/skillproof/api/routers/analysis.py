"""Stateless analysis endpoints: package analysis, security scan, task validation, run comparison, assurance."""
from __future__ import annotations


from typing import Any

from fastapi import Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from skillproof.analyzer import analyze_files
from skillproof.ingestion import PackageError, read_skill_zip
from skillproof.evaluation import BenchmarkTask, ComparisonRequest, compare_runs, validate_benchmark_task
from skillproof.security import scan_security
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance

from fastapi import APIRouter
from skillproof.api.deps import require_roles

router = APIRouter()


class AnalyzeRequest(BaseModel):
    files: dict[str, str] = Field(description="Relative file paths mapped to UTF-8 text content.")


@router.post("/api/v1/skills/analyze", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    return analyze_files(request.files)


@router.post("/api/v1/skills/security", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def security_scan(request: AnalyzeRequest) -> dict[str, Any]:
    return scan_security(request.files)


class ValidateTaskRequest(BaseModel):
    skill_instructions: str = Field(max_length=100_000)
    task: BenchmarkTask


@router.post("/api/v1/evaluations/tasks/validate", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def validate_task(request: ValidateTaskRequest) -> dict[str, Any]:
    return validate_benchmark_task(request.skill_instructions, request.task)


@router.post("/api/v1/evaluations/compare", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def compare(request: ComparisonRequest) -> dict[str, Any]:
    return compare_runs(request)


class AssuranceRequest(BaseModel):
    evidence: AssuranceInput
    policy: AssurancePolicy = Field(default_factory=AssurancePolicy)


@router.post("/api/v1/evaluations/assurance", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def assurance(request: AssuranceRequest) -> dict[str, Any]:
    return evaluate_assurance(request.evidence, request.policy)


@router.post("/api/v1/skills/intelligence", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
async def intelligence(file: UploadFile = File(...)) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip skill package.")
    data = await file.read(10_000_001)
    if len(data) > 10_000_000:
        raise HTTPException(status_code=413, detail="ZIP upload exceeds 10 MB.")
    try:
        files = read_skill_zip(data)
    except PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return analyze_files(files)


# ------------------------------------------------------------------------------------------- skill registry
# The catalogue: upload a skill version, see what it adds over the active version, send it for approval, and promote
# it only after a different person approves (and acknowledges any block-level capability change).
