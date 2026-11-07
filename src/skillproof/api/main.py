from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from skillproof.analyzer import analyze_files
from skillproof.ingestion import PackageError, read_skill_zip
from skillproof.evaluation import BenchmarkTask, ComparisonRequest, compare_runs, validate_benchmark_task
from skillproof.security import scan_security
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance
from skillproof.oidc import AuthenticationError, verifier_from_environment

app = FastAPI(title="SkillProof API", version="1.7.0", description="OIDC-authenticated, role-protected skill evaluation and assurance APIs.")
app.state.oidc_verifier = verifier_from_environment()


def require_roles(*roles: str):
    async def dependency(request: Request) -> None:
        principal = getattr(request.state, "principal", None)
        if principal is not None and principal.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this operation.")
    return dependency


@app.middleware("http")
async def authenticate_api_requests(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        verifier = request.app.state.oidc_verifier
        request.state.principal = None
        if verifier is not None:
            authorization = request.headers.get("authorization", "")
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                return JSONResponse({"detail": "Bearer access token required."}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
            try:
                request.state.principal = await run_in_threadpool(verifier.verify, token.strip())
            except AuthenticationError:
                return JSONResponse({"detail": "Invalid access token."}, status_code=401, headers={"WWW-Authenticate": "Bearer error=\"invalid_token\""})
    return await call_next(request)


class AnalyzeRequest(BaseModel):
    files: dict[str, str] = Field(description="Relative file paths mapped to UTF-8 text content.")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "1.7.0"}


@app.post("/api/v1/skills/analyze", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def analyze(request: AnalyzeRequest) -> dict[str, Any]:
    return analyze_files(request.files)


@app.post("/api/v1/skills/security", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def security_scan(request: AnalyzeRequest) -> dict[str, Any]:
    return scan_security(request.files)


class ValidateTaskRequest(BaseModel):
    skill_instructions: str = Field(max_length=100_000)
    task: BenchmarkTask


@app.post("/api/v1/evaluations/tasks/validate", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def validate_task(request: ValidateTaskRequest) -> dict[str, Any]:
    return validate_benchmark_task(request.skill_instructions, request.task)


@app.post("/api/v1/evaluations/compare", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def compare(request: ComparisonRequest) -> dict[str, Any]:
    return compare_runs(request)


class AssuranceRequest(BaseModel):
    evidence: AssuranceInput
    policy: AssurancePolicy = Field(default_factory=AssurancePolicy)


@app.post("/api/v1/evaluations/assurance", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
def assurance(request: AssuranceRequest) -> dict[str, Any]:
    return evaluate_assurance(request.evidence, request.policy)


@app.post("/api/v1/skills/intelligence", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
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
