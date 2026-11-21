from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from skillproof.analyzer import analyze_files
from skillproof.approvals import ApprovalError, SQLiteApprovalStore
from skillproof.authorization import AuthorizationError, GovernanceAccess, Principal
from skillproof.capabilities import build_manifest
from skillproof.history import EvaluationHistoryStore
from skillproof.ingestion import PackageError, read_skill_zip, read_skill_zip_bytes
from skillproof.registry import RegistryError, SQLiteSkillRegistry
from skillproof.evaluation import BenchmarkTask, ComparisonRequest, compare_runs, validate_benchmark_task
from skillproof.security import scan_security
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance
from skillproof.oidc import AuthenticationError, browser_login_config, verifier_from_environment
from skillproof.evidence import EvidenceError, measured_evidence
from skillproof.second_opinion import add_second_opinions

app = FastAPI(title="SkillProof API", version="1.7.0", description="OIDC-authenticated, role-protected skill evaluation and assurance APIs.")
app.state.oidc_verifier = verifier_from_environment()
CATALOGUE_PAGE = Path(__file__).resolve().parent.parent / "web" / "catalogue.html"


def require_roles(*roles: str):
    async def dependency(request: Request) -> None:
        principal = getattr(request.state, "principal", None)
        if principal is not None and principal.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this operation.")
    return dependency


@app.middleware("http")
async def authenticate_api_requests(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.url.path != "/api/v1/auth/config":
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
    """Liveness: the process answers."""
    return {"status": "ok", "version": "1.7.0"}


@app.get("/health/ready")
def health_ready(request: Request) -> JSONResponse:
    """Readiness: storage is configured and answers a query. 503 otherwise, so a supervisor or balancer can tell."""
    try:
        governance = getattr(request.app.state, "governance", None) or governance_from_environment()
        if governance is None:
            return JSONResponse({"status": "not_ready", "reason": "storage is not configured"}, status_code=503)
        request.app.state.governance = governance
        for store in (governance.registry, governance.approvals, governance.history):
            with store.db.transaction(None) as db:
                db.execute("SELECT 1").fetchone()
        backend = governance.registry.db.dialect
    except Exception as exc:  # any storage failure means not ready
        return JSONResponse({"status": "not_ready", "reason": type(exc).__name__}, status_code=503)
    return JSONResponse({"status": "ready", "storage": backend, "auth": "oidc" if request.app.state.oidc_verifier else "local"})


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


# ------------------------------------------------------------------------------------------- skill registry
# The catalogue: upload a skill version, see what it adds over the active version, send it for approval, and promote
# it only after a different person approves (and acknowledges any block-level capability change).

def _governance(request: Request) -> GovernanceAccess:
    governance = getattr(request.app.state, "governance", None)
    if governance is None:
        governance = governance_from_environment()
        if governance is None:
            raise HTTPException(status_code=503, detail="Registry storage is not configured "
                                                        "(set SKILLPROOF_DATABASE_URL or SKILLPROOF_DATA_DIR).")
        request.app.state.governance = governance
    return governance


def governance_from_environment() -> GovernanceAccess | None:
    """PostgreSQL when SKILLPROOF_DATABASE_URL is set (one database, tenant row-level security), else SQLite files in
    SKILLPROOF_DATA_DIR. None when neither is set."""
    url = os.environ.get("SKILLPROOF_DATABASE_URL", "").strip()
    if url:
        return GovernanceAccess(registry=SQLiteSkillRegistry(url), approvals=SQLiteApprovalStore(url), history=EvaluationHistoryStore(url))
    data_dir = os.environ.get("SKILLPROOF_DATA_DIR", "").strip()
    if not data_dir:
        return None
    root = Path(data_dir)
    return GovernanceAccess(
        registry=SQLiteSkillRegistry(root / "registry.db"),
        approvals=SQLiteApprovalStore(root / "approvals.db"),
        history=EvaluationHistoryStore(root / "history.db"),
    )


def _principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is not None:
        return principal
    if request.app.state.oidc_verifier is not None or os.environ.get("SKILLPROOF_ENV", "").lower() == "production":
        raise HTTPException(status_code=401, detail="Authenticated principal required.")
    # Local development only (OIDC off): one tenant, identity from headers so the two-person rule can be exercised.
    try:
        return Principal(
            user_id=request.headers.get("x-skillproof-dev-user", "local-dev"),
            tenant_id="local",
            role=request.headers.get("x-skillproof-dev-role", "tenant_admin"),  # type: ignore[arg-type]
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _guarded(call):
    try:
        return call()
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except (RegistryError, ApprovalError) as exc:
        status = 404 if "not found" in str(exc) else 409
        raise HTTPException(status_code=status, detail=str(exc)) from exc


class BehaviouralEvidence(BaseModel):
    """Evidence only a run can produce. Static scores always come from SkillProof's own analysis of the upload."""
    behavioral_lift_pp: float | None = Field(default=None, ge=-100, le=10000)
    paired_runs: int | None = Field(default=None, ge=0)
    measured_models: int | None = Field(default=None, ge=0)
    cost_overhead_percent: float | None = Field(default=None, ge=-100, le=100000)


@app.post("/api/v1/registry/versions")
async def register_version(
    request: Request,
    file: UploadFile = File(...),
    evidence_json: str | None = Form(default=None),
    artifact_uri: str | None = Form(default=None),
    experiment_ids: str | None = Form(default=None, description="Comma-separated ids of recorded experiments that ran this SKILL.md."),
) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Upload a .zip skill package.")
    data = await file.read(10_000_001)
    if len(data) > 10_000_000:
        raise HTTPException(status_code=413, detail="ZIP upload exceeds 10 MB.")
    try:
        raw = read_skill_zip_bytes(data)
        behaviour = BehaviouralEvidence(**json.loads(evidence_json)) if evidence_json else BehaviouralEvidence()
    except PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=f"evidence_json is invalid: {exc}") from exc
    text = {}
    for path, content in raw.items():
        try:
            text[path] = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            text[path] = ""
    report = analyze_files(text)
    if report.get("package_fingerprint") is None or not (report.get("metadata") or {}).get("name"):
        raise HTTPException(status_code=422, detail="The package needs a SKILL.md with a name to be registered.")
    try:
        manifest = build_manifest(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    add_second_opinions(manifest, raw)
    security = report.get("security") or {}
    cited = [e.strip() for e in (experiment_ids or "").split(",") if e.strip()]
    if cited and evidence_json:
        raise HTTPException(status_code=422, detail="Cite experiments or declare evidence, not both.")
    behaviour_fields = behaviour.model_dump()
    provenance: dict[str, Any] = {"source": "declared_by_uploader"} if evidence_json else {"source": "none"}
    if cited:
        records = _guarded(lambda: governance.list_evaluations(principal, skill_key=report["metadata"]["name"], limit=500))
        try:
            skill_md = min((p for p in text if p.rsplit("/", 1)[-1] == "SKILL.md"), key=len, default=None)
            measured = measured_evidence(records, cited, text.get(skill_md, "") if skill_md else "")
        except EvidenceError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        provenance = measured.pop("provenance")
        behaviour_fields = measured
    evidence = AssuranceInput(
        structural_score=report.get("structural_score"),
        instruction_quality_score=(report.get("instruction_quality") or {}).get("quality_score"),
        security_score=security.get("security_score"),
        security_findings=[{"code": f["code"], "severity": f["severity"]} for f in security.get("findings", [])],
        **behaviour_fields,
    )
    assurance_report = evaluate_assurance(evidence, AssurancePolicy())
    assurance_report["evidence"] = provenance
    # Bind the report to this exact package so an approval of one version can never promote another.
    assurance_report["subject"] = {"tenant_id": principal.tenant_id, "skill_name": report["metadata"]["name"],
                                   "package_fingerprint": report["package_fingerprint"]}
    version = _guarded(lambda: governance.register_skill(
        principal, report, assurance_report, artifact_uri=artifact_uri, capability_manifest=manifest))
    return {"version": version, "analysis": report}


@app.get("/api/v1/registry/catalogue")
def registry_catalogue(request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return {"tenant_id": principal.tenant_id, "skills": _guarded(lambda: governance.catalogue(principal))}


@app.get("/api/v1/registry/skills/{skill_name}/versions")
def registry_skill_versions(skill_name: str, request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return {"skill_name": skill_name, "versions": _guarded(lambda: governance.list_skill_versions(principal, skill_name))}


@app.get("/api/v1/registry/versions/{version_id}")
def registry_version(version_id: str, request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return _guarded(lambda: governance.get_skill(principal, version_id))


@app.post("/api/v1/registry/versions/{version_id}/approval-requests")
def registry_request_approval(version_id: str, request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return _guarded(lambda: governance.submit_version_for_approval(principal, version_id))


@app.get("/api/v1/registry/versions/{version_id}/approval-requests")
def registry_version_approvals(version_id: str, request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return {"version_id": version_id, "requests": _guarded(lambda: governance.version_approvals(principal, version_id))}


@app.get("/api/v1/whoami")
def whoami(request: Request) -> dict[str, Any]:
    principal = _principal(request)
    return {"user_id": principal.user_id, "tenant_id": principal.tenant_id, "role": principal.role,
            "dev_identity": getattr(request.state, "principal", None) is None}


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/catalogue")


@app.get("/catalogue", response_class=HTMLResponse, include_in_schema=False)
def catalogue_page() -> HTMLResponse:
    return HTMLResponse(CATALOGUE_PAGE.read_text(encoding="utf-8"))


class DecisionRequest(BaseModel):
    action: Literal["approve", "reject", "request_changes"]
    comment: str = Field(default="", max_length=4000)


@app.post("/api/v1/approvals/{request_id}/decision")
def approval_decision(request_id: str, body: DecisionRequest, request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return _guarded(lambda: governance.decide_approval(principal, request_id, body.action, comment=body.comment))


class PromoteRequest(BaseModel):
    approval_request_id: str = Field(min_length=1, max_length=64)
    capability_ack: str | None = Field(default=None, max_length=64,
                                       description="change_hash of the capability change, required when it has block-level items.")


@app.post("/api/v1/registry/versions/{version_id}/promote")
def registry_promote(version_id: str, body: PromoteRequest, request: Request) -> dict[str, Any]:
    principal = _principal(request)
    governance = _governance(request)
    return _guarded(lambda: governance.promote_version(
        principal, version_id, body.approval_request_id, capability_ack=body.capability_ack))


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=500)


@app.post("/api/v1/registry/skills/{skill_name}/rollback")
def registry_rollback(skill_name: str, body: RollbackRequest, request: Request) -> dict[str, Any]:
    """Make the last approved version of a skill active again, with the reason in the audit trail."""
    principal = _principal(request)
    governance = _governance(request)
    return _guarded(lambda: governance.rollback_skill(principal, skill_name, body.reason))


class FalseAlarmRequest(BaseModel):
    category: str = Field(min_length=1, max_length=64)
    value: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=500)


@app.post("/api/v1/registry/versions/{version_id}/false-alarms")
def registry_mark_false_alarm(version_id: str, body: FalseAlarmRequest, request: Request) -> dict[str, Any]:
    """A reviewer marks one raised item as not a real capability; the same evidence is not raised again."""
    principal = _principal(request)
    governance = _governance(request)
    return _guarded(lambda: governance.mark_false_alarm(principal, version_id, body.category, body.value, body.reason))


@app.get("/api/v1/registry/false-alarms")
def registry_false_alarms(request: Request) -> dict[str, Any]:
    """Every reviewer mark in the tenant as labelled items (verdict F), the feed for tuning the engine."""
    principal = _principal(request)
    governance = _governance(request)
    return {"tenant_id": principal.tenant_id, "labels": _guarded(lambda: governance.false_alarm_labels(principal))}


@app.get("/api/v1/auth/config")
def auth_config(request: Request) -> dict[str, Any]:
    """Public: how the page signs a person in (authorization code + PKCE), or that this server runs with local identity."""
    if request.app.state.oidc_verifier is None:
        return {"mode": "local"}
    return browser_login_config()


class ExperimentRecord(BaseModel):
    skill_name: str = Field(min_length=1, max_length=200)
    report: dict[str, Any] = Field(description="An execute_experiment() result; only its summary metrics are stored.")


@app.get("/api/v1/evaluations/experiments")
def list_experiments(skill_name: str, request: Request) -> dict[str, Any]:
    """Recorded runs of a skill in this tenant: lift, adherence per claim, models and cost, newest first."""
    principal = _principal(request)
    governance = _governance(request)
    rows = _guarded(lambda: governance.list_evaluations(principal, skill_key=skill_name, limit=100))
    return {"skill_name": skill_name, "experiments": [
        {"experiment_id": r["experiment_id"], "instructions_fingerprint": r["instructions_fingerprint"], "created_at": r["created_at"],
         "lift_pp": (r["summary"].get("comparison") or {}).get("skill_lift_percentage_points"),
         "interpretation": (r["summary"].get("comparison") or {}).get("interpretation"),
         "paired_by_task": (r["summary"].get("comparison") or {}).get("paired_by_task"),
         "adherence": (r["summary"].get("comparison") or {}).get("adherence"),
         "models": [m.get("model") for m in (r["summary"].get("model_compatibility") or {}).get("models", [])]} for r in rows]}


@app.post("/api/v1/evaluations/experiments", dependencies=[Depends(require_roles("tenant_admin", "evaluator"))])
async def record_experiment(body: ExperimentRecord, request: Request) -> dict[str, Any]:
    """Store an experiment's metrics in the tenant's history for a skill, so catalogue versions can cite it by id."""
    principal = _principal(request)
    governance = _governance(request)
    try:
        stored = _guarded(lambda: governance.record_evaluation(principal, body.report, skill_key=body.skill_name))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"experiment_id": stored["experiment_id"], "instructions_fingerprint": stored["instructions_fingerprint"],
            "skill_name": body.skill_name, "lift_pp": (stored["summary"].get("comparison") or {}).get("skill_lift_percentage_points")}
