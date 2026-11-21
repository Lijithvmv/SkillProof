"""Shared API dependencies: the caller's principal, the tenant's governance access, role checks, and the one
place typed errors become HTTP status (NotFound 404, other refusals 409, authorization 403)."""
from __future__ import annotations


import os
from pathlib import Path

from fastapi import HTTPException, Request

from skillproof.errors import NotFound, SkillProofError
from skillproof.approvals import SQLiteApprovalStore
from skillproof.authorization import AuthorizationError, GovernanceAccess, Principal
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SQLiteSkillRegistry
from skillproof.jobs import JobStore
from skillproof.notify import NotificationStore
from skillproof.fleet import FleetStore


def require_roles(*roles: str):
    async def dependency(request: Request) -> None:
        principal = getattr(request.state, "principal", None)
        if principal is not None and principal.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role for this operation.")
    return dependency


def current_governance(request: Request) -> GovernanceAccess:
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
        return GovernanceAccess(registry=SQLiteSkillRegistry(url), approvals=SQLiteApprovalStore(url),
                                history=EvaluationHistoryStore(url), jobs=JobStore(url), notifications=NotificationStore(url), fleet=FleetStore(url))
    data_dir = os.environ.get("SKILLPROOF_DATA_DIR", "").strip()
    if not data_dir:
        return None
    root = Path(data_dir)
    return GovernanceAccess(
        registry=SQLiteSkillRegistry(root / "registry.db"),
        approvals=SQLiteApprovalStore(root / "approvals.db"),
        history=EvaluationHistoryStore(root / "history.db"),
        jobs=JobStore(root / "jobs.db"),
        notifications=NotificationStore(root / "notify.db"),
        fleet=FleetStore(root / "fleet.db"),
    )


def current_principal(request: Request) -> Principal:
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


def guarded(call):
    try:
        return call()
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SkillProofError as exc:  # every other refusal: conflict with the current state or an invalid request
        raise HTTPException(status_code=409, detail=str(exc)) from exc
