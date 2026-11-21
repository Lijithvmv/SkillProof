"""Health, identity, sign-in configuration and the catalogue page."""
from __future__ import annotations


from pathlib import Path
from typing import Any

from fastapi import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

from skillproof import __version__
from skillproof.oidc import browser_login_config

from fastapi import APIRouter
from skillproof.api.deps import current_principal, governance_from_environment

router = APIRouter()


CATALOGUE_PAGE = Path(__file__).resolve().parents[2] / "web" / "catalogue.html"


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process answers."""
    return {"status": "ok", "version": __version__}


@router.get("/health/ready")
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


@router.get("/api/v1/whoami")
def whoami(request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    return {"user_id": principal.user_id, "tenant_id": principal.tenant_id, "role": principal.role,
            "dev_identity": getattr(request.state, "principal", None) is None}


@router.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/catalogue")


@router.get("/catalogue", response_class=HTMLResponse, include_in_schema=False)
def catalogue_page() -> HTMLResponse:
    return HTMLResponse(CATALOGUE_PAGE.read_text(encoding="utf-8"))


@router.get("/api/v1/auth/config")
def auth_config(request: Request) -> dict[str, Any]:
    """Public: how the page signs a person in (authorization code + PKCE), or that this server runs with local identity."""
    if request.app.state.oidc_verifier is None:
        return {"mode": "local"}
    return browser_login_config()
