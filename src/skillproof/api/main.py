"""The SkillProof API application: middleware (sign-in, request logs), background workers (evaluation jobs, alert
delivery) and the routers, one per area (api/routers)."""
from __future__ import annotations

import re
import threading
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from skillproof import __version__
from skillproof.logs import log
from skillproof.oidc import AuthenticationError, verifier_from_environment
from skillproof.services.evaluation import EvaluationSettings, start_worker
from skillproof.storage.notify import NotificationStore, start_deliverer
from skillproof.api.deps import governance_from_environment  # noqa: F401 - used by the service and workers


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    _start_background()
    yield
    _worker_stop.set()


app = FastAPI(title="SkillProof API", version=__version__, lifespan=_lifespan,
              description="OIDC-authenticated, role-protected skill evaluation and assurance APIs.")


app.state.oidc_verifier = verifier_from_environment()


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


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Outermost: a request id for every call (kept from X-Request-ID when it is a sane value), and one log line with
    method, path, status, duration, tenant and actor. Bodies, tokens and skill contents are never logged."""
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if re.fullmatch(r"[A-Za-z0-9._\-]{8,64}", incoming) else uuid.uuid4().hex
    request.state.request_id = request_id
    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        principal = getattr(request.state, "principal", None)
        log("request", request_id=request_id, method=request.method, path=request.url.path, status=status,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
            tenant=principal.tenant_id if principal else None,
            actor=principal.user_id if principal else request.headers.get("x-skillproof-dev-user"))


_worker_stop = threading.Event()


def _start_background() -> None:
    """Alert delivery always; evaluation jobs when SKILLPROOF_EVAL_MODEL is set (one at a time)."""
    if governance_from_environment() is None:
        return
    _worker_stop.clear()

    def notifications() -> NotificationStore | None:
        governance = governance_from_environment()
        return governance.notifications if governance else None

    start_deliverer(notifications, _worker_stop)
    settings = EvaluationSettings.from_env()
    if settings is not None:
        start_worker(governance_from_environment, settings, _worker_stop)


from skillproof.api.routers import admin, analysis, catalogue, evaluations, fleet, signals, system  # noqa: E402

for _router in (system.router, analysis.router, catalogue.router, evaluations.router, admin.router, fleet.router, signals.router):
    app.include_router(_router)
