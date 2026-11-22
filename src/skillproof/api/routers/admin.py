"""Tenant administration: assurance policy, alert endpoints, alert history."""
from __future__ import annotations


from typing import Any

from fastapi import Request
from pydantic import BaseModel, Field

from skillproof.governance import AssurancePolicy
from skillproof.storage.notify import EVENTS

from fastapi import APIRouter
from skillproof.api.deps import current_governance, current_principal, guarded

router = APIRouter()


@router.get("/api/v1/policy")
def get_policy(request: Request) -> dict[str, Any]:
    """The tenant's assurance policy in force, and who last changed it."""
    principal = current_principal(request)
    governance = current_governance(request)
    stored = guarded(lambda: governance.stored_policy(principal))
    return {"tenant_id": principal.tenant_id, "policy": guarded(lambda: governance.tenant_policy(principal)).model_dump(),
            "source": "tenant" if stored else "default", "updated_by": (stored or {}).get("updated_by"),
            "updated_at": (stored or {}).get("updated_at")}


@router.put("/api/v1/policy")
def put_policy(policy: AssurancePolicy, request: Request) -> dict[str, Any]:
    """Set the tenant's assurance policy (tenant admins). New versions and re-assessments use it; every change is kept."""
    principal = current_principal(request)
    governance = current_governance(request)
    return {"tenant_id": principal.tenant_id, **guarded(lambda: governance.set_tenant_policy(principal, policy))}


class WebhookRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(min_length=1, max_length=len(EVENTS))


@router.get("/api/v1/webhooks")
def list_webhooks(request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    return {"events": list(EVENTS), "webhooks": guarded(lambda: governance.list_webhooks(principal))}


@router.post("/api/v1/webhooks")
def add_webhook(body: WebhookRequest, request: Request) -> dict[str, Any]:
    """Register an alert endpoint (tenant admins). The response carries its signing secret once; store it."""
    principal = current_principal(request)
    governance = current_governance(request)
    return guarded(lambda: governance.add_webhook(principal, body.url, body.events))


@router.delete("/api/v1/webhooks/{webhook_id}")
def delete_webhook(webhook_id: str, request: Request) -> dict[str, Any]:
    principal = current_principal(request)
    governance = current_governance(request)
    guarded(lambda: governance.remove_webhook(principal, webhook_id))
    return {"deleted": webhook_id}


@router.get("/api/v1/notifications")
def list_notifications(request: Request) -> dict[str, Any]:
    """Recent alerts and their delivery state."""
    principal = current_principal(request)
    governance = current_governance(request)
    return {"notifications": guarded(lambda: governance.list_notifications(principal))}
