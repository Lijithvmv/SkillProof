"""Signals from real use: usage counts from agents' hooks, and papercuts agents file when a skill gives them trouble."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from skillproof.api.deps import current_governance, current_principal, guarded

router = APIRouter()


class UsageRow(BaseModel):
    skill_name: str = Field(min_length=1, max_length=200)
    fingerprint: str = Field(default="", max_length=64)
    day: str = Field(min_length=10, max_length=10)
    trigger: Literal["agent", "user"]
    count: int = Field(ge=1, le=100_000)


class UsageReport(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    events: list[UsageRow] = Field(max_length=5000)


class Papercut(BaseModel):
    skill_name: str = Field(min_length=1, max_length=200)
    fingerprint: str = Field(default="", max_length=64)
    tried: str = Field(min_length=1, max_length=2000)
    expected: str = Field(min_length=1, max_length=2000)
    happened: str = Field(min_length=1, max_length=2000)
    suggested_fix: str = Field(default="", max_length=2000)
    host: str = Field(default="", max_length=253)


class Resolution(BaseModel):
    resolution: str = Field(min_length=1, max_length=2000)


@router.post("/api/v1/signals/usage")
def report_usage(body: UsageReport, request: Request) -> dict[str, Any]:
    """Daily skill-run counts from one machine (names, fingerprints and counts only; no prompts or contents)."""
    principal, governance = current_principal(request), current_governance(request)
    return guarded(lambda: governance.record_usage(principal, body.host, [e.model_dump() for e in body.events]))


@router.post("/api/v1/signals/papercuts")
def file_papercut(body: Papercut, request: Request) -> dict[str, Any]:
    """An agent reports friction with a skill: what it tried, what it expected, what happened, what would fix it."""
    principal, governance = current_principal(request), current_governance(request)
    return guarded(lambda: governance.file_papercut(principal, body.model_dump()))


@router.post("/api/v1/signals/papercuts/{papercut_id}/resolve")
def resolve_papercut(papercut_id: str, body: Resolution, request: Request) -> dict[str, Any]:
    """The skill's owner closes a papercut with what was fixed."""
    principal, governance = current_principal(request), current_governance(request)
    return guarded(lambda: governance.resolve_papercut(principal, papercut_id, body.resolution))


@router.get("/api/v1/signals")
def signals_summary(request: Request, days: int = 30) -> dict[str, Any]:
    """Every skill with use or papercuts in the tenant, most used first."""
    principal, governance = current_principal(request), current_governance(request)
    return {"days": days, "skills": guarded(lambda: governance.signals_summary(principal, max(1, min(days, 400))))}


@router.get("/api/v1/signals/skills/{skill_name}")
def skill_signals(skill_name: str, request: Request, days: int = 30) -> dict[str, Any]:
    """One skill's use by day, trigger, version and machine count, and its papercuts (open first)."""
    principal, governance = current_principal(request), current_governance(request)
    return guarded(lambda: governance.skill_signals(principal, skill_name, max(1, min(days, 400))))
