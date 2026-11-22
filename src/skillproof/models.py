"""The shapes that cross service boundaries, typed. Stores return them, services pass them on, the API serialises them
as JSON unchanged. They are TypedDicts, so the JSON contract and the type checker describe the same keys."""
from __future__ import annotations

from typing import Any, Literal, TypedDict

Level = Literal["block", "ask", "note"]
Decision = Literal["none", "note", "ask", "block"]
VersionState = Literal["pending_review", "not_eligible", "active", "superseded"]
AssuranceDecision = Literal["blocked", "not_ready", "insufficient_evidence", "human_review_required", "eligible_for_human_approval"]
JobState = Literal["queued", "running", "done", "failed"]


class ChangeItem(TypedDict, total=False):
    category: str
    value: str
    level: Level
    score: float
    rarity_bits: float | None
    reasons: list[str]
    locations: list[str]
    block: str
    confidence: dict[str, Any]
    widened: dict[str, str]
    second_opinion: str


class CapabilityChange(TypedDict, total=False):
    """What a version adds over the version it is compared with, ranked; change_hash binds an acknowledgement."""
    against: str  # active_version, active_version_without_manifest, previous_version_not_approved, nothing_active,
    #               or full_review_not_human_written (compared with nothing; against_version_id is the version it updates)
    against_version_id: str | None
    status: str
    decision: Decision
    counts: dict[str, int]
    items: list[ChangeItem]
    items_total: int
    dismissed: list[dict[str, Any]]
    combinations: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    removed: dict[str, list[str]]
    meaning: str
    change_hash: str
    update_over_previous: dict[str, Any]  # with full review: what the update itself added over the version before


class Gate(TypedDict):
    code: str
    status: str
    message: str


class AssuranceReport(TypedDict, total=False):
    """A version's assurance: gates and decision, the static inputs and policy it was judged on, where its run evidence
    came from, and the exact package it is about."""
    assurance_version: str
    policy_id: str
    decision: AssuranceDecision
    gates: list[Gate]
    automatic_certification: Literal[False]
    limitations: str
    inputs: dict[str, Any]
    policy: dict[str, Any]
    evidence: dict[str, Any]
    subject: dict[str, str]
    observed_behaviour: dict[str, Any]  # what cited sandboxed runs showed the skill makes agents do
    authorship: dict[str, str]  # author kind and review bar (skillproof.provenance), bound into the approval hash


class AuditEvent(TypedDict):
    actor_id: str
    action: str
    detail: str
    occurred_at: str


class SkillVersion(TypedDict, total=False):
    version_id: str
    tenant_id: str
    skill_name: str
    package_fingerprint: str
    assurance_hash: str
    artifact_uri: str | None
    state: VersionState
    registered_by: str
    created_at: str
    updated_at: str
    summary: dict[str, Any]
    assurance: AssuranceReport | None
    capabilities: dict[str, Any] | None
    capability_change: CapabilityChange | None
    events: list[AuditEvent]
    provenance: dict[str, Any] | None  # who wrote it and the review bar that follows (skillproof.provenance)
    distributable: bool              # its exact package is stored and can be installed by sync
    not_distributable_reason: str


class EvaluationJob(TypedDict, total=False):
    job_id: str
    tenant_id: str
    version_id: str
    skill_name: str
    state: JobState
    requested_by: str
    error: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    result: dict[str, Any] | None
    payload: dict[str, Any]


class FleetEntry(TypedDict, total=False):
    skill_name: str
    installed_fingerprint: str
    status: Literal["approved", "running_unapproved", "never_approved"]
    approved_version_id: str | None
    installed_version_id: str | None
    adds_over_approved: dict[str, Any]


class FleetReportResult(TypedDict):
    host: str
    reported_at: str
    counts: dict[str, int]
    newly_unapproved: list[FleetEntry]
