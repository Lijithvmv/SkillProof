"""Tenant-aware RBAC boundary for embedding applications."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from skillproof.storage.approvals import ApprovalAction, SQLiteApprovalStore
from skillproof.storage.history import EvaluationHistoryStore
from skillproof.governance import AssurancePolicy
from skillproof.models import CapabilityChange, EvaluationJob, FleetEntry, FleetReportResult, SkillVersion
from skillproof.storage.registry import SQLiteSkillRegistry

if TYPE_CHECKING:
    from skillproof.storage.artifacts import ArtifactStore
    from skillproof.storage.fleet import FleetStore
    from skillproof.storage.jobs import JobStore
    from skillproof.storage.notify import NotificationStore


Role = Literal["tenant_admin", "evaluator", "approver", "viewer", "reporter"]
Permission = Literal[
    "skill.read", "skill.register", "skill.promote", "fleet.report",
    "evaluation.read", "evaluation.run", "approval.submit", "approval.decide", "policy.manage",
]

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    "tenant_admin": frozenset({"skill.read", "skill.register", "skill.promote", "evaluation.read", "evaluation.run", "approval.submit", "approval.decide", "policy.manage", "fleet.report"}),
    "evaluator": frozenset({"skill.read", "skill.register", "evaluation.read", "evaluation.run", "approval.submit"}),
    "approver": frozenset({"skill.read", "skill.promote", "evaluation.read", "approval.decide"}),
    "viewer": frozenset({"skill.read", "evaluation.read"}),
    # A machine that reports which skills it runs: nothing else.
    "reporter": frozenset({"skill.read", "fleet.report"}),
}


class AuthorizationError(PermissionError):
    """Principal is outside the requested tenant or lacks the required role."""


ActorKind = Literal["human", "agent"]
# What only a person may do, whatever role an agent identity is given: decide, make live, dismiss what was raised,
# change the rules.
HUMAN_ONLY: frozenset[Permission] = frozenset({"approval.decide", "skill.promote", "policy.manage"})


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    role: Role
    actor_kind: ActorKind = "human"   # 'agent' for an agent identity (a token with a delegation `act` claim)
    on_behalf_of: str | None = None   # the person an agent identity acts for
    identity_source: str = "local"    # 'oidc' for a verified access token, 'local' for development sign-in
    signed_in_at: int | None = None   # the token's auth_time: when the person last signed in interactively (epoch s)

    def __post_init__(self) -> None:
        if not self.user_id.strip() or not self.tenant_id.strip():
            raise ValueError("Principal requires non-empty user_id and tenant_id")
        if self.role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unsupported role: {self.role}")
        if self.actor_kind not in {"human", "agent"}:
            raise ValueError(f"Unsupported actor kind: {self.actor_kind}")
        if self.on_behalf_of is not None and (self.actor_kind != "agent" or not self.on_behalf_of.strip()):
            raise ValueError("on_behalf_of is only for agent identities and must name a person")


def authorize(principal: Principal, tenant_id: str, permission: Permission) -> None:
    if principal.tenant_id != tenant_id:
        raise AuthorizationError("principal does not belong to the requested tenant")
    if permission not in ROLE_PERMISSIONS[principal.role]:
        raise AuthorizationError(f"role '{principal.role}' lacks permission '{permission}'")
    if principal.actor_kind == "agent" and permission in HUMAN_ONLY:
        raise AuthorizationError(f"an agent identity cannot use '{permission}'; a person must")


class GovernanceAccess:
    """Trusted host integration layer that checks role and tenant before storage calls.

    The embedding application must construct Principal from authenticated identity
    claims. Never accept caller-supplied role or tenant values directly.
    """

    def __init__(self, *, registry: SQLiteSkillRegistry, approvals: SQLiteApprovalStore, history: EvaluationHistoryStore,
                 jobs: JobStore | None = None, notifications: NotificationStore | None = None, fleet: FleetStore | None = None,
                 artifacts: ArtifactStore | None = None):
        self.registry = registry
        self.approvals = approvals
        self.history = history
        self.jobs = jobs  # when the service runs evaluations
        self.notifications = notifications  # when alerts are configured
        self.fleet = fleet  # when machines report to this server
        self.artifacts = artifacts  # package bytes, so approved versions can be distributed

    def store_package(self, principal: Principal, files: dict[str, bytes], oversize: dict[str, str] | None = None) -> str:
        authorize(principal, principal.tenant_id, "skill.register")
        if self.artifacts is None:
            from skillproof.storage.registry import RegistryError

            raise RegistryError("package storage is not enabled on this server")
        return self.artifacts.put(principal.tenant_id, files, actor_id=principal.user_id, oversize=oversize)

    def package_bytes(self, principal: Principal, version_id: str) -> tuple[SkillVersion, bytes]:
        """A version and its exact package (ZIP), re-checked against the version's fingerprint."""
        authorize(principal, principal.tenant_id, "skill.read")
        version = self.registry.get_version(principal.tenant_id, version_id)
        if self.artifacts is None:
            from skillproof.storage.registry import RegistryError

            raise RegistryError("package storage is not enabled on this server")
        return version, self.artifacts.get(principal.tenant_id, version["package_fingerprint"])

    def approved_set(self, principal: Principal) -> list[dict[str, Any]]:
        """Every skill's active (approved) version, and whether its package can be distributed."""
        authorize(principal, principal.tenant_id, "skill.read")
        out = []
        for entry in self.registry.catalogue(principal.tenant_id):
            active = entry.get("active")
            if active:
                fingerprint = active["package_fingerprint"]
                out.append({"skill_name": entry["skill_name"], "version_id": active["version_id"], "fingerprint": fingerprint,
                            "distributable": bool(self.artifacts and self.artifacts.has(principal.tenant_id, fingerprint))})
        return out

    def fleet_versions(self, principal: Principal, names: set[str]) -> dict[str, list[SkillVersion]]:
        """The tenant's versions of each named skill, for a machine comparing what it runs (reporter permission)."""
        authorize(principal, principal.tenant_id, "fleet.report")
        return {name: self.registry.list_versions(principal.tenant_id, name) for name in names if name}

    def record_fleet_report(self, principal: Principal, host: str, compared: list[FleetEntry]) -> FleetReportResult:
        authorize(principal, principal.tenant_id, "fleet.report")
        if self.fleet is None:
            from skillproof.storage.registry import RegistryError

            raise RegistryError("fleet reporting is not enabled on this server")
        return self.fleet.record(principal.tenant_id, host, compared, reported_by=principal.user_id)

    def fleet_hosts(self, principal: Principal) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "skill.read")
        return [] if self.fleet is None else self.fleet.hosts(principal.tenant_id)

    def add_webhook(self, principal: Principal, url: str, events: list[str]) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "policy.manage")
        return self._notify().add_webhook(principal.tenant_id, url, events, actor_id=principal.user_id)

    def list_webhooks(self, principal: Principal) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "policy.manage")
        return self._notify().webhooks(principal.tenant_id)

    def remove_webhook(self, principal: Principal, webhook_id: str) -> None:
        authorize(principal, principal.tenant_id, "policy.manage")
        self._notify().remove_webhook(principal.tenant_id, webhook_id)

    def list_notifications(self, principal: Principal, limit: int = 100) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "skill.read")
        return [] if self.notifications is None else self.notifications.notifications(principal.tenant_id, limit)

    def _notify(self) -> NotificationStore:
        if self.notifications is None:
            from skillproof.storage.registry import RegistryError

            raise RegistryError("alerts are not enabled on this server")
        return self.notifications

    def tenant_policy(self, principal: Principal) -> AssurancePolicy:
        """The tenant's assurance policy (stored by a tenant admin), or the default policy."""
        authorize(principal, principal.tenant_id, "skill.read")
        stored = self.registry.get_policy(principal.tenant_id)
        return AssurancePolicy(**stored["policy"]) if stored else AssurancePolicy()

    def stored_policy(self, principal: Principal) -> dict[str, Any] | None:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.get_policy(principal.tenant_id)

    def set_tenant_policy(self, principal: Principal, policy: Any) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "policy.manage")
        return self.registry.set_policy(principal.tenant_id, policy.model_dump(), actor_id=principal.user_id)

    def gate_settings(self, principal: Principal) -> dict[str, Any]:
        """The load-rate thresholds in force for the tenant: its own, else the server defaults."""
        from skillproof.config import settings

        authorize(principal, principal.tenant_id, "skill.read")
        stored = self.registry.get_gate_settings(principal.tenant_id)
        defaults = {"min_load_rate": settings().min_load_rate, "max_false_load_rate": settings().max_false_load_rate}
        return {"settings": {**defaults, **((stored or {}).get("settings") or {})}, "source": "tenant" if stored else "default",
                "updated_by": (stored or {}).get("updated_by"), "updated_at": (stored or {}).get("updated_at")}

    def set_gate_settings(self, principal: Principal, values: dict[str, Any]) -> dict[str, Any]:
        """Change the tenant's load-rate thresholds (a person with policy.manage; agents cannot)."""
        authorize(principal, principal.tenant_id, "policy.manage")
        self.registry.set_gate_settings(principal.tenant_id, values, actor_id=principal.user_id)
        return self.gate_settings(principal)

    def preview_change(self, principal: Principal, skill_name: str, manifest: dict[str, Any], *,
                       full_review: bool = False) -> CapabilityChange:
        authorize(principal, principal.tenant_id, "skill.register")
        return self.registry.preview_change(principal.tenant_id, skill_name, manifest, full_review=full_review)

    def enqueue_evaluation(self, principal: Principal, version_id: str, payload: dict[str, Any]) -> EvaluationJob:
        authorize(principal, principal.tenant_id, "evaluation.run")
        if self.jobs is None:
            from skillproof.storage.registry import RegistryError

            raise RegistryError("evaluation jobs are not enabled on this server")
        version = self.registry.get_version(principal.tenant_id, version_id)
        return self.jobs.enqueue(principal.tenant_id, version_id, version["skill_name"], payload, requested_by=principal.user_id)

    def version_jobs(self, principal: Principal, version_id: str) -> list[EvaluationJob]:
        authorize(principal, principal.tenant_id, "evaluation.read")
        return [] if self.jobs is None else self.jobs.for_version(principal.tenant_id, version_id)

    @staticmethod
    def _history_key(tenant_id: str, skill_key: str) -> str:
        return f"{tenant_id}:{skill_key}"

    def register_skill(
        self, principal: Principal, skill_report: dict[str, Any], assurance_report: dict[str, Any], *,
        artifact_uri: str | None = None, capability_manifest: dict[str, Any] | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> SkillVersion:
        authorize(principal, principal.tenant_id, "skill.register")
        return self.registry.register(principal.tenant_id, skill_report, assurance_report, actor_id=principal.user_id,
                                      artifact_uri=artifact_uri, capability_manifest=capability_manifest, provenance=provenance)

    def promote_skill(
        self, principal: Principal, version_id: str, assurance_report: dict[str, Any], approval_record: dict[str, Any],
        *, capability_ack: str | None = None,
    ) -> SkillVersion:
        authorize(principal, principal.tenant_id, "skill.promote")
        return self.registry.promote(principal.tenant_id, version_id, assurance_report, approval_record,
                                     actor_id=principal.user_id, capability_ack=capability_ack)

    def reassess_skill(self, principal: Principal, version_id: str, assurance_report: dict[str, Any]) -> SkillVersion:
        authorize(principal, principal.tenant_id, "skill.register")
        return self.registry.reassess(principal.tenant_id, version_id, assurance_report, actor_id=principal.user_id)

    def rollback_skill(self, principal: Principal, skill_name: str, reason: str) -> SkillVersion:
        """Restore the last approved version. The same permission as promotion: it changes what is live."""
        authorize(principal, principal.tenant_id, "skill.promote")
        return self.registry.rollback(principal.tenant_id, skill_name, actor_id=principal.user_id, reason=reason)

    def promote_version(self, principal: Principal, version_id: str, request_id: str, *, capability_ack: str | None = None) -> SkillVersion:
        """Promote using the assurance report stored with the version and the tenant's own approval record."""
        authorize(principal, principal.tenant_id, "skill.promote")
        assurance = self.registry.get_assurance(principal.tenant_id, version_id)
        record = self.approvals.get_request(request_id, tenant_id=principal.tenant_id)
        return self.registry.promote(principal.tenant_id, version_id, assurance, record,
                                     actor_id=principal.user_id, capability_ack=capability_ack)

    def get_skill(self, principal: Principal, version_id: str) -> SkillVersion:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.get_version(principal.tenant_id, version_id)

    def list_skill_versions(self, principal: Principal, skill_name: str) -> list[SkillVersion]:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.list_versions(principal.tenant_id, skill_name)

    def catalogue(self, principal: Principal) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.catalogue(principal.tenant_id)

    def version_approvals(self, principal: Principal, version_id: str) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "skill.read")
        assurance = self.registry.get_assurance(principal.tenant_id, version_id)
        return self.approvals.list_for_report(assurance, tenant_id=principal.tenant_id)

    def submit_version_for_approval(self, principal: Principal, version_id: str) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "approval.submit")
        assurance = self.registry.get_assurance(principal.tenant_id, version_id)
        return self.approvals.submit_for_review(assurance, submitter_id=principal.user_id, tenant_id=principal.tenant_id)

    def mark_false_alarm(self, principal: Principal, version_id: str, category: str, value: str, reason: str) -> SkillVersion:
        """A reviewer says one raised item is not a real capability. Needs the reviewer's permission, never the author's."""
        authorize(principal, principal.tenant_id, "approval.decide")
        return self.registry.mark_false_alarm(principal.tenant_id, version_id, category, value, reason, actor_id=principal.user_id)

    def false_alarm_labels(self, principal: Principal) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.false_alarms(principal.tenant_id)

    def submit_approval(self, principal: Principal, report: dict[str, Any]) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "approval.submit")
        return self.approvals.submit_for_review(report, submitter_id=principal.user_id, tenant_id=principal.tenant_id)

    def decide_approval(self, principal: Principal, request_id: str, action: ApprovalAction, *, comment: str = "") -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "approval.decide")
        return self.approvals.decide(request_id, actor_id=principal.user_id, action=action, comment=comment, tenant_id=principal.tenant_id)

    def record_evaluation(self, principal: Principal, report: dict[str, Any], *, skill_key: str) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "evaluation.run")
        return self.history.record(report, skill_key=self._history_key(principal.tenant_id, skill_key))

    def list_evaluations(self, principal: Principal, *, skill_key: str, limit: int = 50) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "evaluation.read")
        return self.history.list_history(self._history_key(principal.tenant_id, skill_key), limit=limit)

