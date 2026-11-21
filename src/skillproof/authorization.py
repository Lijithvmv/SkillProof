"""Tenant-aware RBAC boundary for embedding applications."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from skillproof.approvals import ApprovalAction, SQLiteApprovalStore
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SQLiteSkillRegistry


Role = Literal["tenant_admin", "evaluator", "approver", "viewer"]
Permission = Literal[
    "skill.read", "skill.register", "skill.promote",
    "evaluation.read", "evaluation.run", "approval.submit", "approval.decide", "policy.manage",
]

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    "tenant_admin": frozenset({"skill.read", "skill.register", "skill.promote", "evaluation.read", "evaluation.run", "approval.submit", "approval.decide", "policy.manage"}),
    "evaluator": frozenset({"skill.read", "skill.register", "evaluation.read", "evaluation.run", "approval.submit"}),
    "approver": frozenset({"skill.read", "skill.promote", "evaluation.read", "approval.decide"}),
    "viewer": frozenset({"skill.read", "evaluation.read"}),
}


class AuthorizationError(PermissionError):
    """Principal is outside the requested tenant or lacks the required role."""


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    role: Role

    def __post_init__(self) -> None:
        if not self.user_id.strip() or not self.tenant_id.strip():
            raise ValueError("Principal requires non-empty user_id and tenant_id")
        if self.role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unsupported role: {self.role}")


def authorize(principal: Principal, tenant_id: str, permission: Permission) -> None:
    if principal.tenant_id != tenant_id:
        raise AuthorizationError("principal does not belong to the requested tenant")
    if permission not in ROLE_PERMISSIONS[principal.role]:
        raise AuthorizationError(f"role '{principal.role}' lacks permission '{permission}'")


class GovernanceAccess:
    """Trusted host integration layer that checks role and tenant before storage calls.

    The embedding application must construct Principal from authenticated identity
    claims. Never accept caller-supplied role or tenant values directly.
    """

    def __init__(self, *, registry: SQLiteSkillRegistry, approvals: SQLiteApprovalStore, history: EvaluationHistoryStore,
                 jobs: Any | None = None):
        self.registry = registry
        self.approvals = approvals
        self.history = history
        self.jobs = jobs  # skillproof.jobs.JobStore, when the service runs evaluations

    def request_evaluation(self, principal: Principal, version_id: str, skill_md: str) -> dict[str, Any]:
        """Queue a run-evidence job for a version, given the exact SKILL.md text the version holds."""
        authorize(principal, principal.tenant_id, "evaluation.run")
        if self.jobs is None:
            from skillproof.registry import RegistryError

            raise RegistryError("evaluation jobs are not enabled on this server")
        from skillproof.evidence import instructions_fingerprint

        version = self.registry.get_version(principal.tenant_id, version_id)
        payload = {"skill_md": skill_md, "instructions_fingerprint": instructions_fingerprint(skill_md)}
        return self.jobs.enqueue(principal.tenant_id, version_id, version["skill_name"], payload, requested_by=principal.user_id)

    def version_jobs(self, principal: Principal, version_id: str) -> list[dict[str, Any]]:
        authorize(principal, principal.tenant_id, "evaluation.read")
        return [] if self.jobs is None else self.jobs.for_version(principal.tenant_id, version_id)

    @staticmethod
    def _history_key(tenant_id: str, skill_key: str) -> str:
        return f"{tenant_id}:{skill_key}"

    def register_skill(
        self, principal: Principal, skill_report: dict[str, Any], assurance_report: dict[str, Any], *,
        artifact_uri: str | None = None, capability_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.register")
        return self.registry.register(principal.tenant_id, skill_report, assurance_report, actor_id=principal.user_id,
                                      artifact_uri=artifact_uri, capability_manifest=capability_manifest)

    def promote_skill(
        self, principal: Principal, version_id: str, assurance_report: dict[str, Any], approval_record: dict[str, Any],
        *, capability_ack: str | None = None,
    ) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.promote")
        return self.registry.promote(principal.tenant_id, version_id, assurance_report, approval_record,
                                     actor_id=principal.user_id, capability_ack=capability_ack)

    def reassess_skill(self, principal: Principal, version_id: str, assurance_report: dict[str, Any]) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.register")
        return self.registry.reassess(principal.tenant_id, version_id, assurance_report, actor_id=principal.user_id)

    def rollback_skill(self, principal: Principal, skill_name: str, reason: str) -> dict[str, Any]:
        """Restore the last approved version. The same permission as promotion: it changes what is live."""
        authorize(principal, principal.tenant_id, "skill.promote")
        return self.registry.rollback(principal.tenant_id, skill_name, actor_id=principal.user_id, reason=reason)

    def promote_version(self, principal: Principal, version_id: str, request_id: str, *, capability_ack: str | None = None) -> dict[str, Any]:
        """Promote using the assurance report stored with the version and the tenant's own approval record."""
        authorize(principal, principal.tenant_id, "skill.promote")
        assurance = self.registry.get_assurance(principal.tenant_id, version_id)
        record = self.approvals.get_request(request_id, tenant_id=principal.tenant_id)
        return self.registry.promote(principal.tenant_id, version_id, assurance, record,
                                     actor_id=principal.user_id, capability_ack=capability_ack)

    def get_skill(self, principal: Principal, version_id: str) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.get_version(principal.tenant_id, version_id)

    def list_skill_versions(self, principal: Principal, skill_name: str) -> list[dict[str, Any]]:
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

    def mark_false_alarm(self, principal: Principal, version_id: str, category: str, value: str, reason: str) -> dict[str, Any]:
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

