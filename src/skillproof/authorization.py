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

    def __init__(self, *, registry: SQLiteSkillRegistry, approvals: SQLiteApprovalStore, history: EvaluationHistoryStore):
        self.registry = registry
        self.approvals = approvals
        self.history = history

    @staticmethod
    def _history_key(tenant_id: str, skill_key: str) -> str:
        return f"{tenant_id}:{skill_key}"

    def register_skill(self, principal: Principal, skill_report: dict[str, Any], assurance_report: dict[str, Any], *, artifact_uri: str | None = None) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.register")
        return self.registry.register(principal.tenant_id, skill_report, assurance_report, actor_id=principal.user_id, artifact_uri=artifact_uri)

    def promote_skill(self, principal: Principal, version_id: str, assurance_report: dict[str, Any], approval_record: dict[str, Any]) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.promote")
        return self.registry.promote(principal.tenant_id, version_id, assurance_report, approval_record, actor_id=principal.user_id)

    def get_skill(self, principal: Principal, version_id: str) -> dict[str, Any]:
        authorize(principal, principal.tenant_id, "skill.read")
        return self.registry.get_version(principal.tenant_id, version_id)

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

