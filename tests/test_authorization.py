import pytest

from skillproof.approvals import ApprovalError, SQLiteApprovalStore
from skillproof.authorization import AuthorizationError, GovernanceAccess, Principal, authorize
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SQLiteSkillRegistry


def test_cross_tenant_access_is_denied():
    principal = Principal(user_id="alice", tenant_id="tenant-a", role="viewer")
    with pytest.raises(AuthorizationError, match="requested tenant"):
        authorize(principal, "tenant-b", "skill.read")


def test_role_matrix_blocks_viewer_write_and_evaluator_approval_decision():
    viewer = Principal("reader", "tenant", "viewer")
    with pytest.raises(AuthorizationError, match="lacks permission"):
        authorize(viewer, "tenant", "skill.register")
    evaluator = Principal("builder", "tenant", "evaluator")
    with pytest.raises(AuthorizationError, match="lacks permission"):
        authorize(evaluator, "tenant", "approval.decide")
    approver = Principal("reviewer", "tenant", "approver")
    authorize(approver, "tenant", "approval.decide")


def test_governance_access_uses_principal_tenant_and_enforces_reviewer_role(tmp_path):
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    approvals = SQLiteApprovalStore(tmp_path / "approvals.db")
    history = EvaluationHistoryStore(tmp_path / "history.db")
    access = GovernanceAccess(registry=registry, approvals=approvals, history=history)
    report = {"decision": "eligible_for_human_approval", "policy_id": "p", "automatic_certification": False}
    evaluator = Principal("alice", "tenant-a", "evaluator")
    request = access.submit_approval(evaluator, report)
    assert request["tenant_id"] == "tenant-a"
    with pytest.raises(AuthorizationError, match="lacks permission"):
        access.decide_approval(evaluator, request["request_id"], "approve")

    approver = Principal("bob", "tenant-a", "approver")
    approved = access.decide_approval(approver, request["request_id"], "approve")
    assert approved["state"] == "approved"
    with pytest.raises(ApprovalError, match="not found"):
        approvals.get_request(request["request_id"], tenant_id="tenant-b")
    registry.close()
    approvals.close()
    history.close()


def test_principal_rejects_empty_identity_or_unsupported_role():
    with pytest.raises(ValueError):
        Principal("", "tenant", "viewer")
    with pytest.raises(ValueError):
        Principal("alice", "tenant", "owner")
