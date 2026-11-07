import sqlite3

import pytest

from skillproof.approvals import ApprovalError, SQLiteApprovalStore


def eligible_report():
    return {
        "decision": "eligible_for_human_approval",
        "policy_id": "production-v1",
        "automatic_certification": False,
        "gates": [{"code": "quality", "status": "pass"}],
    }


def test_submission_requires_eligible_report_and_human_approval_flag(tmp_path):
    store = SQLiteApprovalStore(tmp_path / "approvals.db")
    with pytest.raises(ApprovalError, match="eligible"):
        store.submit_for_review({"decision": "not_ready", "automatic_certification": False}, submitter_id="alice")
    with pytest.raises(ApprovalError, match="automatic certification"):
        store.submit_for_review({"decision": "eligible_for_human_approval", "automatic_certification": True}, submitter_id="alice")


def test_approval_requires_separate_reviewer_and_persists_audit(tmp_path):
    database = tmp_path / "approvals.db"
    store = SQLiteApprovalStore(database)
    submitted = store.submit_for_review(eligible_report(), submitter_id="alice")
    assert submitted["state"] == "pending_review"
    assert len(submitted["report_hash"]) == 64
    with pytest.raises(ApprovalError, match="cannot approve"):
        store.decide(submitted["request_id"], actor_id="alice", action="approve")
    approved = store.decide(submitted["request_id"], actor_id="bob", action="approve", comment="Reviewed evidence.")
    assert approved["state"] == "approved"
    assert [event["action"] for event in approved["events"]] == ["submitted", "approve"]
    store.close()

    reopened = SQLiteApprovalStore(database)
    persisted = reopened.get_request(submitted["request_id"])
    assert persisted["state"] == "approved"
    assert persisted["events"][1]["actor_id"] == "bob"
    with pytest.raises(ApprovalError, match="terminal"):
        reopened.decide(submitted["request_id"], actor_id="carol", action="reject")
    reopened.close()


def test_audit_events_cannot_be_updated_or_deleted(tmp_path):
    database = tmp_path / "audit.db"
    store = SQLiteApprovalStore(database)
    request = store.submit_for_review(eligible_report(), submitter_id="alice")
    with sqlite3.connect(database) as direct:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute("UPDATE approval_events SET comment = 'tampered' WHERE request_id = ?", (request["request_id"],))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute("DELETE FROM approval_events WHERE request_id = ?", (request["request_id"],))
    store.close()


def test_approval_requests_are_tenant_scoped(tmp_path):
    store = SQLiteApprovalStore(tmp_path / "tenants.db")
    request = store.submit_for_review(eligible_report(), submitter_id="alice", tenant_id="tenant-a")
    with pytest.raises(ApprovalError, match="not found"):
        store.get_request(request["request_id"], tenant_id="tenant-b")
    with pytest.raises(ApprovalError, match="not found"):
        store.decide(request["request_id"], actor_id="reviewer", action="approve", tenant_id="tenant-b")
    store.close()

