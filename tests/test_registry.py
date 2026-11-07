import sqlite3

import pytest

from skillproof.approvals import SQLiteApprovalStore
from skillproof.registry import RegistryError, SQLiteSkillRegistry


def skill_report(name, fingerprint, score=90):
    return {
        "schema_version": "1.2.0",
        "package_fingerprint": fingerprint * 64,
        "metadata": {"name": name},
        "structural_score": score,
        "instruction_quality": {"quality_score": 80},
        "security": {"security_score": 90, "status": "no_static_findings"},
    }


def assurance_report(policy="prod"):
    return {
        "decision": "eligible_for_human_approval",
        "policy_id": policy,
        "automatic_certification": False,
        "gates": [{"code": "all", "status": "pass"}],
    }


def approved_record(approval_store, assurance, submitter="alice", tenant_id="tenant"):
    request = approval_store.submit_for_review(assurance, submitter_id=submitter, tenant_id=tenant_id)
    return approval_store.decide(request["request_id"], actor_id="reviewer", action="approve", tenant_id=tenant_id)


def test_registry_requires_matching_approved_human_record(tmp_path):
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    approvals = SQLiteApprovalStore(tmp_path / "approvals.db")
    assurance = assurance_report()
    version = registry.register("tenant-a", skill_report("demo-skill", "a"), assurance, actor_id="alice", artifact_uri="s3://private/skills/demo.zip")
    assert version["state"] == "pending_review"
    assert version["summary"]["assurance_decision"] == "eligible_for_human_approval"
    assert version["artifact_uri"] == "s3://private/skills/demo.zip"

    request = approvals.submit_for_review(assurance, submitter_id="alice", tenant_id="tenant-a")
    with pytest.raises(RegistryError, match="approved human review"):
        registry.promote("tenant-a", version["version_id"], assurance, request, actor_id="operator")
    approved = approvals.decide(request["request_id"], actor_id="reviewer", action="approve", tenant_id="tenant-a")
    other_report = assurance_report("different-policy")
    with pytest.raises(RegistryError, match="does not match"):
        registry.promote("tenant-a", version["version_id"], other_report, approved, actor_id="operator")

    active = registry.promote("tenant-a", version["version_id"], assurance, approved, actor_id="operator")
    assert active["state"] == "active"
    assert active["events"][-1]["action"] == "promoted"
    assert registry.get_active("tenant-a", "demo-skill")["version_id"] == version["version_id"]
    with pytest.raises(RegistryError, match="not found in this tenant"):
        registry.get_version("tenant-b", version["version_id"])
    registry.close()
    approvals.close()


def test_new_approved_version_supersedes_previous_active_version(tmp_path):
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    approvals = SQLiteApprovalStore(tmp_path / "approvals.db")
    assurance = assurance_report()
    first = registry.register("tenant", skill_report("demo-skill", "a"), assurance, actor_id="alice")
    first_approval = approved_record(approvals, assurance, tenant_id="tenant")
    registry.promote("tenant", first["version_id"], assurance, first_approval, actor_id="operator")

    second = registry.register("tenant", skill_report("demo-skill", "b"), assurance, actor_id="alice")
    second_approval = approved_record(approvals, assurance, tenant_id="tenant")
    registry.promote("tenant", second["version_id"], assurance, second_approval, actor_id="operator")
    assert registry.get_version("tenant", first["version_id"])["state"] == "superseded"
    assert registry.get_active("tenant", "demo-skill")["version_id"] == second["version_id"]
    registry.close()
    approvals.close()


def test_noneligible_version_cannot_be_promoted_and_duplicates_are_idempotent(tmp_path):
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    blocked = {"decision": "not_ready", "policy_id": "prod", "automatic_certification": False}
    version = registry.register("tenant", skill_report("demo-skill", "a"), blocked, actor_id="alice")
    assert version["state"] == "not_eligible"
    assert registry.register("tenant", skill_report("demo-skill", "a"), blocked, actor_id="alice")["version_id"] == version["version_id"]
    with pytest.raises(RegistryError, match="only assurance-eligible"):
        registry.promote("tenant", version["version_id"], blocked, {}, actor_id="operator")
    with pytest.raises(RegistryError, match="different assurance report"):
        registry.register("tenant", skill_report("demo-skill", "a"), assurance_report(), actor_id="alice")
    registry.close()


def test_registry_audit_events_are_append_only(tmp_path):
    database = tmp_path / "registry.db"
    registry = SQLiteSkillRegistry(database)
    version = registry.register("tenant", skill_report("demo-skill", "a"), assurance_report(), actor_id="alice")
    with sqlite3.connect(database) as direct:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute("UPDATE registry_events SET detail='tampered' WHERE version_id=?", (version["version_id"],))
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute("DELETE FROM registry_events WHERE version_id=?", (version["version_id"],))
    registry.close()

