"""Version lifecycle after registration: new evidence re-assesses a waiting version; rollback restores the last
approved one. Each test names the decision it changes."""
import pytest

from skillproof.approvals import SQLiteApprovalStore
from skillproof.registry import RegistryError, SQLiteSkillRegistry
from test_registry import approved_record, assurance_report, skill_report

TENANT = "tenant"


def waiting(decision):
    return {"decision": decision, "policy_id": "prod", "automatic_certification": False, "gates": []}


def test_new_evidence_reassesses_a_waiting_version_and_voids_the_old_approval(tmp_path):
    # Decision: can a version be approved on evidence recorded after it was registered? Yes, on the new report only.
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    approvals = SQLiteApprovalStore(tmp_path / "approvals.db")
    version = registry.register(TENANT, skill_report("s", "a"), waiting("insufficient_evidence"), actor_id="alice")
    assert version["state"] == "not_eligible"
    measured = assurance_report()
    measured["evidence"] = {"source": "measured", "experiment_ids": ["e1"]}
    again = registry.reassess(TENANT, version["version_id"], measured, actor_id="importer")
    assert again["state"] == "pending_review" and again["assurance"]["evidence"]["source"] == "measured"
    assert again["events"][-1]["action"] == "reassessed" and "insufficient_evidence -> eligible" in again["events"][-1]["detail"]

    record = approved_record(approvals, measured, tenant_id=TENANT)
    newer = dict(measured, evidence={"source": "measured", "experiment_ids": ["e1", "e2"]})
    registry.reassess(TENANT, version["version_id"], newer, actor_id="importer")
    with pytest.raises(RegistryError, match="does not match"):
        registry.promote(TENANT, version["version_id"], newer, record, actor_id="bob")  # approval was on the old report


def test_an_approved_version_keeps_the_report_it_was_approved_on(tmp_path):
    # Decision: evidence arriving later cannot rewrite what an approver signed.
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    approvals = SQLiteApprovalStore(tmp_path / "approvals.db")
    report = assurance_report()
    version = registry.register(TENANT, skill_report("s", "a"), report, actor_id="alice")
    registry.promote(TENANT, version["version_id"], report, approved_record(approvals, report, tenant_id=TENANT), actor_id="bob")
    with pytest.raises(RegistryError, match="keeps the assurance report"):
        registry.reassess(TENANT, version["version_id"], waiting("not_ready"), actor_id="importer")


def test_rollback_restores_the_last_approved_version_once(tmp_path):
    # Decision: what is live after a bad update. The previous approved version, audited, never an unapproved one.
    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    approvals = SQLiteApprovalStore(tmp_path / "approvals.db")
    ids = []
    for fp, policy in (("a", "v1"), ("b", "v2"), ("c", "v3")):
        report = assurance_report(policy)
        version = registry.register(TENANT, skill_report("s", fp), report, actor_id="alice")
        registry.promote(TENANT, version["version_id"], report, approved_record(approvals, report, tenant_id=TENANT), actor_id="bob")
        ids.append(version["version_id"])
    registry.register(TENANT, skill_report("s", "d"), waiting("insufficient_evidence"), actor_id="alice")  # never approved

    with pytest.raises(RegistryError, match="reason"):
        registry.rollback(TENANT, "s", actor_id="bob", reason=" ")
    restored = registry.rollback(TENANT, "s", actor_id="bob", reason="v3 broke the escape notification")
    assert restored["version_id"] == ids[1] and restored["state"] == "active"
    assert registry.get_version(TENANT, ids[2])["events"][-1]["action"] == "rolled_back"
    again = registry.rollback(TENANT, "s", actor_id="bob", reason="v2 also bad")
    assert again["version_id"] == ids[0]  # not back to v3, which was rolled back from
    with pytest.raises(RegistryError, match="no earlier approved version"):
        registry.rollback(TENANT, "s", actor_id="bob", reason="nothing left")
