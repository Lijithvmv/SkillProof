"""The service produces run evidence itself. Decision changed: a version uploaded without evidence no longer stays at
insufficient_evidence; the server's job measures it and the version is assessed again."""
import json

from fastapi.testclient import TestClient

from skillproof.api.main import app
from skillproof.approvals import SQLiteApprovalStore
from skillproof.authorization import GovernanceAccess
from skillproof.evaluation_jobs import EvaluationSettings, work_once
from skillproof.execution import AgentResult
from skillproof.history import EvaluationHistoryStore
from skillproof.jobs import JobStore
from skillproof.registry import SQLiteSkillRegistry
from test_registry_api import as_user, zip_of

SKILL = """---
name: release-notes
description: Write release notes from merged pull requests. Use when the user asks for release notes or a changelog.
---

# Release notes

1. Group the changes into Added, Fixed and Changed, then verify every pull request number appears once.
2. Write the notes as a Markdown file with one section per group.

Do not invent pull request numbers.
"""


def governance(tmp_path):
    return GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "registry.db"), approvals=SQLiteApprovalStore(tmp_path / "approvals.db"),
                            history=EvaluationHistoryStore(tmp_path / "history.db"), jobs=JobStore(tmp_path / "jobs.db"))


def scenario_writer(prompt, schema):
    return json.dumps({"request": "Write release notes for this sprint", "context": "Merged: fix login timeout; add CSV export; rename settings page."})


class Runner:
    def run(self, *, prompt, context, skill_instructions):
        text = "Added: CSV export. Fixed: login timeout. The PR numbers were not provided." if skill_instructions else "PR #101 fixed login."
        return AgentResult(output=text, provider="fake", model="fake-1", duration_ms=1, input_tokens=150 if skill_instructions else 100,
                           output_tokens=20, cost_usd=0.0)


def test_uploaded_version_is_measured_by_the_server_and_assessed_again(tmp_path):
    gov = governance(tmp_path)
    app.state.governance = gov
    try:
        client = TestClient(app)
        uploaded = client.post("/api/v1/registry/versions", files={"file": ("skill.zip", zip_of(SKILL))},
                               data={"evaluate": "true"}, headers=as_user("alice", "evaluator"))
        assert uploaded.status_code == 200, uploaded.text
        version, job = uploaded.json()["version"], uploaded.json()["job"]
        assert version["summary"]["assurance_decision"] == "insufficient_evidence" and job["state"] == "queued"

        settings = EvaluationSettings(model="fake-1", draft_model="fake-draft", repeats=3)
        done = work_once(gov, settings, ask=scenario_writer, runner=Runner())
        assert done["state"] == "done", done.get("error")
        result = done["result"]
        assert result["outcome"] == "measured" and result["adherence_rate"] == 1.0 and result["baseline_rate"] == 0.0
        assert work_once(gov, settings, ask=scenario_writer, runner=Runner()) is None  # queue is empty

        after = client.get(f"/api/v1/registry/versions/{version['version_id']}", headers=as_user("carol", "viewer")).json()
        assert after["assurance"]["evidence"]["source"] == "measured"
        assert after["assurance"]["evidence"]["experiment_ids"] == [result["experiment_id"]]
        assert any(g["code"] == "CLAIM_ADHERENCE" and g["status"] == "pass" for g in after["assurance"]["gates"])
        assert after["events"][-1]["action"] == "reassessed"
        listed = client.get(f"/api/v1/registry/versions/{version['version_id']}/jobs", headers=as_user("carol", "viewer")).json()
        assert [j["state"] for j in listed["jobs"]] == ["done"]
    finally:
        app.state.governance = None


def test_a_failed_job_is_recorded_and_a_stopped_job_is_requeued(tmp_path):
    gov = governance(tmp_path)
    version = gov.registry.register("t", {"package_fingerprint": "a" * 64, "metadata": {"name": "s"}},
                                    {"decision": "insufficient_evidence", "automatic_certification": False}, actor_id="alice")
    jobs = gov.jobs
    first = jobs.enqueue("t", version["version_id"], "s", {"skill_md": "x", "instructions_fingerprint": "wrong"}, requested_by="alice")
    assert jobs.enqueue("t", version["version_id"], "s", {}, requested_by="bob")["job_id"] == first["job_id"]  # one open job per version
    failed = work_once(gov, EvaluationSettings(model="m", draft_model="m"), ask=scenario_writer, runner=Runner())
    assert failed["state"] == "failed" and "does not match the fingerprint" in failed["error"]

    second = jobs.enqueue("t", version["version_id"], "s", {"skill_md": "x", "instructions_fingerprint": "y"}, requested_by="alice")
    assert jobs.claim()[1]["job_id"] == second["job_id"]  # server stops while running
    assert jobs.recover() == 1 and jobs.get("t", second["job_id"])["state"] == "queued"
    assert jobs.claim()[1]["job_id"] == second["job_id"]
