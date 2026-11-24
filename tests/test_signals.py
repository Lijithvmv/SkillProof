"""Signals from real use: usage counts and papercuts. Each test names the decision it guards."""
from datetime import date

import pytest
from fastapi.testclient import TestClient

from skillproof.api.main import app
from skillproof.approvals import SQLiteApprovalStore
from skillproof.authorization import GovernanceAccess
from skillproof.cli.signals import skill_run, spooled_counts
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SQLiteSkillRegistry
from skillproof.storage.signals import SignalStore

TODAY = date.today().isoformat()


def as_user(user, role):
    return {"x-skillproof-dev-user": user, "x-skillproof-dev-role": role}


@pytest.fixture()
def client(tmp_path):
    governance = GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "registry.db"), approvals=SQLiteApprovalStore(tmp_path / "a.db"),
                                  history=EvaluationHistoryStore(tmp_path / "h.db"), signals=SignalStore(tmp_path / "signals.db"))
    app.state.governance = governance
    yield TestClient(app)
    app.state.governance = None
    for store in (governance.registry, governance.approvals, governance.signals):
        store.close()


# Decision: a machine resends its whole spool, so a count replaces the earlier one for the same day, skill, version,
# machine and trigger instead of adding to it; the summary separates agent-chosen from user-typed runs.
def test_usage_counts_are_replaced_not_doubled(client):
    rows = [{"skill_name": "create-pr", "day": TODAY, "trigger": "agent", "count": 3},
            {"skill_name": "create-pr", "day": TODAY, "trigger": "user", "count": 1}]
    for _ in range(2):
        assert client.post("/api/v1/signals/usage", json={"host": "laptop-1", "events": rows}, headers=as_user("m", "reporter")).status_code == 200
    client.post("/api/v1/signals/usage", json={"host": "laptop-2", "events": rows[:1]}, headers=as_user("m", "reporter"))
    skill = client.get("/api/v1/signals/skills/create-pr", headers=as_user("v", "viewer")).json()
    assert skill["invocations"] == 7 and skill["by_trigger"] == {"agent": 6, "user": 1} and skill["machines"] == 2
    summary = client.get("/api/v1/signals", headers=as_user("v", "viewer")).json()["skills"]
    assert summary[0] == {"skill_name": "create-pr", "invocations": 7, "machines": 2, "chosen_by_agent": 6, "open_papercuts": 0, "papercuts": 0}


# Decision: the hook keeps the name of the skill that ran and who chose it, never the prompt; other events are ignored.
def test_the_hook_keeps_no_prompt_text(tmp_path):
    assert skill_run({"hook_event_name": "PostToolUse", "tool_name": "Skill", "tool_input": {"skill": "create-pr"}}) == ("create-pr", "agent")
    assert skill_run({"hook_event_name": "UserPromptSubmit", "prompt": "/review-security token sk-abc and my notes"}) == ("review-security", "user")
    assert skill_run({"hook_event_name": "UserPromptSubmit", "prompt": "please review this"}) is None
    assert skill_run({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}) is None
    spool = tmp_path / "usage.jsonl"
    spool.write_text(f'{{"day": "{TODAY}", "skill_name": "create-pr", "trigger": "agent"}}\n' * 2 + "broken line\n"
                     '{"day": "2000-01-01", "skill_name": "old", "trigger": "agent"}\n', encoding="utf-8")
    assert spooled_counts(spool) == [{"day": TODAY, "skill_name": "create-pr", "trigger": "agent", "count": 2}]


# Decision: anyone working with skills (and a reporting machine) can file a papercut; only the skill's owners (who can
# register versions) close one, once, with what was fixed; a viewer can report nothing.
def test_papercuts_are_filed_by_users_and_closed_by_owners(client):
    body = {"skill_name": "create-pr", "tried": "gh pr create --draft-only", "expected": "a draft PR",
            "happened": "unknown flag: --draft-only", "suggested_fix": "use --draft"}
    filed = client.post("/api/v1/signals/papercuts", json=body, headers=as_user("agent-run", "reporter"))
    assert filed.status_code == 200, filed.text
    cut = filed.json()["papercut_id"]
    assert client.post("/api/v1/signals/papercuts", json=body, headers=as_user("v", "viewer")).status_code == 403
    assert client.post(f"/api/v1/signals/papercuts/{cut}/resolve", json={"resolution": "x"}, headers=as_user("b", "approver")).status_code == 403
    done = client.post(f"/api/v1/signals/papercuts/{cut}/resolve", json={"resolution": "step 2 now uses --draft"}, headers=as_user("e", "evaluator"))
    assert done.status_code == 200 and done.json()["status"] == "resolved"
    assert client.post(f"/api/v1/signals/papercuts/{cut}/resolve", json={"resolution": "again"}, headers=as_user("e", "evaluator")).status_code == 409
    assert client.post("/api/v1/signals/usage", json={"host": "h", "events": []}, headers=as_user("v", "viewer")).status_code == 403


# Decision: one tenant's usage and papercuts are never visible to another.
def test_signals_stay_in_their_tenant(tmp_path):
    store = SignalStore(tmp_path / "signals.db")
    try:
        store.record_usage("acme", "h1", [{"skill_name": "a", "day": TODAY, "trigger": "agent", "count": 2}])
        store.file_papercut("acme", {"skill_name": "a", "tried": "t", "expected": "e", "happened": "h"}, reported_by="x")
        assert store.summary("other") == [] and store.skill("other", "a")["invocations"] == 0
        assert store.summary("acme")[0]["open_papercuts"] == 1
    finally:
        store.close()
