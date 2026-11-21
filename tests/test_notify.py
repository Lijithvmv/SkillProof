"""Alerts. Decision changed: who is told, and when, that a block-level update arrived, a version went live or was rolled
back, an evaluation finished, or an unapproved skill is running; and that the message can be trusted (signed)."""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from skillproof.api.main import app
from skillproof.approvals import SQLiteApprovalStore
from skillproof.authorization import GovernanceAccess
from skillproof.history import EvaluationHistoryStore
from skillproof.jobs import JobStore
from skillproof.notify import NotificationStore, NotifyError, check_endpoint
from skillproof.registry import SQLiteSkillRegistry
from test_registry_api import BYPASS, SKILL, approve, as_user, zip_of


class Endpoint:
    def __init__(self, statuses):
        self.statuses, self.calls = list(statuses), []

    def __call__(self, url, body, headers):
        self.calls.append((url, body, headers))
        return self.statuses.pop(0)


def test_delivery_is_signed_and_retried_then_settled(tmp_path):
    store = NotificationStore(tmp_path / "notify.db")
    hook = store.add_webhook("t", "https://alerts.example.org/skillproof", ["version.promoted"], actor_id="root")
    assert store.emit("t", "version.promoted", {"skill_name": "s"}) == 1
    assert store.emit("t", "evaluation.failed", {"skill_name": "s"}) == 0  # not subscribed

    flaky = Endpoint([503])
    first = store.deliver_once(flaky)
    assert first["state"] == "queued" and first["attempts"] == 1 and "HTTP 503" in first["error"]
    assert store.deliver_once(flaky) is None  # waits for its back-off

    store.db.execute("UPDATE delivery_queue SET due_at='2000-01-01T00:00:00.000Z'")
    ok = Endpoint([204])
    assert store.deliver_once(ok)["state"] == "sent"
    url, body, headers = ok.calls[0]
    expected = "sha256=" + hmac.new(hook["secret"].encode(), body, hashlib.sha256).hexdigest()
    assert headers["X-SkillProof-Signature"] == expected and json.loads(body)["skill_name"] == "s"
    assert "secret" not in store.webhook("t", hook["webhook_id"])  # shown once, at creation
    assert [n["state"] for n in store.notifications("t")] == ["sent"]


def test_endpoints_must_be_https_and_public_in_production(monkeypatch):
    with pytest.raises(NotifyError, match="HTTPS"):
        check_endpoint("http://alerts.example.org/x")
    check_endpoint("http://127.0.0.1:9000/x")  # local testing outside production
    monkeypatch.setenv("SKILLPROOF_ENV", "production")
    with pytest.raises(NotifyError, match="non-public"):
        check_endpoint("https://alerts.example.org/x", resolve=lambda host: ["10.0.0.5"])
    check_endpoint("https://alerts.example.org/x", resolve=lambda host: ["93.184.216.34"])


def test_catalogue_events_reach_subscribed_endpoints(tmp_path):
    gov = GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "r.db"), approvals=SQLiteApprovalStore(tmp_path / "a.db"),
                           history=EvaluationHistoryStore(tmp_path / "h.db"), jobs=JobStore(tmp_path / "j.db"),
                           notifications=NotificationStore(tmp_path / "n.db"))
    app.state.governance = gov
    try:
        client = TestClient(app)
        denied = client.post("/api/v1/webhooks", json={"url": "https://a.example.org/h", "events": ["version.promoted"]},
                             headers=as_user("alice", "evaluator"))
        assert denied.status_code == 403
        made = client.post("/api/v1/webhooks", json={"url": "https://a.example.org/h", "events": ["version.promoted", "version.block_level_addition"]},
                           headers=as_user("root", "tenant_admin"))
        assert made.status_code == 200 and len(made.json()["secret"]) == 64
        evidence = {"evidence_json": json.dumps({"behavioral_lift_pp": 10, "paired_runs": 5, "measured_models": 1, "cost_overhead_percent": 20})}
        first = client.post("/api/v1/registry/versions", files={"file": ("s.zip", zip_of(SKILL))}, data=evidence,
                            headers=as_user("alice", "evaluator")).json()["version"]
        client.post(f"/api/v1/registry/versions/{first['version_id']}/promote", headers=as_user("bob", "approver"),
                    json={"approval_request_id": approve(client, first["version_id"])})
        client.post("/api/v1/registry/versions", files={"file": ("s.zip", zip_of(SKILL + BYPASS))}, data=evidence,
                    headers=as_user("alice", "evaluator"))
        events = [n["event"] for n in client.get("/api/v1/notifications", headers=as_user("carol", "viewer")).json()["notifications"]]
        assert sorted(events) == ["version.block_level_addition", "version.promoted"]
    finally:
        app.state.governance = None
