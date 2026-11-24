"""Machine-authored updates: who wrote a version decides its review bar, and no author approves it.
Each test names the decision it guards."""
import pytest
from fastapi.testclient import TestClient

from skillproof import provenance
from skillproof.api.main import app
from skillproof.approvals import SQLiteApprovalStore
from skillproof.authorization import AuthorizationError, GovernanceAccess, Principal, authorize
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SQLiteSkillRegistry

from test_oidc import OIDCAccessTokenVerifier, OIDCSettings, FakeKeys, make_token
from test_registry_api import BYPASS, EVIDENCE, SKILL, as_user, zip_of

# A harmless edit: a person who rewrites this line gets a diff against the approved version.
TWEAK = SKILL.replace("Group the changes", "Group the merged changes")
AGENT = {"x-skillproof-dev-user": "agent:release-bot", "x-skillproof-dev-role": "evaluator",
         "x-skillproof-dev-actor": "agent", "x-skillproof-dev-on-behalf-of": "dave"}


@pytest.fixture()
def client(tmp_path):
    governance = GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "registry.db"), approvals=SQLiteApprovalStore(tmp_path / "approvals.db"),
                                  history=EvaluationHistoryStore(tmp_path / "history.db"))
    app.state.governance = governance
    yield TestClient(app)
    app.state.governance = None
    governance.registry.close()
    governance.approvals.close()


def upload(client, text, headers, provenance_json=None):
    data = {"evidence_json": EVIDENCE}
    if provenance_json:
        data["provenance_json"] = provenance_json
    response = client.post("/api/v1/registry/versions", files={"file": ("skill.zip", zip_of(text))}, data=data, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["version"]


def request_approval(client, version_id, reviewer):
    request = client.post(f"/api/v1/registry/versions/{version_id}/approval-requests", headers=as_user("erin", "evaluator"))
    assert request.status_code == 200, request.text
    request_id = request.json()["request_id"]
    decided = client.post(f"/api/v1/approvals/{request_id}/decision", json={"action": "approve"}, headers=as_user(reviewer, "approver"))
    assert decided.status_code == 200, decided.text
    return request_id


def promote(client, version, request_id, ack=None):
    body = {"approval_request_id": request_id}
    if ack:
        body["capability_ack"] = ack
    return client.post(f"/api/v1/registry/versions/{version['version_id']}/promote", json=body, headers=as_user("bob", "approver"))


def active_skill(client, text=SKILL):
    first = upload(client, text, as_user("alice", "evaluator"))
    ack = first["capability_change"]["change_hash"] if first["capability_change"]["decision"] == "block" else None
    assert promote(client, first, request_approval(client, first["version_id"], "bob"), ack).status_code == 200
    return first


# Decision: declarations only raise the bar. An agent identity cannot declare a version human-written, the importer
# cannot attest anything about files on disk, and a malformed declaration is refused.
def test_declarations_never_lower_the_review_bar():
    agent = Principal(user_id="agent:bot", tenant_id="t", role="evaluator", actor_kind="agent", on_behalf_of="dave")
    person = Principal(user_id="alice", tenant_id="t", role="evaluator")
    assert provenance.resolve(agent, {"author_kind": "human"})["author_kind"] == "agent"
    assert provenance.resolve(person, None, source="installed_import")["author_kind"] == "unknown"
    assert provenance.resolve(person, {"author_kind": "human"}, source="installed_import")["author_kind"] == "unknown"
    assert provenance.resolve(person, {"author_kind": "agent", "agent": "claude-code"})["review_bar"] == "new_skill"
    assert provenance.resolve(person, None)["review_bar"] == "change_over_previous"
    assert provenance.authors(provenance.resolve(agent), "agent:bot") == {"agent:bot", "dave"}
    assert not provenance.full_review(None)  # registered before provenance was kept: keeps its comparison
    for bad in ({"author_kind": "robot"}, {"secret": "x"}, {"note": "x" * 501}, ["agent"]):
        with pytest.raises(provenance.ProvenanceError):
            provenance.resolve(person, bad)


# Decision: an agent identity never decides, makes a version live, dismisses raised items or changes policy, whatever
# role it is given; it can still register and ask for review.
def test_agent_identities_cannot_use_human_only_permissions():
    agent = Principal(user_id="agent:bot", tenant_id="t", role="tenant_admin", actor_kind="agent")
    for permission in ("approval.decide", "skill.promote", "policy.manage"):
        with pytest.raises(AuthorizationError):
            authorize(agent, "t", permission)
    authorize(agent, "t", "skill.register")
    authorize(agent, "t", "approval.submit")
    with pytest.raises(ValueError):
        Principal(user_id="alice", tenant_id="t", role="viewer", on_behalf_of="bob")  # only agents act for someone


# Decision: the same update is diffed against the approved version when a person attests they wrote it, and reviewed
# as a new skill when an agent wrote it: a capability already approved (here a permission bypass) is raised again for
# the agent's rewrite, with the update's own additions kept beside it.
def test_an_agent_written_update_is_reviewed_as_a_new_skill(client):
    first = active_skill(client, SKILL + BYPASS)
    by_person = upload(client, TWEAK + BYPASS, as_user("carol", "evaluator"))
    assert by_person["capability_change"]["against"] == "active_version"
    assert by_person["capability_change"]["decision"] == "none" and by_person["provenance"]["author_kind"] == "human"

    by_agent = upload(client, TWEAK + BYPASS + "\n", AGENT)
    change = by_agent["capability_change"]
    assert by_agent["provenance"]["author_kind"] == "agent" and by_agent["provenance"]["on_behalf_of"] == "dave"
    assert change["against"] == "full_review_not_human_written" and change["against_version_id"] == first["version_id"]
    assert change["update_over_previous"]["against"] == "active_version"
    assert change["update_over_previous"]["decision"] == "none"  # the rewrite itself adds nothing new...
    assert change["decision"] == "block"  # ...but the agent's version is judged on everything it can do
    assert any(i["value"] == "permission bypass" and i["level"] == "block" for i in change["items"])
    assert by_agent["assurance"]["authorship"] == {"author_kind": "agent", "review_bar": "new_skill"}

    declared = upload(client, TWEAK + BYPASS + "\n\n", as_user("carol", "evaluator"), '{"author_kind": "agent", "agent": "claude-code"}')
    assert declared["capability_change"]["against"] == "full_review_not_human_written"
    refused = client.post("/api/v1/registry/versions", files={"file": ("skill.zip", zip_of(TWEAK + "\n\n\n"))},
                          data={"provenance_json": '{"author_kind": "robot"}'}, headers=as_user("carol", "evaluator"))
    assert refused.status_code == 422


# Decision: no author approves a version: not the person the agent acted for, not whoever registered it, and not an
# agent at all. Another person's approval promotes it.
def test_no_author_approves_an_agent_written_update(client):
    active_skill(client)
    update = upload(client, SKILL + BYPASS, AGENT)
    ack = update["capability_change"]["change_hash"]

    for_dave = promote(client, update, request_approval(client, update["version_id"], "dave"), ack)
    assert for_dave.status_code == 409 and "author of this version" in for_dave.json()["detail"]

    request = client.post(f"/api/v1/registry/versions/{update['version_id']}/approval-requests", headers=as_user("erin", "evaluator")).json()
    agent_decides = client.post(f"/api/v1/approvals/{request['request_id']}/decision", json={"action": "approve"},
                                headers={**AGENT, "x-skillproof-dev-role": "approver"})
    assert agent_decides.status_code == 403
    agent_promotes = client.post(f"/api/v1/registry/versions/{update['version_id']}/promote", json={"approval_request_id": request["request_id"]},
                                 headers={**AGENT, "x-skillproof-dev-role": "approver"})
    assert agent_promotes.status_code == 403

    promoted = promote(client, update, request_approval(client, update["version_id"], "carol"), ack)
    assert promoted.status_code == 200, promoted.text
    assert "provenance_recorded" in [e["action"] for e in promoted.json()["events"]]


# Decision: whoever registered a version cannot approve it, even when someone else asked for the review.
def test_the_registrant_cannot_approve_their_own_version(client):
    version = upload(client, SKILL, as_user("alice", "evaluator"))
    own = promote(client, version, request_approval(client, version["version_id"], "alice"))
    assert own.status_code == 409 and "author of this version" in own.json()["detail"]


# Decision: a token issued to an agent (delegation `act` claim, or an OAuth client registered as an agent) is an agent
# identity, and the person it acts for is kept.
def test_oidc_tokens_for_agents_become_agent_identities():
    plain = OIDCAccessTokenVerifier(OIDCSettings(issuer="https://login.example.test/", audience="skillproof-api",
                                                 jwks_url="https://login.example.test/.well-known/jwks.json", leeway_seconds=0,
                                                 agent_clients=("release-bot-client",)), signing_keys=FakeKeys())
    delegated = plain.verify(make_token(act={"sub": "agent:release-bot"}))
    assert (delegated.user_id, delegated.actor_kind, delegated.on_behalf_of) == ("agent:release-bot", "agent", "user-123")
    client_agent = plain.verify(make_token(client_id="release-bot-client"))
    assert client_agent.actor_kind == "agent" and client_agent.on_behalf_of is None
    person = plain.verify(make_token())
    assert person.actor_kind == "human"
    with pytest.raises(Exception, match="act"):
        plain.verify(make_token(act="agent"))


# Decision: an attestation that a person wrote a version counts only from a token whose interactive sign-in is recent;
# a token signed in hours ago, or with no sign-in time, could be an agent running on the person's token, so the
# version is recorded as unknown and reviewed as a new skill.
def test_human_attestation_needs_a_recent_interactive_sign_in():
    import time

    verifier = OIDCAccessTokenVerifier(OIDCSettings(issuer="https://login.example.test/", audience="skillproof-api",
                                                    jwks_url="https://login.example.test/.well-known/jwks.json", leeway_seconds=0),
                                       signing_keys=FakeKeys())
    now = int(time.time())
    fresh = verifier.verify(make_token(auth_time=now - 60))
    stale = verifier.verify(make_token(auth_time=now - 3 * 3600))
    missing = verifier.verify(make_token())
    assert fresh.identity_source == "oidc" and fresh.signed_in_at == now - 60
    assert provenance.resolve(fresh)["author_kind"] == "human"
    stale_record = provenance.resolve(stale)
    assert stale_record["author_kind"] == "unknown" and stale_record["review_bar"] == "new_skill"
    assert "180 minute(s) ago" in " ".join(stale_record["basis"])
    assert provenance.resolve(missing)["author_kind"] == "unknown"
    assert provenance.resolve(stale, {"author_kind": "agent"})["author_kind"] == "agent"  # raising the bar still works
    local = Principal(user_id="alice", tenant_id="t", role="evaluator")
    assert provenance.resolve(local)["author_kind"] == "human"  # development sign-in has no sign-in time to check


# Decision: a server can require a strong sign-in method (amr, e.g. mfa) for a "human-written" attestation; a recent
# password-only sign-in then counts as unknown, and one with the required method counts as human.
def test_human_attestation_can_require_a_strong_sign_in_method(monkeypatch):
    import time

    monkeypatch.setenv("SKILLPROOF_HUMAN_ATTESTATION_AMR", "mfa,hwk")
    verifier = OIDCAccessTokenVerifier(OIDCSettings(issuer="https://login.example.test/", audience="skillproof-api",
                                                    jwks_url="https://login.example.test/.well-known/jwks.json", leeway_seconds=0),
                                       signing_keys=FakeKeys())
    now = int(time.time())
    password = verifier.verify(make_token(auth_time=now - 60, amr=["pwd"]))
    strong = verifier.verify(make_token(auth_time=now - 60, amr=["pwd", "mfa"]))
    assert password.sign_in_methods == ("pwd",)
    record = provenance.resolve(password)
    assert record["author_kind"] == "unknown" and "requires one of ['mfa', 'hwk']" in " ".join(record["basis"])
    assert provenance.resolve(strong)["author_kind"] == "human"
    monkeypatch.delenv("SKILLPROOF_HUMAN_ATTESTATION_AMR")
    assert provenance.resolve(password)["author_kind"] == "human"  # not required by default


def _oidc_person(session="sid-1", signed_in_ago=60, scopes=(), user="alice"):
    import time

    return Principal(user_id=user, tenant_id="local", role="evaluator", identity_source="oidc",
                     signed_in_at=int(time.time()) - signed_in_ago, sign_in_session=session, scopes=tuple(scopes))


# Decision: with one attestation per sign-in, a token that already attested a version (an agent reusing the person's
# fresh token afterwards) cannot attest a second one: that version is recorded as unknown, names the version that used
# the sign-in, and is reviewed as a new skill. A new sign-in attests again.
def test_each_sign_in_attests_one_version(tmp_path, monkeypatch):
    import json

    from skillproof.services import catalogue

    monkeypatch.setenv("SKILLPROOF_HUMAN_ATTESTATION_ONCE", "true")
    governance = GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "registry.db"), approvals=SQLiteApprovalStore(tmp_path / "approvals.db"),
                                  history=EvaluationHistoryStore(tmp_path / "history.db"))
    try:
        def put(principal, text):
            assessment = catalogue.assess_package(governance, principal, {"SKILL.md": text.encode()}, declared=json.loads(EVIDENCE))
            return catalogue.register(governance, principal, assessment)

        first = put(_oidc_person(), SKILL)
        assert first["provenance"]["author_kind"] == "human" and first["provenance"]["attested_sign_in"]
        reused = put(_oidc_person(), TWEAK)  # same sign-in (sid and auth_time) as the first upload
        assert reused["provenance"]["author_kind"] == "unknown"
        assert reused["provenance"]["review_bar"] == "new_skill"
        assert f"already attested version {first['version_id']}" in " ".join(reused["provenance"]["basis"])
        again = put(_oidc_person(session="sid-2"), TWEAK.replace("merged", "squashed"))  # signed in again
        assert again["provenance"]["author_kind"] == "human"
        monkeypatch.delenv("SKILLPROOF_HUMAN_ATTESTATION_ONCE")
        free = put(_oidc_person(), TWEAK.replace("merged", "rebased"))
        assert free["provenance"]["author_kind"] == "human"  # off by default
    finally:
        governance.registry.close()
        governance.approvals.close()


# Decision: two uploads racing on one sign-in cannot both be recorded as human-written: the registry refuses the
# second inside its transaction, so nothing is registered for it.
def test_a_sign_in_cannot_attest_twice_even_in_a_race(tmp_path):
    from skillproof.storage.registry import RegistryError

    registry = SQLiteSkillRegistry(tmp_path / "registry.db")
    try:
        record = provenance.resolve(Principal(user_id="alice", tenant_id="t", role="evaluator"))
        record["attested_sign_in"] = "k" * 40
        report = {"package_fingerprint": "a" * 64, "metadata": {"name": "x"}}
        registry.register("t", report, {"decision": "not_eligible"}, actor_id="alice", provenance=dict(record))
        with pytest.raises(RegistryError, match="already attested"):
            registry.register("t", {**report, "package_fingerprint": "b" * 64}, {"decision": "not_eligible"},
                              actor_id="alice", provenance=dict(record))
        assert registry.attestation_of("t", "k" * 40) is not None
    finally:
        registry.close()


# Decision: a server can require a scope that only a person's own sign-in for attesting requests; a token without it
# (a CLI token, one refreshed without the scope) is recorded as unknown, one with it as human.
def test_human_attestation_can_require_a_dedicated_scope(monkeypatch):
    monkeypatch.setenv("SKILLPROOF_HUMAN_ATTESTATION_SCOPE", "skillproof:attest")
    without = provenance.resolve(_oidc_person(scopes=["openid", "profile"]))
    assert without["author_kind"] == "unknown" and "lacks the scope 'skillproof:attest'" in " ".join(without["basis"])
    assert provenance.resolve(_oidc_person(scopes=["openid", "skillproof:attest"]))["author_kind"] == "human"


# Decision: the verifier carries the sign-in session (sid) and the granted scopes, which the two rules above use.
def test_tokens_carry_sign_in_session_and_scopes():
    import time

    verifier = OIDCAccessTokenVerifier(OIDCSettings(issuer="https://login.example.test/", audience="skillproof-api",
                                                    jwks_url="https://login.example.test/.well-known/jwks.json", leeway_seconds=0),
                                       signing_keys=FakeKeys())
    person = verifier.verify(make_token(auth_time=int(time.time()) - 30, sid="abc", scope="openid skillproof:attest"))
    assert person.sign_in_session == "abc" and person.scopes == ("openid", "skillproof:attest")
    listed = verifier.verify(make_token(scp=["a", "b"]))
    assert listed.scopes == ("a", "b") and listed.sign_in_session is None
