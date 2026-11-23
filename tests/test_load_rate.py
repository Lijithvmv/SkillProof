"""Load rate in the decision: a skill is measured against the installed skills it competes with, and a version citing
that run is gated on it. Each test names the decision it guards."""
from types import SimpleNamespace

from skillproof.approvals import SQLiteApprovalStore
from skillproof.authorization import GovernanceAccess, Principal
from skillproof.cli import evaluation as cli_evaluation
from skillproof.engines.activation import SkillCard, measure_activation
from skillproof.engines.checks import CheckedEvaluator
from skillproof.engines.evaluation import BenchmarkTask
from skillproof.engines.execution import AgentResult, execute_experiment
from skillproof.engines.inventory import installed_cards, rank_similar
from skillproof.history import EvaluationHistoryStore
from skillproof.registry import SQLiteSkillRegistry
from skillproof.services import catalogue

SKILL = """---
name: release-notes
description: Write release notes from merged pull requests. Use when asked for release notes or a changelog.
---

1. Read the merged pull requests and write `RELEASE_NOTES.md`.
"""


def card(folder, name, description):
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: {description}\n---\n\nBody.\n", encoding="utf-8")


# Decision: the competitors are the installed skills whose descriptions are closest to the skill (the ones an agent
# would pick instead), never the skill itself.
def test_competitors_are_the_most_similar_installed_skills(tmp_path, monkeypatch):
    root = tmp_path / "skills"
    card(root / "changelog", "changelog-writer", "Write a changelog from merged pull requests and commits.")
    card(root / "pptx", "pptx", "Make slide decks and presentations.")
    card(root / "pdf", "pdf", "Fill and merge PDF forms.")
    card(root / "dup", "release-notes", "Another copy with the same name.")
    pool = installed_cards([root])
    assert [n for n, _ in pool] == ["changelog-writer", "pdf", "pptx", "release-notes"]
    ranked = rank_similar("Write release notes from merged pull requests.", [p for p in pool if p[0] != "release-notes"], 2)
    assert ranked[0]["name"] == "changelog-writer" and len(ranked) == 2 and ranked[0]["similarity"] > ranked[1]["similarity"]

    skill = tmp_path / "release-notes"
    skill.mkdir()
    (skill / "SKILL.md").write_text(SKILL, encoding="utf-8")
    seen = {}

    class Probe:
        def __init__(self, **kwargs):
            pass

        def choose(self, *, request, cards):
            seen["names"] = sorted(c.name for c in cards)
            return "release-notes"

    monkeypatch.setattr(cli_evaluation, "OllamaActivationProbe", Probe)
    args = SimpleNamespace(skill=str(skill), competitors_root=[str(root)], competitors=2, distractor_skills=None, unrelated_tasks=None,
                           model="m", ollama_url="http://127.0.0.1:11434", seed=0, load_repeats=1)
    result = cli_evaluation.measure_load_rate(args, ["Write the release notes for v2."], 20.0)
    assert seen["names"] == ["changelog-writer", "pdf", "release-notes"]  # its own installed copy is not a competitor
    assert result["competitors"]["installed_available"] == 3 and result["relevant"]["activation_rate"] == 1.0
    assert result["expected_lift_percentage_points"] == 20.0 and "records" not in result and result["failure_reasons"] == []


def assurance(decision="eligible_for_human_approval"):
    return {"decision": decision, "gates": []}


# Decision: a skill picked for fewer relevant requests than the floor, or for more unrelated ones than the ceiling, is
# not ready (a blocked version stays blocked); without a load-rate run the gate says so and changes nothing.
def test_the_load_rate_gate():
    low = assurance()
    catalogue.apply_load_rate(low, {"activation_rate": 0.25, "false_activation_rate": 0.0, "candidate_skills": 16})
    assert low["decision"] == "not_ready" and low["gates"][-1]["status"] == "fail" and "25%" in low["gates"][-1]["message"]
    noisy = assurance()
    catalogue.apply_load_rate(noisy, {"activation_rate": 0.9, "false_activation_rate": 0.5, "candidate_skills": 16})
    assert noisy["decision"] == "not_ready" and "unrelated" in noisy["gates"][-1]["message"]
    good = assurance()
    catalogue.apply_load_rate(good, {"activation_rate": 0.9, "false_activation_rate": None, "candidate_skills": 16})
    assert good["decision"] == "eligible_for_human_approval" and good["gates"][-1]["status"] == "pass"
    blocked = assurance("blocked")
    catalogue.apply_load_rate(blocked, {"activation_rate": 0.0, "candidate_skills": 4})
    assert blocked["decision"] == "blocked"
    unmeasured = assurance()
    catalogue.apply_load_rate(unmeasured, None)
    assert unmeasured["decision"] == "eligible_for_human_approval" and unmeasured["gates"][-1]["status"] == "not_measured"


class Echo:
    def run(self, *, prompt, context, skill_instructions):
        return AgentResult(output="Release notes: (#12)", provider="x", model="x", duration_ms=1)


class RarelyPicked:
    def __init__(self):
        self.n = 0

    def choose(self, *, request, cards):
        self.n += 1
        return "release-notes" if self.n % 4 == 0 else "changelog-writer"


# Decision: a version citing an experiment whose load rate is under the floor is registered not ready, with the
# measured rate in its assurance report, and re-assessing it on new runs keeps the gate.
def test_a_cited_load_rate_reaches_the_decision(tmp_path):
    governance = GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "r.db"), approvals=SQLiteApprovalStore(tmp_path / "a.db"),
                                  history=EvaluationHistoryStore(tmp_path / "h.db"))
    evaluator = Principal(user_id="eval", tenant_id="local", role="evaluator")
    tasks = [BenchmarkTask(task_id=f"t{i}", prompt=f"Write the release notes for sprint {i}.",
                           checks=[{"kind": "contains", "description": "keeps #12", "value": "#12"}]) for i in range(2)]
    report = execute_experiment(tasks=tasks, skill_instructions=SKILL, runner=Echo(), evaluator=CheckedEvaluator(None), repeats=2)
    load = measure_activation(target=SkillCard("release-notes", "Write release notes."),
                              distractors=[SkillCard("changelog-writer", "Write a changelog.")],
                              relevant_requests=[t.prompt for t in tasks], unrelated_requests=[], probe=RarelyPicked(), repeats=10)
    load.pop("records")
    report["comparison"]["load_rate"] = load
    governance.record_evaluation(evaluator, report, skill_key="release-notes")
    assessed = catalogue.assess_package(governance, evaluator, {"SKILL.md": SKILL.encode()}, cite=[report["experiment_id"]])
    gate = next(g for g in assessed.assurance["gates"] if g["code"] == "LOAD_RATE")
    assert gate["status"] == "fail" and assessed.assurance["decision"] == "not_ready"
    assert assessed.assurance["load_rate"]["activation_rate"] == 0.25 and assessed.assurance["load_rate"]["experiment_id"] == report["experiment_id"]
    version = catalogue.register(governance, evaluator, assessed)
    assert version["state"] == "not_eligible"

    again = execute_experiment(tasks=tasks, skill_instructions=SKILL, runner=Echo(), evaluator=CheckedEvaluator(None), repeats=2, seed=1)
    governance.record_evaluation(evaluator, again, skill_key="release-notes")  # a later run without a load-rate test
    reassessed = catalogue.reassess_on_runs(governance, evaluator, version, assessed.skill_md)
    assert reassessed is not None
    gates = [g for g in reassessed["assurance"]["gates"] if g["code"] == "LOAD_RATE"]
    assert len(gates) == 1 and gates[0]["status"] == "fail" and reassessed["state"] == "not_eligible"
    governance.registry.close(); governance.approvals.close(); governance.history.close()


# Decision: the standalone load-rate check fails (exit 1) when a close competitor takes the skill's requests, and
# passes when the skill is picked for its own requests and not for its sibling's.
def test_load_rate_command_fails_a_description_that_loses_to_its_competitor(tmp_path, monkeypatch):
    import json

    root = tmp_path / "skills"
    card(root / "create-draft-pr", "create-draft-pr", "Create a draft pull request. Use when the user wants a draft PR.")
    skill = tmp_path / "create-pr"
    card(skill, "create-pr", "Create a pull request. Use when the user wants to open a PR.")
    requests, unrelated = tmp_path / "r.jsonl", tmp_path / "u.jsonl"
    requests.write_text(json.dumps({"prompt": "Open a PR."}) + "\n", encoding="utf-8")
    unrelated.write_text(json.dumps({"prompt": "Open a draft PR."}) + "\n", encoding="utf-8")

    def probe_choosing(rule):
        class Probe:
            def __init__(self, **kwargs):
                pass

            def choose(self, *, request, cards):
                return rule(request)
        return Probe

    args = SimpleNamespace(skill=str(skill), requests=str(requests), unrelated_tasks=str(unrelated), competitors_root=[str(root)],
                           competitors=5, distractor_skills=None, model="m", ollama_url="http://127.0.0.1:11434", seed=0, load_repeats=2)
    monkeypatch.setattr(cli_evaluation, "OllamaActivationProbe", probe_choosing(lambda r: "create-draft-pr"))
    result, code = cli_evaluation.run_load_rate(args)
    assert code == 1 and result["relevant"]["activation_rate"] == 0.0 and result["relevant"]["picked_other_skill"] == 2
    monkeypatch.setattr(cli_evaluation, "OllamaActivationProbe", probe_choosing(lambda r: "create-draft-pr" if "draft" in r else "create-pr"))
    result, code = cli_evaluation.run_load_rate(args)
    assert code == 0 and result["relevant"]["activation_rate"] == 1.0 and result["unrelated"]["false_activation_rate"] == 0.0


# Decision: a choice the model wrote outside the schema is read only when exactly one listed name appears; an answer
# naming two listed skills, or none, stays a failure.
def test_probe_reads_an_off_schema_choice_only_when_unambiguous():
    import pytest

    from skillproof.adapters.ollama import OllamaActivationProbe

    class Client:
        def __init__(self, content):
            self.content = content

        def chat(self, payload):
            return {"model": "m", "message": {"content": self.content}}

    cards = [SkillCard("create-pr", "PR"), SkillCard("create-draft-pr", "draft PR")]
    fenced = '```json\n[\n  {"tool": "create-pr"}\n]\n```'
    assert OllamaActivationProbe(model="m", client=Client(fenced)).choose(request="r", cards=cards) == "create-pr"
    for content in ('[{"tool": "create-pr"}, {"tool": "create-draft-pr"}]', '{"tool": "something-else"}', "no idea"):
        with pytest.raises(RuntimeError):
            OllamaActivationProbe(model="m", client=Client(content)).choose(request="r", cards=cards)


# Decision: a rival that matches the skill's own requests becomes a competitor even when its description shares no
# words with the skill's (word overlap alone misses it); when the embedding model cannot be used, the result says so.
def test_rivals_by_meaning_join_the_competitors(tmp_path, monkeypatch):
    import skillproof.adapters.ollama as ollama

    root = tmp_path / "skills"
    card(root / "auditor", "code-auditor", "Scan a repository and patch findings.")      # no word shared with the skill
    card(root / "pptx", "pptx", "Make slide decks.")
    skill = tmp_path / "review-security"
    card(skill, "review-security", "Review changes with the security subagent.")
    seen = {}

    class Probe:
        def __init__(self, **kwargs):
            pass

        def choose(self, *, request, cards):
            seen["names"] = sorted(c.name for c in cards)
            return "code-auditor"

    class Embedder:
        def __init__(self, **kwargs):
            pass

        def embed(self, texts, prefix=""):
            # "security" requests and the auditor point the same way; everything else is orthogonal.
            return [[1.0, 0.0] if ("auditor" in t or "vulnerab" in t) else [0.0, 1.0] for t in texts]

    monkeypatch.setattr(cli_evaluation, "OllamaActivationProbe", Probe)
    monkeypatch.setattr(ollama, "OllamaEmbedder", Embedder)
    args = SimpleNamespace(skill=str(skill), competitors_root=[str(root)], competitors=1, distractor_skills=None, unrelated_tasks=None,
                           model="m", ollama_url="http://127.0.0.1:11434", seed=0, load_repeats=1, embed_model="e")
    lexical_only = rank_similar("Review changes with the security subagent.", installed_cards([root]), 1)
    assert lexical_only[0]["similarity"] == 0  # word overlap sees nothing
    result = cli_evaluation.measure_load_rate(args, ["Check this diff for vulnerabilities."], None)
    assert "code-auditor" in seen["names"] and result["competitors"]["semantic"]["status"] == "used"
    assert any(c["name"] == "code-auditor" and c.get("request_match") == 1.0 for c in result["competitors"]["used"])
    assert result["relevant"]["activation_rate"] == 0.0 and result["relevant"]["picked_other_skill"] == 1

    class Broken(Embedder):
        def embed(self, texts, prefix=""):
            raise RuntimeError("Could not reach Ollama")

    monkeypatch.setattr(ollama, "OllamaEmbedder", Broken)
    result = cli_evaluation.measure_load_rate(args, ["Check this diff for vulnerabilities."], None)
    assert result["competitors"]["semantic"] == {"status": "unavailable", "reason": "Could not reach Ollama"}


# Decision: a tenant sets its own load-rate thresholds and the gate uses them; only a person with policy.manage can
# change them (never an agent identity), values outside 0..1 are refused, and every change is kept append-only.
def test_tenant_load_rate_thresholds(tmp_path):
    import sqlite3

    from fastapi.testclient import TestClient

    from skillproof.api.main import app

    governance = GovernanceAccess(registry=SQLiteSkillRegistry(tmp_path / "r.db"), approvals=SQLiteApprovalStore(tmp_path / "a.db"),
                                  history=EvaluationHistoryStore(tmp_path / "h.db"))
    app.state.governance = governance
    try:
        client = TestClient(app)
        admin = {"x-skillproof-dev-user": "ada", "x-skillproof-dev-role": "tenant_admin"}
        viewer = {"x-skillproof-dev-user": "vic", "x-skillproof-dev-role": "viewer"}
        agent = {**admin, "x-skillproof-dev-user": "agent:bot", "x-skillproof-dev-actor": "agent"}
        assert client.get("/api/v1/policy/gates", headers=viewer).json()["source"] == "default"
        assert client.put("/api/v1/policy/gates", json={"min_load_rate": 0.9, "max_false_load_rate": 0.1}, headers=viewer).status_code == 403
        assert client.put("/api/v1/policy/gates", json={"min_load_rate": 0.9, "max_false_load_rate": 0.1}, headers=agent).status_code == 403
        assert client.put("/api/v1/policy/gates", json={"min_load_rate": 1.5, "max_false_load_rate": 0.1}, headers=admin).status_code == 422
        put = client.put("/api/v1/policy/gates", json={"min_load_rate": 0.9, "max_false_load_rate": 0.1}, headers=admin)
        assert put.status_code == 200 and put.json()["settings"] == {"min_load_rate": 0.9, "max_false_load_rate": 0.1}
        assert put.json()["source"] == "tenant" and put.json()["updated_by"] == "ada"
    finally:
        app.state.governance = None

    reader = Principal(user_id="eval", tenant_id="local", role="evaluator")
    strict = assurance()
    catalogue.apply_load_rate(strict, {"activation_rate": 0.75, "candidate_skills": 9}, governance.gate_settings(reader)["settings"])
    assert strict["decision"] == "not_ready" and "minimum 90%" in strict["gates"][-1]["message"]
    lenient = assurance()
    catalogue.apply_load_rate(lenient, {"activation_rate": 0.75, "candidate_skills": 9})  # server default floor 50%
    assert lenient["decision"] == "eligible_for_human_approval"
    governance.registry.close(); governance.approvals.close(); governance.history.close()
    with sqlite3.connect(tmp_path / "r.db") as db:
        assert db.execute("SELECT count(*) FROM gate_settings_events").fetchone()[0] == 1
        try:
            db.execute("DELETE FROM gate_settings_events")
            raise AssertionError("history must be append-only")
        except sqlite3.DatabaseError as exc:
            assert "append-only" in str(exc)


# Decision: with an interval, the gate decides only what the data shows. The two real review-security runs (3 of 8,
# 9 of 12) sit on either side of the 50% floor, but the floor lies inside both intervals, so neither may pass or fail
# the version: both are insufficient evidence. A run whose whole interval is clear of the floor passes or fails.
def test_the_gate_respects_the_uncertainty_of_the_run():
    from skillproof.engines.activation import wilson

    for hits, total in ((3, 8), (9, 12)):
        gated = assurance()
        catalogue.apply_load_rate(gated, {"activation_rate": hits / total, "interval_95": wilson(hits, total),
                                          "relevant_trials": total, "candidate_skills": 24,
                                          "requests_lost_to": {"claude-security": [0, 3]}})
        gate = gated["gates"][-1]
        assert gate["status"] == "insufficient_evidence" and gated["decision"] == "insufficient_evidence"
        assert "run more choices" in gate["message"] and "claude-security (2)" in gate["message"]
    clear_fail, clear_pass = assurance(), assurance()
    catalogue.apply_load_rate(clear_fail, {"activation_rate": 0.2, "interval_95": wilson(6, 30), "relevant_trials": 30, "candidate_skills": 9})
    catalogue.apply_load_rate(clear_pass, {"activation_rate": 1.0, "interval_95": wilson(16, 16), "relevant_trials": 16, "candidate_skills": 9,
                                           "false_activation_rate": 0.0, "false_interval_95": wilson(0, 20)})
    assert clear_fail["decision"] == "not_ready" and clear_pass["gates"][-1]["status"] == "pass"
    noisy = assurance()
    catalogue.apply_load_rate(noisy, {"activation_rate": 1.0, "interval_95": wilson(16, 16), "relevant_trials": 16, "candidate_skills": 9,
                                      "false_activation_rate": 0.25, "false_interval_95": wilson(2, 8)})
    assert noisy["gates"][-1]["status"] == "insufficient_evidence"  # 25% unrelated, but 2 of 8 cannot show it is over 20%
