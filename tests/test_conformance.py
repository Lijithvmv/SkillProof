"""Conformance: claims from a SKILL.md, a draft benchmark that tests them, adherence per claim, and the catalogue
citing that run evidence. Each test names the decision it changes."""
import json

from skillproof.authorization import Principal
from skillproof.catalogue_import import import_installed
from skillproof.checks import CheckedEvaluator
from skillproof.conformance import adherence, draft_benchmark, extract_claims
from skillproof.evaluation import BenchmarkTask
from skillproof.execution import AgentResult, execute_experiment
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance
from test_catalogue_import import governance_for, write_skill

SKILL = """---
name: incident-summary
description: Writes an incident summary. Never invents a root cause. Use when someone says "summarise this incident" or "write up the outage".
---

# Incident summary

### Step 1 — State the impact

Give the customer impact first, in numbers where the source has
them. If the source gives no root cause, say "root cause not yet known" and
never guess one.

### Step 2 — List the timeline

- Always list times in UTC.
"""


def test_claims_join_wrapped_rule_sentences_and_keep_requests():
    # Decision: which claims a benchmark tests. A rule wrapped over two lines must stay one claim, not two halves.
    claims = extract_claims(SKILL)
    texts = [c["text"] for c in claims["claims"]]
    assert "Never invents a root cause." in texts
    assert any(t.startswith('If the source gives no root cause, say "root cause not yet known" and never guess one') for t in texts)
    assert "Always list times in UTC." in texts
    assert {"State the impact", "List the timeline"} <= set(texts)
    assert claims["triggers"] == ["summarise this incident", "write up the outage"]


def test_draft_keeps_only_valid_checks_tied_to_a_known_claim():
    # Decision: what counts as conformance evidence. A check for an unknown claim or with a broken pattern is dropped.
    claims = extract_claims(SKILL)
    known = claims["claims"][0]["id"]
    reply = {"tasks": [{"prompt": "Our API was down for 40 minutes, write it up", "context": "Outage 09:10-09:50 UTC, 1,200 failed calls.",
                        "claims": [known], "checks": [
                            {"kind": "contains", "claim": known, "description": "quotes the failed calls", "value": "1,200 failed calls"},
                            {"kind": "regex", "claim": known, "description": "broken pattern", "value": "(unclosed"},
                            {"kind": "contains", "claim": "C99", "description": "made-up claim", "value": "x"}]}]}
    drafted = draft_benchmark(SKILL, claims, lambda prompt, schema: json.dumps(reply), tasks=1, self_test=False)
    [task] = drafted["tasks"]
    assert [c.description for c in task.checks] == [f"[{known}] quotes the failed calls"]
    reasons = [d["reason"] for d in drafted["dropped"]]
    assert len(reasons) == 2 and sum(r.startswith("unknown claim id") for r in reasons) == 1
    assert drafted["reviews"][0]["task_id"] == "t1"


def test_drafted_phrase_must_be_short_and_come_from_the_scenario_or_the_claim():
    # Decision: which drafted checks count. The first real drafts demanded whole sentences no answer contains.
    from skillproof.conformance import ungrounded
    context = "Bore measured 0.512 in on part 4410-B."
    claim = "If the requirement cannot be located, flag the NCR as blocking and say what was searched."
    assert ungrounded("contains", "0.512", context, claim) is None  # a fact from the scenario
    assert ungrounded("contains", "blocking", context, claim) is None  # the claim's own term
    assert "words" in ungrounded("contains", "Part A found in 10 units at location X today now", context, claim)
    assert "neither" in ungrounded("contains", "location X: not checked", context, claim)
    assert ungrounded("regex", r"\b\d+\b", context, claim) is None  # patterns are judged by the self-test


def test_self_test_drops_checks_an_answer_following_the_claim_fails():
    # Decision: a check that even a skill-following answer cannot pass is measuring the drafter, not the skill.
    claims = extract_claims(SKILL)
    known = claims["claims"][0]["id"]
    scenario = {"tasks": [{"prompt": "Write up the outage", "context": "1,200 failed calls between 09:10 and 09:50 UTC.",
                           "claims": [known], "checks": [
                               {"kind": "contains", "claim": known, "description": "quotes the failed calls", "value": "1,200 failed calls"},
                               {"kind": "regex", "claim": known, "description": "names a cause", "value": "(?i)caused by"}]}]}
    ideal = {"answer": "Impact: 1,200 failed calls from 09:10 to 09:50 UTC. Root cause not yet known."}
    ask = lambda prompt, schema: json.dumps(ideal if "answer" in schema["properties"] else scenario)  # noqa: E731
    drafted = draft_benchmark(SKILL, claims, ask, tasks=1)
    [task] = drafted["tasks"]
    assert [c.value for c in task.checks] == ["1,200 failed calls"]
    assert any("fails it" in d["reason"] for d in drafted["dropped"])


class Runner:
    """Follows the skill's rule only when the skill is loaded."""

    def run(self, *, prompt, context, skill_instructions):
        text = "Impact: 1,200 failed calls. root cause not yet known." if skill_instructions else "Impact: the database crashed."
        return AgentResult(output=text, provider="fake", model="fake-1", duration_ms=1,
                           input_tokens=150 if skill_instructions else 100, output_tokens=20, cost_usd=0.0)


def experiment_for(skill_text):
    task = BenchmarkTask(task_id="t1", prompt="Write up the outage", context="1,200 failed calls, no cause found yet.",
                         checks=[{"kind": "contains", "description": "[C1] does not invent a cause", "value": "root cause not yet known"}],
                         target_behaviors=["C1"])
    report = execute_experiment(tasks=[task], skill_instructions=skill_text, runner=Runner(), evaluator=CheckedEvaluator(), repeats=3)
    report["comparison"]["adherence"] = adherence(report, extract_claims(skill_text))
    return report


def test_adherence_is_measured_per_claim_with_and_without_the_skill():
    # Decision: whether the skill does what it says. Here it does with the skill loaded and not without.
    result = experiment_for(SKILL)["comparison"]["adherence"]
    assert result["adherence_rate"] == 1.0 and result["baseline_rate"] == 0.0
    assert result["per_claim"][0]["claim"] == "C1" and result["per_claim"][0]["text"] == "Never invents a root cause."
    assert result["broken_with_skill"] == []


def test_assurance_fails_a_skill_that_breaks_its_own_claims_and_ignores_unmeasured_adherence():
    # Decision: approvable or not. Measured adherence below the minimum fails; no measurement adds no gate.
    base = dict(structural_score=90, instruction_quality_score=90, security_score=100, behavioral_lift_pp=10,
                paired_runs=6, measured_models=1, cost_overhead_percent=20)
    assert evaluate_assurance(AssuranceInput(**base))["decision"] == "eligible_for_human_approval"
    failed = evaluate_assurance(AssuranceInput(**base, adherence_rate=0.4))
    assert failed["decision"] == "not_ready" and any(g["code"] == "CLAIM_ADHERENCE" and g["status"] == "fail" for g in failed["gates"])
    assert evaluate_assurance(AssuranceInput(**base, adherence_rate=0.9), AssurancePolicy())["decision"] == "eligible_for_human_approval"


def installed_text(root):
    # The exact bytes on disk (line endings included), decoded as the catalogue reads them.
    return (root / "skills" / "incident-summary" / "SKILL.md").read_bytes().decode("utf-8-sig")


def test_catalogue_import_cites_runs_recorded_for_the_exact_skill_md(tmp_path):
    # Decision: an installed skill stops at insufficient_evidence only while nobody has measured it.
    root = tmp_path / ".claude"
    write_skill(root / "skills" / "incident-summary", SKILL)
    text = installed_text(root)
    governance = governance_for(tmp_path)
    evaluator = Principal(user_id="skill-evaluation", tenant_id="local", role="evaluator")
    stored = governance.record_evaluation(evaluator, experiment_for(text), skill_key="incident-summary")
    governance.record_evaluation(evaluator, experiment_for(SKILL + "\nchanged\n"), skill_key="incident-summary")  # another text

    result = import_installed(governance, Principal(user_id="installed-skill-import", tenant_id="local", role="evaluator"), [root])
    [row] = result["registered"]
    assert row["evidence"] == "measured"
    version = governance.get_skill(evaluator, row["version_id"])
    evidence = version["assurance"]["evidence"]
    assert evidence["experiment_ids"] == [stored["experiment_id"]]  # only the run on this exact SKILL.md
    gates = {g["code"]: g["status"] for g in version["assurance"]["gates"]}
    assert gates["BEHAVIORAL_LIFT"] == "pass" and gates["CLAIM_ADHERENCE"] == "pass" and gates["PAIRED_RUN_COUNT"] == "pass"


def test_runs_recorded_after_registration_reassess_the_waiting_version(tmp_path):
    # Decision: a version registered before its runs is no longer stuck at insufficient_evidence.
    root = tmp_path / ".claude"
    write_skill(root / "skills" / "incident-summary", SKILL)
    governance = governance_for(tmp_path)
    importer = Principal(user_id="installed-skill-import", tenant_id="local", role="evaluator")
    first = import_installed(governance, importer, [root])
    assert first["registered"][0]["assurance_decision"] == "insufficient_evidence"
    stored = governance.record_evaluation(Principal(user_id="e", tenant_id="local", role="evaluator"),
                                          experiment_for(installed_text(root)), skill_key="incident-summary")
    again = import_installed(governance, importer, [root])
    assert again["evidence_not_attached"] == []
    [row] = again["reassessed"]  # still waiting for a decision, so assessed again on the new run
    assert row["experiments"] == [stored["experiment_id"]] and row["assurance_decision"] != "insufficient_evidence"
    version = governance.get_skill(importer, row["version_id"])
    assert version["assurance"]["evidence"]["source"] == "measured" and version["events"][-1]["action"] == "reassessed"
