import pytest
from pydantic import ValidationError

from skillproof.evaluation import BenchmarkTask, ComparisonRequest, RunScores, compare_runs, validate_benchmark_task


def test_task_validator_flags_exact_skill_phrase_leakage():
    skill = "Always use a typed schema to validate every incoming request before processing it."
    task = BenchmarkTask(
        task_id="api-validation",
        prompt="Create an endpoint. Always use a typed schema to validate every incoming request before processing it.",
        criteria=["Requests are checked"],
        target_behaviors=["validate incoming requests"],
    )
    result = validate_benchmark_task(skill, task)
    assert any(item["code"] == "TASK_SKILL_LEAKAGE" for item in result["findings"])
    assert result["disposition"] == "needs_review"


def test_task_validator_reports_missing_value_declaration_and_ambiguity():
    task = BenchmarkTask(task_id="draft", prompt="Write a production-ready plan as needed.", criteria=["Plan is clear"])
    result = validate_benchmark_task("", task)
    codes = {item["code"] for item in result["findings"]}
    assert "TASK_AMBIGUOUS" in codes
    assert "TASK_VALUE_UNSPECIFIED" in codes


def test_comparison_reports_negative_lift_and_variance():
    result = compare_runs(ComparisonRequest(
        baseline=RunScores(scores=[0.8, 0.9]),
        skill_enabled=RunScores(scores=[0.4, 0.6]),
        pass_threshold=0.7,
    ))
    assert result["skill_lift_percentage_points"] == -35.0
    assert result["interpretation"] == "negative"
    assert result["baseline"]["population_stddev"] == 0.05
    assert result["pass_rate_change_percentage_points"] == -100.0


def test_comparison_rejects_out_of_range_scores():
    with pytest.raises(ValidationError):
        RunScores(scores=[1.2])


def test_evaluation_api_endpoints():
    from fastapi.testclient import TestClient
    from skillproof.api.main import app

    client = TestClient(app)
    task_response = client.post("/api/v1/evaluations/tasks/validate", json={
        "skill_instructions": "Use strict structured output.",
        "task": {"task_id": "json", "prompt": "Create a response", "criteria": ["Contains a result"], "target_behaviors": ["structured output"]},
    })
    assert task_response.status_code == 200
    compare_response = client.post("/api/v1/evaluations/compare", json={
        "baseline": {"scores": [0.5]}, "skill_enabled": {"scores": [0.75]}
    })
    assert compare_response.status_code == 200
    assert compare_response.json()["skill_lift_percentage_points"] == 25.0



def test_criterion_requiring_skill_format_absent_from_prompt_is_flagged():
    from skillproof.evaluation import BenchmarkTask, validate_benchmark_task
    skill = "Return one JSON object with `summary`, `facts` (claim and evidence), and `uncertainties`."
    task = BenchmarkTask(task_id="t", prompt="Summarize the key changes in these release notes.",
                         criteria=["Names version 2.4.1.", "Returns syntactically valid JSON with summary, facts, and uncertainties."])
    codes = {(f["code"], f["severity"]) for f in validate_benchmark_task(skill, task)["findings"]}
    assert ("TASK_CRITERION_REQUIRES_SKILL_FORMAT", "warning") in codes


def test_format_criterion_is_fair_when_the_prompt_asks_for_it():
    from skillproof.evaluation import BenchmarkTask, validate_benchmark_task
    skill = "Return one JSON object with `summary`, `facts`, and `uncertainties`."
    task = BenchmarkTask(task_id="t", prompt="Summarize the release notes as JSON with summary, facts and uncertainties.",
                         criteria=["Returns syntactically valid JSON with summary, facts, and uncertainties."])
    codes = {f["code"] for f in validate_benchmark_task(skill, task)["findings"]}
    assert "TASK_CRITERION_REQUIRES_SKILL_FORMAT" not in codes
    assert "TASK_CRITERION_SKILL_SPECIFIC" not in codes


def test_skill_specific_behaviour_criterion_is_review_not_warning():
    from skillproof.evaluation import BenchmarkTask, validate_benchmark_task
    skill = "For each important claim, include a short exact quotation from the source as evidence for every fact."
    task = BenchmarkTask(task_id="t", prompt="Summarize this customer message for the service team.",
                         criteria=["Notes that the customer reports no data loss.", "Provides source evidence for reported facts."])
    findings = validate_benchmark_task(skill, task)["findings"]
    flagged = [f for f in findings if f["code"].startswith("TASK_CRITERION_")]
    assert [(f["code"], f["severity"]) for f in flagged] == [("TASK_CRITERION_SKILL_SPECIFIC", "info")]
    assert "data loss" not in flagged[0]["evidence"]
