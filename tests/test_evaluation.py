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

