import pytest

from skillproof.evaluation import BenchmarkTask
from skillproof.execution import AgentResult, Grade, execute_experiment


class FakeRunner:
    def __init__(self, fail_baseline: bool = False):
        self.conditions = []
        self.fail_baseline = fail_baseline

    def run(self, *, prompt, context, skill_instructions):
        enabled = skill_instructions is not None
        self.conditions.append("skill_enabled" if enabled else "baseline")
        if self.fail_baseline and not enabled:
            raise RuntimeError("provider unavailable")
        return AgentResult(
            output="uses the required format" if enabled else "unstructured result",
            provider="fake", model="fake-v1", duration_ms=24 if enabled else 12,
            input_tokens=15 if enabled else 10, output_tokens=9 if enabled else 4,
            cost_usd=0.002 if enabled else 0.001,
        )


class FakeEvaluator:
    def evaluate(self, *, task, output):
        return Grade(0.9 if "required format" in output else 0.4, ["format checked"])


TASK = BenchmarkTask(
    task_id="format-task", prompt="Create a short response.", criteria=["Follows the required format"],
    target_behaviors=["required format"],
)


def test_experiment_runs_paired_repeats_and_measures_lift():
    runner = FakeRunner()
    result = execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.", runner=runner, evaluator=FakeEvaluator(), repeats=4, seed=7)
    assert len(result["runs"]) == 8
    assert len(result["pairs"]) == 4
    assert result["comparison"]["skill_lift_percentage_points"] == 50.0
    assert result["failure_counts"] == {"baseline": 0, "skill_enabled": 0}
    assert {record["model"] for record in result["runs"]} == {"fake-v1"}
    assert result["efficiency"]["paired_skill_overhead"]["latency"]["mean_absolute_change"] == 12.0
    assert result["efficiency"]["paired_skill_overhead"]["latency"]["mean_relative_change_percent"] == 100.0
    assert result["efficiency"]["paired_skill_overhead"]["cost_usd"]["mean_absolute_change"] == 0.001
    assert result["model_compatibility"]["models"][0]["assessment"] == "measured"
    # Each paired repeat uses both conditions; randomized order is retained in invocation order.
    assert sorted(runner.conditions).count("baseline") == 4
    assert sorted(runner.conditions).count("skill_enabled") == 4


def test_failed_provider_call_is_retained_as_failed_zero_score_run():
    result = execute_experiment(tasks=[TASK], skill_instructions="Follow the required format.", runner=FakeRunner(fail_baseline=True), evaluator=FakeEvaluator(), repeats=1)
    failed = next(run for run in result["runs"] if run["condition"] == "baseline")
    assert failed["score"] == 0
    assert failed["error"] == "RuntimeError: provider unavailable"
    assert result["failure_counts"]["baseline"] == 1


def test_duplicate_task_ids_are_rejected():
    with pytest.raises(ValueError, match="unique"):
        execute_experiment(tasks=[TASK, TASK], skill_instructions="Follow the format.", runner=FakeRunner(), evaluator=FakeEvaluator(), repeats=1)


@pytest.mark.parametrize("kwargs", [
    {"tasks": [], "skill_instructions": "x", "repeats": 1},
    {"tasks": [TASK], "skill_instructions": " ", "repeats": 1},
    {"tasks": [TASK], "skill_instructions": "x", "repeats": 0},
])
def test_invalid_experiment_configuration_is_rejected(kwargs):
    kwargs.update(runner=FakeRunner(), evaluator=FakeEvaluator())
    with pytest.raises(ValueError):
        execute_experiment(**kwargs)

