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



class FlakyBaselineGrader:
    """Fails to grade every other baseline output, like the small local grader did on real runs."""

    def __init__(self):
        self.baseline_seen = 0

    def evaluate(self, *, task, output):
        if "unstructured" in output:
            self.baseline_seen += 1
            if self.baseline_seen % 2:
                raise ValueError("grader scored 0 of 1 criteria")
            return Grade(0.4, ["ok"])
        return Grade(0.9, ["ok"])


def test_lift_uses_complete_pairs_and_flags_uneven_failures():
    result = execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.", runner=FakeRunner(), evaluator=FlakyBaselineGrader(), repeats=4, seed=7)
    coverage = result["comparison"]["coverage"]
    assert coverage == {**coverage, "complete_pairs": 2, "total_pairs": 4, "uneven_failures": True}
    assert "warning" in coverage
    # Counting the failed baselines as 0.0 would have reported +70 points; complete pairs give +50.
    assert result["comparison"]["skill_lift_percentage_points"] == 50.0


def test_no_complete_pair_means_no_lift():
    result = execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.", runner=FakeRunner(fail_baseline=True), evaluator=FakeEvaluator(), repeats=2, seed=1)
    assert result["comparison"]["skill_lift_percentage_points"] is None
    assert result["comparison"]["coverage"]["complete_pairs"] == 0


def _pair(task_id, baseline, enabled):
    return ({"task_id": task_id, "score": baseline}, {"task_id": task_id, "score": enabled})


def test_one_improved_task_out_of_three_is_not_called_positive():
    from skillproof.execution import paired_task_uncertainty
    result = paired_task_uncertainty([_pair("a", 0.5, 1.0), _pair("b", 1.0, 1.0), _pair("c", 1.0, 1.0)])
    assert (result["tasks"], result["tasks_improved"], result["tasks_unchanged"]) == (3, 1, 2)
    assert result["sign_flip_p_value"] == 1.0 and result["smallest_possible_p_value"] == 0.25
    assert result["interval_excludes_zero"] is False


def test_repeats_of_one_task_count_once():
    from skillproof.execution import paired_task_uncertainty
    result = paired_task_uncertainty([_pair("a", 0.0, 1.0)] * 5 + [_pair("b", 0.5, 0.5)])
    assert result["tasks"] == 2 and result["per_task_lift_percentage_points"] == {"a": 100.0, "b": 0.0}


def test_consistent_lift_across_many_tasks_is_distinguishable_from_zero():
    from skillproof.execution import paired_task_uncertainty
    result = paired_task_uncertainty([_pair(f"t{i}", 0.4, 0.8 + 0.01 * i) for i in range(8)])
    assert result["tasks_improved"] == 8
    assert result["sign_flip_p_value"] == round(2 / 256, 4)
    assert result["interval_excludes_zero"] is True


def test_interval_alone_is_not_enough_with_few_tasks():
    from skillproof.execution import interpret_lift, paired_task_uncertainty
    paired = paired_task_uncertainty([_pair("a", 0.25, 1.0), _pair("b", 0.25, 1.0), _pair("c", 0.25, 0.75), _pair("d", 1.0, 1.0)])
    assert paired["interval_excludes_zero"] is True and paired["sign_flip_p_value"] == 0.25
    assert interpret_lift(50.0, paired) == "not_distinguishable_from_zero"
    assert interpret_lift(None, paired) == "not_measured"
