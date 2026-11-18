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
    result = execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.", runner=runner, evaluator=FakeEvaluator(), repeats=4, seed=7, require_calibration=False)
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
    result = execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.", runner=FakeRunner(), evaluator=FlakyBaselineGrader(), repeats=4, seed=7, require_calibration=False)
    coverage = result["comparison"]["coverage"]
    assert coverage == {**coverage, "complete_pairs": 2, "total_pairs": 4, "uneven_failures": True}
    assert "warning" in coverage
    # Counting the failed baselines as 0.0 would have reported +70 points; complete pairs give +50.
    assert result["comparison"]["skill_lift_percentage_points"] == 50.0


def test_no_complete_pair_means_no_lift():
    result = execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.", runner=FakeRunner(fail_baseline=True), evaluator=FakeEvaluator(), repeats=2, seed=1, require_calibration=False)
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


def test_lift_is_withheld_until_the_grader_passes_calibration():
    from skillproof.grader_check import GraderCase

    run = lambda **kw: execute_experiment(tasks=[TASK], skill_instructions="Always follow the required format.",
                                          runner=FakeRunner(), repeats=2, seed=3, **kw)
    uncalibrated = run(evaluator=FakeEvaluator())["comparison"]
    assert uncalibrated["skill_lift_percentage_points"] is None and uncalibrated["interpretation"] == "grader_not_calibrated"
    assert uncalibrated["withheld_lift_percentage_points"] == 50.0 and uncalibrated["calibration"]["status"] == "not_run"
    good = [GraderCase(case_id="ok", task_id="format-task", output="uses the required format", expected=[1]),
            GraderCase(case_id="broken", task_id="format-task", output="unstructured", expected=[0])]
    class PerCriterion(FakeEvaluator):  # calibration needs a score per criterion, as real graders give
        def evaluate(self, *, task, output):
            grade = super().evaluate(task=task, output=output)
            return Grade(grade.score, grade.evidence, criterion_scores=[{"criterion": task.criteria[0], "score": grade.score}])

    passed = run(evaluator=PerCriterion(), calibration_cases=good)["comparison"]
    assert passed["calibration"]["status"] == "passed" and passed["skill_lift_percentage_points"] == 50.0

    class Lenient:  # passes everything, the failure the calibration set exists to catch
        def evaluate(self, *, task, output):
            return Grade(0.95, ["looks fine"], criterion_scores=[{"criterion": task.criteria[0], "score": 0.95}])

    broken = [GraderCase(case_id=f"b{i}", task_id="format-task", output="unstructured", expected=[0]) for i in range(3)]
    failed = run(evaluator=Lenient(), calibration_cases=broken)["comparison"]
    assert failed["calibration"]["status"] == "failed" and "broken criteria passed" in failed["withheld_reason"]
    assert failed["skill_lift_percentage_points"] is None


def test_checks_score_exactly_and_need_no_calibration():
    from skillproof.checks import Check, CheckedEvaluator, criteria_mix

    task = BenchmarkTask(task_id="total", prompt="Sum the invoice.", checks=[
        Check(kind="number", description="total is 1,250.50", value=r"total[^0-9]*([\d,.]+)", expected=1250.5, tolerance=0.01),
        Check(kind="heading", description="has a Summary heading", value="Summary"),
        Check(kind="not_contains", description="no TODO left", value="TODO"),
        Check(kind="json_equals", description="status is ok", value="status", expected="ok"),
        Check(kind="max_words", description="at most 60 words", limit=60),
    ])
    grade = CheckedEvaluator().evaluate(task=task, output='## Summary\nTotal: 1,250.50\n```json\n{"status": "ok"}\n```')
    assert grade.score == 1.0 and all(item["kind"] == "check" for item in grade.criterion_scores)
    wrong = CheckedEvaluator().evaluate(task=task, output="Total: 1,200\nTODO")
    assert wrong.score == 0.2  # only the word limit holds
    assert criteria_mix([task]) == {"checks": 5, "judged_criteria": 0, "check_share": 1.0}

    class Runner:
        def run(self, *, prompt, context, skill_instructions):
            text = '## Summary\nTotal: 1,250.50\n{"status": "ok"}' if skill_instructions else "Total: 1,000"
            return AgentResult(output=text, provider="fake", model="m", duration_ms=1)

    result = execute_experiment(tasks=[task], skill_instructions="Sum carefully.", runner=Runner(), evaluator=CheckedEvaluator(), repeats=2)
    assert result["comparison"]["calibration"]["status"] == "not_needed"
    assert result["comparison"]["skill_lift_percentage_points"] == 60.0  # baseline passes 2 of 5 checks


def test_mixed_task_asks_the_judge_only_about_criteria():
    from skillproof.checks import Check, CheckedEvaluator

    seen = []

    class Judge:
        def evaluate(self, *, task, output):
            seen.append((list(task.criteria), list(task.checks)))
            return Grade(1.0, [], criterion_scores=[{"criterion": task.criteria[0], "score": 1.0, "evidence": "clear"}])

    task = BenchmarkTask(task_id="m", prompt="p", criteria=["Explains the trade-off clearly"],
                         checks=[Check(kind="contains", description="names the API", value="GraphQL")])
    grade = CheckedEvaluator(Judge()).evaluate(task=task, output="REST only")
    assert seen == [(["Explains the trade-off clearly"], [])] and grade.score == 0.5
    with pytest.raises(ValueError, match="no judge"):
        CheckedEvaluator().evaluate(task=task, output="x")
    with pytest.raises(ValueError, match="criterion or check"):
        BenchmarkTask(task_id="e", prompt="p")
