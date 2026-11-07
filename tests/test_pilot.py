import json
from types import SimpleNamespace

from skillproof.evaluation import BenchmarkTask
from skillproof.human_review import HumanAnnotation, compare_decision_agreement, compare_score_agreement, create_blind_review_bundle
from skillproof.openai_adapter import OpenAIResponsesEvaluator, OpenAIResponsesRunner
from skillproof.pilot import load_benchmark, read_manifest


class FakeResponses:
    def __init__(self, values):
        self.values = list(values)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return self.values.pop(0)


class FakeClient:
    def __init__(self, values):
        self.responses = FakeResponses(values)


def response(output, model="fake-model"):
    return SimpleNamespace(
        output_text=output,
        model=model,
        id="resp_fake",
        usage=SimpleNamespace(input_tokens=100, output_tokens=20),
    )


def test_openai_responses_runner_tracks_usage_and_uses_nonstored_calls():
    client = FakeClient([response("baseline output"), response("skill output")])
    runner = OpenAIResponsesRunner(model="explicit-agent-model", client=client)
    baseline = runner.run(prompt="Summarize this", context="Source", skill_instructions=None)
    enabled = runner.run(prompt="Summarize this", context="Source", skill_instructions="Use evidence.")
    assert baseline.output == "baseline output"
    assert baseline.provider == "openai"
    assert baseline.input_tokens == 100
    assert baseline.response_id == "resp_fake"
    assert client.responses.requests[0]["store"] is False
    assert all(item["content"].find("Use evidence") < 0 for item in client.responses.requests[0]["input"])
    assert any("Use evidence" in item["content"] for item in client.responses.requests[1]["input"])
    assert enabled.output == "skill output"


def test_openai_structured_grader_returns_criterion_and_usage_data():
    result = {
        "score": 0.8,
        "evidence": ["Correctly names the release."],
        "criterion_scores": [{"criterion": "Names version", "score": 1.0, "evidence": "2.4.1"}],
    }
    client = FakeClient([response(json.dumps(result), model="explicit-grader-model")])
    task = BenchmarkTask(task_id="release", prompt="Summarize notes", criteria=["Names version"])
    grade = OpenAIResponsesEvaluator(model="explicit-grader-model", client=client).evaluate(task=task, output='{"version":"2.4.1"}')
    assert grade.score == 0.8
    assert grade.criterion_scores[0]["criterion"] == "Names version"
    assert grade.model == "explicit-grader-model"
    assert grade.input_tokens == 100
    request = client.responses.requests[0]
    assert request["store"] is False
    assert request["text"]["format"]["strict"] is True
    assert request["input"][1]["content"].find("candidate_output") >= 0


def test_blind_review_bundle_hides_condition_and_grader_score():
    tasks = [BenchmarkTask(task_id="task-a", prompt="Summarize", criteria=["Accurate"], context="Note")]
    experiment = {"experiment_id": "exp-1", "runs": [
        {"task_id": "task-a", "trial_id": "task-a:1", "condition": "baseline", "score": 0.4, "grader_evidence": [], "model": "model-a", "output": "Answer A"},
        {"task_id": "task-a", "trial_id": "task-a:1", "condition": "skill_enabled", "score": 0.8, "grader_evidence": [], "model": "model-a", "output": "Answer B"},
    ]}
    bundle = create_blind_review_bundle(experiment, tasks)
    assert len(bundle["review_samples"]) == 2
    for sample in bundle["review_samples"]:
        assert "condition" not in sample
        assert "grader_score" not in sample
        assert "model" not in sample
    assert {row["human_score"] for row in bundle["annotation_template"]} == {None}
    assert {item["condition"] for key, item in bundle["sealed_unblinding_key"].items() if not key.startswith("__")} == {"baseline", "skill_enabled"}


def test_task_heuristic_predictions_are_sealed_while_task_prompt_is_blind():
    tasks = [BenchmarkTask(task_id="task-a", prompt="Summarize this source", criteria=["Accurate summary"])]
    reviews = [{"task_id": "task-a", "disposition": "needs_review", "findings": [{"code": "TASK_ACTION_UNCLEAR"}]}]
    bundle = create_blind_review_bundle({"runs": []}, tasks, reviews)
    assert "disposition" not in bundle["task_review_samples"][0]
    assert bundle["task_review_template"][0]["human_decision"] is None
    assert bundle["sealed_unblinding_key"]["__task_heuristics__"]["task-a"]["heuristic_decision"] == "needs_review"


def test_grader_human_score_agreement_metrics():
    annotations = [
        HumanAnnotation(sample_id="a", human_score=0.8, reviewer_id="r1"),
        HumanAnnotation(sample_id="b", human_score=0.4, reviewer_id="r1"),
    ]
    key = {"a": {"grader_score": 0.75, "condition": "skill_enabled"}, "b": {"grader_score": 0.3, "condition": "baseline"}}
    result = compare_score_agreement(annotations, key, pass_threshold=0.7, tolerance=0.1)
    assert result["score_metrics"]["mean_absolute_error"] == 0.075
    assert result["pass_fail_metrics"]["agreement_rate"] == 1
    assert result["pass_fail_metrics"]["cohen_kappa"] == 1
    assert result["by_condition_after_unblinding"]["baseline"]["samples"] == 1


def _failure_experiment():
    runs = [
        {"task_id": "t", "trial_id": f"t:{i}", "condition": "baseline", "score": score, "output": "real answer"}
        for i, score in enumerate([0.9, 0.9, 0.2, 0.2])
    ]
    runs += [
        {"task_id": "t", "trial_id": f"f:{i}", "condition": "skill_enabled", "score": 0.0, "output": None, "error": "APIConnectionError: down"}
        for i in range(4)
    ]
    runs.append({"task_id": "t", "trial_id": "g:1", "condition": "skill_enabled", "score": 0.0, "output": "graded output", "error": "ValidationError: bad grader JSON"})
    return {"runs": runs}


def test_agent_failures_are_not_sent_to_reviewers():
    tasks = [BenchmarkTask(task_id="t", prompt="p", criteria=["c"])]
    bundle = create_blind_review_bundle(_failure_experiment(), tasks)
    assert all(sample["candidate_output"] for sample in bundle["review_samples"])
    assert len(bundle["review_samples"]) == 5
    excluded = bundle["sealed_unblinding_key"]["__excluded_runs__"]
    assert [item["reason"] for item in excluded] == ["agent_failure"] * 4


def test_failed_runs_do_not_inflate_grader_agreement():
    tasks = [BenchmarkTask(task_id="t", prompt="p", criteria=["c"])]
    bundle = create_blind_review_bundle(_failure_experiment(), tasks)
    samples = bundle["review_samples"]
    human_scores = [0.2, 0.9, 0.9, 0.2, 0.0]  # grader disagrees on 2 of 4 real samples; last is the grader failure
    annotations = [HumanAnnotation(sample_id=s["sample_id"], human_score=h, reviewer_id="r1") for s, h in zip(samples, human_scores)]
    result = compare_score_agreement(annotations, bundle["sealed_unblinding_key"])
    assert result["sample_count"] == 4
    assert result["pass_fail_metrics"]["agreement_rate"] == 0.5
    assert result["pass_fail_metrics"]["cohen_kappa"] == 0
    assert result["excluded_annotations"]["failed_run"] == 1
    assert result["excluded_runs_before_review"] == 4


def test_legacy_sealed_key_with_zero_scored_failures_is_still_excluded():
    annotations = [
        HumanAnnotation(sample_id="ok", human_score=0.9, reviewer_id="r1"),
        HumanAnnotation(sample_id="failed", human_score=0.0, reviewer_id="r1"),
    ]
    key = {"ok": {"grader_score": 0.8, "condition": "baseline"}, "failed": {"grader_score": 0.0, "condition": "baseline", "error": "Timeout"}}
    result = compare_score_agreement(annotations, key)
    assert result["sample_count"] == 1
    assert result["excluded_annotations"]["failed_run"] == 1


def test_assurance_or_heuristic_decision_human_agreement():
    result = compare_decision_agreement(
        [
            {"automated": "ready", "human": "ready"},
            {"automated": "review", "human": "ready"},
            {"automated": "blocked", "human": "blocked"},
        ],
        predicted_key="automated", human_key="human", labels=["ready", "review", "blocked"],
    )
    assert result["sample_count"] == 3
    assert result["accuracy"] == 0.6667
    assert result["confusion_matrix_actual_by_predicted"]["ready"]["review"] == 1


def test_candidate_pilot_benchmark_loads_and_is_marked_for_review():
    from pathlib import Path

    root = Path(__file__).parents[1] / "examples" / "pilot"
    tasks = load_benchmark(root / "benchmark.jsonl")
    manifest = read_manifest(root / "benchmark.jsonl")
    assert len(tasks) == 3
    assert manifest["status"] == "candidate_requires_independent_review"

