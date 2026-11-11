import json
from pathlib import Path

import pytest

from skillproof.cli import main
from skillproof.evaluation import BenchmarkTask
from skillproof.execution import Grade
from skillproof.grader_check import GraderCase, check_grader, read_cases
from skillproof.pilot import load_benchmark

TASK = BenchmarkTask(task_id="t", prompt="Summarize notes", criteria=["has date", "no invented tests"])


class ScriptedGrader:
    """Returns fixed criterion scores per output text; raises for 'boom'."""

    def __init__(self, scores):
        self.scores = scores

    def evaluate(self, *, task, output):
        if output == "boom":
            raise ValueError("grader scored 0 of 2 criteria")
        return Grade(score=0.5, criterion_scores=[{"criterion": c, "score": s, "evidence": f"e-{c}"} for c, s in zip(task.criteria, self.scores[output])])


def test_counts_false_pass_and_false_fail_with_grader_evidence():
    cases = [GraderCase(case_id="a", task_id="t", output="good", expected=[1, 1]),
             GraderCase(case_id="b", task_id="t", output="bad", expected=[0, 0], note="no date, invents tests")]
    report = check_grader([TASK], cases, ScriptedGrader({"good": [0.0, 1.0], "bad": [1.0, 0.0]}))
    assert (report["criterion_judgments"], report["disagreements"], report["false_fail"], report["false_pass"]) == (4, 2, 1, 1)
    assert report["disagreement_rate"] == 0.5
    kinds = {(d["case_id"], d["kind"], d["grader_evidence"]) for d in report["details"]}
    assert kinds == {("a", "false_fail", "e-has date"), ("b", "false_pass", "e-has date")}


def test_grader_failure_is_reported_not_counted_as_a_verdict():
    report = check_grader([TASK], [GraderCase(case_id="x", task_id="t", output="boom", expected=[1, 1])], ScriptedGrader({}))
    assert report["criterion_judgments"] == 0 and report["disagreement_rate"] is None
    assert "0 of 2" in report["grader_failures"][0]["error"]


@pytest.mark.parametrize("expected", [[1], [1, 2]])
def test_labels_must_match_the_criteria(expected):
    with pytest.raises(ValueError, match="one 0/1 label per criterion"):
        check_grader([TASK], [GraderCase(case_id="x", task_id="t", output="o", expected=expected)], ScriptedGrader({}))


def test_example_cases_cover_every_pilot_task_with_a_good_and_a_bad_answer():
    root = Path(__file__).parents[1] / "examples" / "pilot"
    tasks = {t.task_id: t for t in load_benchmark(root / "benchmark.jsonl")}
    cases = read_cases(root / "grader-check-cases.jsonl")
    assert {c.task_id for c in cases} == set(tasks)
    for task_id, task in tasks.items():
        labels = [c.expected for c in cases if c.task_id == task_id]
        assert [1] * len(task.criteria) in labels and any(0 in l for l in labels)


def test_cli_runs_against_a_local_grader(tmp_path):
    from test_ollama import FakeOllama
    server = FakeOllama()
    try:
        root = Path(__file__).parents[1] / "examples" / "pilot"
        out = tmp_path / "check.json"
        code = main(["grader-check", "--provider", "ollama", "--ollama-url", server.url, "--grader-model", "g",
                     "--benchmark", str(root / "benchmark.jsonl"), "--cases", str(root / "grader-check-cases.jsonl"), "--output", str(out)])
    finally:
        server.close()
    report = json.loads(out.read_text(encoding="utf-8"))
    # The fake grader scores every criterion 0.8, so every label-0 criterion is a false pass.
    assert code == 1 and report["false_fail"] == 0 and report["false_pass"] > 0


def test_example_cases_include_a_single_omission_answer_per_task():
    root = Path(__file__).parents[1] / "examples" / "pilot"
    cases = read_cases(root / "grader-check-cases.jsonl")
    subtle = [c for c in cases if c.note.startswith("subtle omission")]
    assert {c.task_id for c in subtle} == {t.task_id for t in load_benchmark(root / "benchmark.jsonl")}
    assert all(c.expected.count(0) <= 2 for c in subtle)
