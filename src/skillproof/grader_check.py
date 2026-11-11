"""Grader check: grade answers whose per-criterion verdicts are known, and report where the grader disagrees.

Lift is only as good as the grader that scored it. Human agreement (grader-agreement) is the real measure, but it
needs people. This check is cheaper and narrower: someone writes answers to the benchmark tasks with a known
pass/fail for each criterion (for example one answer that meets every criterion and one that breaks some on
purpose), and the grader grades them. Every criterion where the grader's verdict differs from the label is listed
with the grader's own evidence.

What it shows and what it does not: it catches plain grader mistakes (calling a present fact missing, passing a
broken answer) on the cases written. The cases come from whoever wrote them, often the benchmark author, so a clean
result is an upper bound on grader accuracy, not a measurement of it.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from skillproof.evaluation import BenchmarkTask
from skillproof.execution import OutputEvaluator


class GraderCase(BaseModel):
    case_id: str
    task_id: str
    output: str
    expected: list[int] = Field(description="1 = the answer meets the criterion, 0 = it does not; one per criterion, in task order.")
    note: str = ""


def read_cases(path: str | Path) -> list[GraderCase]:
    cases = [GraderCase.model_validate_json(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if len({c.case_id for c in cases}) != len(cases):
        raise ValueError("case_id values must be unique")
    return cases


def check_grader(tasks: list[BenchmarkTask], cases: list[GraderCase], evaluator: OutputEvaluator, *, pass_mark: float = 0.5) -> dict[str, Any]:
    by_id = {task.task_id: task for task in tasks}
    for case in cases:
        task = by_id.get(case.task_id)
        if task is None:
            raise ValueError(f"case {case.case_id}: unknown task_id {case.task_id}")
        if len(case.expected) != len(task.criteria) or any(v not in (0, 1) for v in case.expected):
            raise ValueError(f"case {case.case_id}: expected needs one 0/1 label per criterion ({len(task.criteria)})")

    judged = 0
    false_pass = false_fail = 0
    per_criterion: dict[str, dict[str, Any]] = {}
    disagreements: list[dict[str, Any]] = []
    failed_cases: list[dict[str, str]] = []
    for case in cases:
        task = by_id[case.task_id]
        try:
            grade = evaluator.evaluate(task=task, output=case.output)
        except Exception as exc:  # a grader failure is a result too
            failed_cases.append({"case_id": case.case_id, "error": f"{type(exc).__name__}: {exc}"[:500]})
            continue
        named = {item.get("criterion"): item for item in grade.criterion_scores}
        for index, (criterion, label) in enumerate(zip(task.criteria, case.expected)):
            item = named.get(criterion) or (grade.criterion_scores[index] if index < len(grade.criterion_scores) else None)
            if item is None:
                failed_cases.append({"case_id": case.case_id, "error": f"no score for criterion: {criterion}"})
                continue
            verdict = int(float(item["score"]) >= pass_mark)
            judged += 1
            stats = per_criterion.setdefault(f"{task.task_id}: {criterion}", {"judged": 0, "disagreements": 0})
            stats["judged"] += 1
            if verdict != label:
                stats["disagreements"] += 1
                false_pass += verdict == 1
                false_fail += verdict == 0
                disagreements.append({
                    "case_id": case.case_id, "task_id": task.task_id, "criterion": criterion,
                    "expected": label, "grader_score": item["score"], "grader_evidence": item.get("evidence", ""),
                    "kind": "false_pass" if verdict else "false_fail", "case_note": case.note,
                })
    wrong = false_pass + false_fail
    return {
        "method": "grader_check_on_labelled_answers",
        "cases": len(cases),
        "criterion_judgments": judged,
        "disagreements": wrong,
        "disagreement_rate": round(wrong / judged, 4) if judged else None,
        "false_pass": false_pass,
        "false_fail": false_fail,
        "grader_failures": failed_cases,
        "by_criterion": {k: v for k, v in per_criterion.items() if v["disagreements"]},
        "details": disagreements,
        "pass_mark": pass_mark,
        "limitations": (
            "Labels come from whoever wrote the cases, usually the benchmark author; a clean result bounds grader "
            "error on these cases only and does not replace agreement with independent human reviewers."
        ),
    }


def write_json(data: Any, path: str | Path) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
