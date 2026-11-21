"""Checks before judges: score what a program can verify exactly, and leave only the rest to a model judge.

A benchmark task can carry typed checks on the output (text present or absent, a pattern, a JSON value, a number
recomputed within a tolerance, a word limit, a required heading). Checks are exact, free and never drift; a judge
misses omissions and changes its mind between runs (local pilot: 6 of 40 labels disagreed, single-omission answers
passed 6 of 8, a temperature-0 regrade flipped 2 of 40). CheckedEvaluator runs the checks itself, asks the judge only
about the free-text criteria, and scores each criterion equally, so a task's score says how much of it was exact.
"""
from __future__ import annotations

import json
import math
import re
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field, model_validator

if TYPE_CHECKING:
    from skillproof.evaluation import BenchmarkTask
    from skillproof.execution import Grade, OutputEvaluator

MAX_OUTPUT = 200_000  # characters a check reads; longer outputs are cut, and the check says so


class Check(BaseModel):
    """One executable assertion on an agent's output."""
    kind: Literal["contains", "not_contains", "regex", "not_regex", "json_equals", "number", "max_words", "min_words", "heading"]
    description: str = Field(min_length=1, max_length=300, description="What the check verifies, shown in reports.")
    value: str | None = Field(default=None, max_length=2000,
                              description="Text, pattern, JSON path (a.b.0), heading text, or a pattern with one group for a number.")
    expected: Any = None
    tolerance: float = Field(default=0, ge=0)
    case_sensitive: bool = False
    limit: int | None = Field(default=None, ge=0, description="Word limit for max_words / min_words.")

    @model_validator(mode="after")
    def _complete(self) -> "Check":
        needs_value = {"contains", "not_contains", "regex", "not_regex", "json_equals", "number", "heading"}
        if self.kind in needs_value and not self.value:
            raise ValueError(f"a {self.kind} check needs value")
        if self.kind in {"max_words", "min_words"} and self.limit is None:
            raise ValueError(f"a {self.kind} check needs limit")
        if self.kind == "number":
            if not isinstance(self.expected, (int, float)) or isinstance(self.expected, bool):
                raise ValueError("a number check needs a numeric expected value")
            if re.compile(self.value).groups != 1:
                raise ValueError("a number check's pattern needs exactly one group around the number")
        if self.kind in {"regex", "not_regex"}:
            re.compile(self.value)
        if self.kind == "json_equals" and self.expected is None:
            raise ValueError("a json_equals check needs expected")
        return self


def _first_json(text: str) -> Any:
    fenced = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.S)
    candidates = [fenced.group(1)] if fenced else []
    decoder = json.JSONDecoder()
    for start, char in enumerate(text):
        if char in "{[":
            candidates.append(text[start:])
            break
    for candidate in candidates:
        try:
            return decoder.raw_decode(candidate.strip())[0]
        except ValueError:
            continue
    raise ValueError("no JSON value in the output")


def run_check(check: Check, output: str) -> tuple[bool, str]:
    """Whether the output passes the check, and the evidence for the verdict."""
    cut = len(output) > MAX_OUTPUT
    text = output[:MAX_OUTPUT]
    note = " (output cut to 200,000 characters)" if cut else ""
    flags = 0 if check.case_sensitive else re.I
    if check.kind in {"contains", "not_contains"}:
        haystack, needle = (text, check.value) if check.case_sensitive else (text.lower(), check.value.lower())
        found = needle in haystack
        passed = found if check.kind == "contains" else not found
        return passed, f"{'found' if found else 'not found'}: {check.value!r}{note}"
    if check.kind in {"regex", "not_regex"}:
        match = re.search(check.value, text, flags | re.M)
        passed = bool(match) if check.kind == "regex" else not match
        return passed, (f"matched {match.group(0)[:120]!r}" if match else f"no match for /{check.value}/") + note
    if check.kind == "heading":
        pattern = r"^\s{0,3}#{1,6}\s+" + re.escape(check.value.strip()) + r"\s*#*\s*$"
        found = re.search(pattern, text, flags | re.M) is not None
        return found, f"heading {check.value!r} {'present' if found else 'missing'}{note}"
    if check.kind in {"max_words", "min_words"}:
        words = len(re.findall(r"\S+", output))
        passed = words <= check.limit if check.kind == "max_words" else words >= check.limit
        return passed, f"{words} words (limit {'≤' if check.kind == 'max_words' else '≥'} {check.limit})"
    if check.kind == "number":
        match = re.search(check.value, text, flags | re.M)
        if not match:
            return False, f"no number found by /{check.value}/{note}"
        raw = match.group(1).replace(",", "").replace("_", "").strip()
        try:
            number = float(raw)
        except ValueError:
            return False, f"{raw!r} is not a number"
        passed = math.isfinite(number) and abs(number - float(check.expected)) <= check.tolerance
        return passed, f"found {number:g}, expected {float(check.expected):g} ± {check.tolerance:g}"
    try:  # json_equals
        value = _first_json(text)
        for part in check.value.split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        return False, f"path {check.value!r} not readable: {exc}"
    passed = value == check.expected
    return passed, f"{check.value} = {json.dumps(value)[:120]}, expected {json.dumps(check.expected)[:120]}"


def criteria_mix(tasks: list["BenchmarkTask"]) -> dict[str, Any]:
    """How much of a benchmark is exact (checks) and how much is judgement (criteria for a model judge)."""
    checks = sum(len(task.checks) for task in tasks)
    judged = sum(len(task.criteria) for task in tasks)
    total = checks + judged
    return {"checks": checks, "judged_criteria": judged, "check_share": round(checks / total, 4) if total else None}


class CheckedEvaluator:
    """Runs a task's checks itself and asks the judge only about its free-text criteria; each criterion counts once."""

    def __init__(self, judge: "OutputEvaluator | None" = None):
        self.judge = judge

    def evaluate(self, *, task: "BenchmarkTask", output: str) -> "Grade":
        from skillproof.execution import Grade

        items: list[dict[str, Any]] = []
        for check in task.checks:
            passed, evidence = run_check(check, output)
            items.append({"criterion": check.description, "kind": "check", "score": 1.0 if passed else 0.0, "evidence": evidence})
        judged = None
        if task.criteria:
            if self.judge is None:
                raise ValueError(f"task {task.task_id} has criteria for a judge but no judge is configured")
            judged = self.judge.evaluate(task=task.model_copy(update={"checks": []}), output=output)
            scores = list(judged.criterion_scores)
            if len(scores) != len(task.criteria):  # a judge that only gives an overall score covers every criterion alike
                scores = [{"criterion": c, "score": judged.score, "evidence": "; ".join(judged.evidence)[:500]} for c in task.criteria]
            for criterion, item in zip(task.criteria, scores, strict=False):
                items.append({"criterion": criterion, "kind": "judge", "score": float(item.get("score", 0)),
                              "evidence": item.get("evidence", "")})
        score = sum(item["score"] for item in items) / len(items)
        return Grade(
            score=round(score, 6), evidence=[f"{i['kind']}: {i['criterion']}: {i['evidence']}" for i in items][:60],
            criterion_scores=items, provider=getattr(judged, "provider", None), model=getattr(judged, "model", None),
            duration_ms=getattr(judged, "duration_ms", None), input_tokens=getattr(judged, "input_tokens", None),
            output_tokens=getattr(judged, "output_tokens", None), response_id=getattr(judged, "response_id", None),
            model_overall_score=getattr(judged, "model_overall_score", None),
        )
