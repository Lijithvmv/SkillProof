"""Benchmark task quality checks and deterministic outcome comparison."""
from __future__ import annotations

import math
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator


class BenchmarkTask(BaseModel):
    task_id: str = Field(min_length=1, max_length=120)
    prompt: str = Field(min_length=1, max_length=20_000)
    criteria: list[str] = Field(min_length=1, max_length=30)
    target_behaviors: list[str] = Field(default_factory=list, max_length=30)
    context: str | None = Field(default=None, max_length=10_000)

    @field_validator("criteria")
    @classmethod
    def criteria_must_not_be_blank(cls, values: list[str]) -> list[str]:
        if any(not item.strip() for item in values):
            raise ValueError("criteria entries cannot be blank")
        return values


class RunScores(BaseModel):
    scores: list[float] = Field(min_length=1, max_length=100)

    @field_validator("scores")
    @classmethod
    def scores_are_unit_interval(cls, values: list[float]) -> list[float]:
        if any(not math.isfinite(value) or not 0 <= value <= 1 for value in values):
            raise ValueError("run scores must be finite values from 0 to 1")
        return values


class ComparisonRequest(BaseModel):
    baseline: RunScores
    skill_enabled: RunScores
    pass_threshold: float = Field(default=0.7, ge=0, le=1)


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _ngrams(text: str, size: int = 6) -> set[tuple[str, ...]]:
    words = _words(text)
    return {tuple(words[i:i + size]) for i in range(max(0, len(words) - size + 1))}


def _finding(code: str, severity: str, message: str, evidence: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message, "evidence": evidence[:500]}


def validate_benchmark_task(skill_instructions: str, task: BenchmarkTask) -> dict[str, Any]:
    """Check obvious lexical leakage and task completeness; not an independent semantic review."""
    findings: list[dict[str, str]] = []
    skill_grams = _ngrams(skill_instructions)
    prompt_grams = _ngrams(task.prompt)
    shared = skill_grams & prompt_grams
    skill_ratio = len(shared) / max(1, len(prompt_grams))
    if shared:
        phrases = [" ".join(gram) for gram in sorted(shared)[:3]]
        severity = "error" if skill_ratio >= 0.15 else "warning"
        findings.append(_finding("TASK_SKILL_LEAKAGE", severity, "Task prompt repeats phrases from the skill instructions; inspect for cueing.", "Shared phrases: " + " | ".join(phrases)))

    criterion_terms = {tuple(_words(c)) for c in task.criteria if len(_words(c)) >= 4}
    prompt_words = _words(task.prompt)
    prompt_text = " ".join(prompt_words)
    exposed = [" ".join(terms) for terms in criterion_terms if " ".join(terms) in prompt_text]
    if exposed:
        findings.append(_finding("TASK_CRITERIA_LEAKAGE", "warning", "The prompt includes wording from one or more grading criteria.", "; ".join(exposed[:3])))

    if not re.search(r"\b(create|write|build|produce|draft|analyze|review|convert|implement|summarize|generate|classify|extract|compare|fix|debug|design|plan|explain|find|identify)\b", task.prompt, re.I):
        findings.append(_finding("TASK_ACTION_UNCLEAR", "warning", "Task prompt does not contain a recognizable action; confirm the requested work is clear.", task.prompt))
    if re.search(r"\b(as appropriate|as needed|etc\.?|best possible|good quality|production[- ]ready)\b", task.prompt, re.I):
        findings.append(_finding("TASK_AMBIGUOUS", "warning", "Task contains subjective wording that may make task completion or grading ambiguous.", task.prompt))
    if not task.target_behaviors:
        findings.append(_finding("TASK_VALUE_UNSPECIFIED", "warning", "No skill-specific target behaviors are declared, so task value cannot be assessed.", task.task_id))
    elif not any(any(term in " ".join(_words(behavior)) for term in _words(task.prompt)) for behavior in task.target_behaviors):
        # This is a weak lexical signal only; do not infer that semantic value is absent.
        findings.append(_finding("TASK_VALUE_REVIEW", "info", "Target behaviors are not visibly represented in the prompt; review whether the task can elicit them.", "; ".join(task.target_behaviors)))

    penalty = sum(35 if item["severity"] == "error" else 15 if item["severity"] == "warning" else 5 for item in findings)
    return {
        "task_id": task.task_id,
        "method": "deterministic_lexical_checks",
        "quality_score": max(0, 100 - penalty),
        "skill_phrase_overlap_ratio": round(skill_ratio, 4),
        "findings": findings,
        "disposition": "needs_review" if findings else "provisionally_clear",
        "limitations": "Lexical checks do not establish semantic leakage, feasibility, or discriminative power. Have an independent reviewer assess tasks before using them as a benchmark.",
    }


def _summary(scores: list[float], threshold: float) -> dict[str, float | int]:
    mean = sum(scores) / len(scores)
    variance = sum((score - mean) ** 2 for score in scores) / len(scores)
    return {
        "runs": len(scores),
        "mean_score": round(mean, 4),
        "population_stddev": round(math.sqrt(variance), 4),
        "pass_rate": round(sum(score >= threshold for score in scores) / len(scores), 4),
    }


def compare_runs(request: ComparisonRequest) -> dict[str, Any]:
    baseline = _summary(request.baseline.scores, request.pass_threshold)
    enabled = _summary(request.skill_enabled.scores, request.pass_threshold)
    lift = enabled["mean_score"] - baseline["mean_score"]
    return {
        "metric_version": "0.4.0",
        "pass_threshold": request.pass_threshold,
        "baseline": baseline,
        "skill_enabled": enabled,
        "skill_lift_percentage_points": round(lift * 100, 2),
        "relative_improvement_percent": round(lift / baseline["mean_score"] * 100, 2) if baseline["mean_score"] else None,
        "pass_rate_change_percentage_points": round((enabled["pass_rate"] - baseline["pass_rate"]) * 100, 2),
        "interpretation": "positive" if lift > 0 else "negative" if lift < 0 else "neutral",
        "limitations": "Scores must come from the same task rubric and comparable agent/model settings. This endpoint summarizes supplied runs; it does not execute an agent or judge outputs.",
    }
