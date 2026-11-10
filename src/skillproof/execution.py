"""Provider-neutral paired execution harness for controlled skill evaluations.

Integrations supply an AgentRunner and OutputEvaluator. SkillProof deliberately
does not execute skill package code; it supplies skill instructions as context
to the configured agent adapter.
"""
from __future__ import annotations

import random
import time
import uuid
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from skillproof.evaluation import BenchmarkTask, ComparisonRequest, RunScores, compare_runs
from skillproof.operations import summarize_efficiency
from skillproof.compatibility import analyze_model_compatibility


@dataclass(frozen=True)
class AgentResult:
    output: str
    provider: str
    model: str
    duration_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    response_id: str | None = None


class AgentRunner(Protocol):
    """Adapter for a single agent call. Implementations own model credentials."""

    def run(self, *, prompt: str, context: str | None, skill_instructions: str | None) -> AgentResult:
        """Run a task; skill_instructions is None for the baseline condition."""
        ...


@dataclass(frozen=True)
class Grade:
    score: float
    evidence: list[str] = field(default_factory=list)
    criterion_scores: list[dict[str, Any]] = field(default_factory=list)
    provider: str | None = None
    model: str | None = None
    duration_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    response_id: str | None = None
    model_overall_score: float | None = None  # the grader's own overall number, kept for audit only


class OutputEvaluator(Protocol):
    def evaluate(self, *, task: BenchmarkTask, output: str) -> Grade:
        """Score an output against the task's criteria on a 0–1 scale."""
        ...


def _run_one(
    *, task: BenchmarkTask, skill_instructions: str | None, runner: AgentRunner,
    evaluator: OutputEvaluator, trial_id: str, condition: str,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        result = runner.run(prompt=task.prompt, context=task.context, skill_instructions=skill_instructions)
    except Exception as exc:  # preserve provider failures as zero-score records
        return {
            "trial_id": trial_id, "task_id": task.task_id, "condition": condition,
            "score": 0.0, "grader_evidence": [], "output": None,
            "provider": None, "model": None, "duration_ms": round((time.perf_counter() - started) * 1000),
            "input_tokens": None, "output_tokens": None, "cost_usd": None, "response_id": None,
            "grader_criterion_scores": [], "grader_provider": None, "grader_model": None,
            "grader_duration_ms": None, "grader_input_tokens": None, "grader_output_tokens": None,
            "grader_response_id": None, "error": f"{type(exc).__name__}: {exc}",
        }

    grader_started = time.perf_counter()
    try:
        grade = evaluator.evaluate(task=task, output=result.output)
        if not 0 <= grade.score <= 1:
            raise ValueError("OutputEvaluator score must be between 0 and 1.")
        grade_error = None
    except Exception as exc:  # preserve failures as evaluation data; do not silently drop a run
        grade = None
        grade_error = f"{type(exc).__name__}: {exc}"
    return {
        "trial_id": trial_id,
        "task_id": task.task_id,
        "condition": condition,
        "score": round(float(grade.score), 6) if grade is not None else 0.0,
        "grader_evidence": grade.evidence if grade is not None else [],
        "output": result.output,
        "provider": result.provider,
        "model": result.model,
        "duration_ms": result.duration_ms,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "cost_usd": result.cost_usd,
        "response_id": result.response_id,
        "grader_criterion_scores": grade.criterion_scores if grade is not None else [],
        "grader_model_overall_score": grade.model_overall_score if grade is not None else None,
        "grader_provider": grade.provider if grade is not None else None,
        "grader_model": grade.model if grade is not None else None,
        "grader_duration_ms": grade.duration_ms if grade is not None and grade.duration_ms is not None else round((time.perf_counter() - grader_started) * 1000),
        "grader_input_tokens": grade.input_tokens if grade is not None else None,
        "grader_output_tokens": grade.output_tokens if grade is not None else None,
        "grader_response_id": grade.response_id if grade is not None else None,
        "error": grade_error,
    }


def execute_experiment(
    *, tasks: list[BenchmarkTask], skill_instructions: str, runner: AgentRunner,
    evaluator: OutputEvaluator, repeats: int = 3, pass_threshold: float = 0.7,
    seed: int = 0,
) -> dict[str, Any]:
    """Run paired baseline/enabled trials and summarize all generated records."""
    if not tasks:
        raise ValueError("At least one benchmark task is required.")
    if len({task.task_id for task in tasks}) != len(tasks):
        raise ValueError("task_id values must be unique within an experiment.")
    if not skill_instructions.strip():
        raise ValueError("skill_instructions cannot be blank.")
    if not 1 <= repeats <= 100:
        raise ValueError("repeats must be between 1 and 100.")
    if not 0 <= pass_threshold <= 1:
        raise ValueError("pass_threshold must be between 0 and 1.")

    experiment_id = str(uuid.uuid4())
    task_payload = [task.model_dump(mode="json") for task in tasks]
    instructions_fingerprint = hashlib.sha256(skill_instructions.encode("utf-8")).hexdigest()
    benchmark_fingerprint = hashlib.sha256(json.dumps(task_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    pairs: list[dict[str, str]] = []
    for task in tasks:
        for repeat in range(repeats):
            trial_id = f"{task.task_id}:{repeat + 1}"
            order = ["baseline", "skill_enabled"]
            if rng.choice((False, True)):
                order.reverse()
            trial_records: dict[str, str] = {}
            for condition in order:
                result = _run_one(
                    task=task,
                    skill_instructions=skill_instructions if condition == "skill_enabled" else None,
                    runner=runner,
                    evaluator=evaluator,
                    trial_id=trial_id,
                    condition=condition,
                )
                records.append(result)
                trial_records[condition] = trial_id
            pairs.append({"task_id": task.task_id, **trial_records})

    baseline_scores = [record["score"] for record in records if record["condition"] == "baseline"]
    enabled_scores = [record["score"] for record in records if record["condition"] == "skill_enabled"]
    comparison = compare_runs(ComparisonRequest(
        baseline=RunScores(scores=baseline_scores),
        skill_enabled=RunScores(scores=enabled_scores),
        pass_threshold=pass_threshold,
    ))
    return {
        "experiment_id": experiment_id,
        "engine_version": "1.7.0",
        "instructions_fingerprint": instructions_fingerprint,
        "benchmark_fingerprint": benchmark_fingerprint,
        "configuration": {"task_count": len(tasks), "repeats": repeats, "pass_threshold": pass_threshold, "order_randomization_seed": seed},
        "pairs": pairs,
        "comparison": comparison,
        "efficiency": summarize_efficiency(records),
        "model_compatibility": analyze_model_compatibility(records, pass_threshold=pass_threshold),
        "failure_counts": {
            "baseline": sum(bool(r["error"]) for r in records if r["condition"] == "baseline"),
            "skill_enabled": sum(bool(r["error"]) for r in records if r["condition"] == "skill_enabled"),
        },
        "runs": records,
        "limitations": "Control only applies to paired task text and this adapter instance. Provider nondeterminism, evaluator bias, shared state, and model setting differences must be controlled by the integration. Review stored outputs for sensitive data before persistence.",
    }
