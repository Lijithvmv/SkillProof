"""Blinded human annotation bundles and grader-versus-human agreement metrics."""
from __future__ import annotations

import math
import uuid
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from skillproof.evaluation import BenchmarkTask


class HumanAnnotation(BaseModel):
    sample_id: str
    human_score: float = Field(ge=0, le=1)
    reviewer_id: str = Field(min_length=1, max_length=160)
    rationale: str = Field(default="", max_length=5000)


def create_blind_review_bundle(
    experiment: dict[str, Any], tasks: list[BenchmarkTask],
    task_reviews: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    task_by_id = {task.task_id: task for task in tasks}
    samples: list[dict[str, Any]] = []
    sealed_key: dict[str, Any] = {}
    annotations: list[dict[str, Any]] = []
    task_review_samples = []
    task_review_template = []
    task_heuristics = {}
    reviews_by_id = {item["task_id"]: item for item in (task_reviews or [])}
    for task in tasks:
        task_review_samples.append({"task_id": task.task_id, "prompt": task.prompt, "source_context": task.context, "criteria": task.criteria})
        task_review_template.append({"task_id": task.task_id, "human_decision": None, "reviewer_id": "", "rationale": ""})
        review = reviews_by_id.get(task.task_id)
        if review:
            task_heuristics[task.task_id] = {"heuristic_decision": review.get("disposition"), "finding_codes": [finding.get("code") for finding in review.get("findings", [])]}
    excluded_runs: list[dict[str, Any]] = []
    for run in experiment.get("runs", []):
        task = task_by_id.get(run.get("task_id"))
        if task is None:
            continue
        if not isinstance(run.get("output"), str) or not run["output"].strip():
            # An agent failure has no output to review. Sending a blank sample would let a reviewer's
            # obvious 0 "agree" with the recorded 0.0 failure score and inflate agreement.
            excluded_runs.append({"trial_id": run.get("trial_id"), "condition": run.get("condition"), "reason": "agent_failure", "error": run.get("error")})
            continue
        grader_failed = bool(run.get("error"))
        sample_id = uuid.uuid4().hex
        samples.append({
            "sample_id": sample_id,
            "task_id": task.task_id,
            "prompt": task.prompt,
            "source_context": task.context,
            "criteria": task.criteria,
            "candidate_output": run.get("output") or "",
        })
        annotations.append({"sample_id": sample_id, "human_score": None, "reviewer_id": "", "rationale": ""})
        sealed_key[sample_id] = {
            "trial_id": run.get("trial_id"),
            "condition": run.get("condition"),
            # A grader failure is recorded as 0.0 in the experiment; it is not a grader judgment.
            "grader_score": None if grader_failed else run.get("score"),
            "grader_evidence": run.get("grader_evidence", []),
            "model": run.get("model"),
            "grader_model": run.get("grader_model"),
            "error": run.get("error"),
        }
    sealed_key["__task_heuristics__"] = task_heuristics
    sealed_key["__excluded_runs__"] = excluded_runs
    return {
        "review_samples": samples,
        "annotation_template": annotations,
        "task_review_samples": task_review_samples,
        "task_review_template": task_review_template,
        "sealed_unblinding_key": sealed_key,
        "instructions": "Give reviewers only review_samples and annotation_template. Keep sealed_unblinding_key separate until annotations are complete.",
    }


def _binary_agreement(pairs: list[tuple[bool, bool]]) -> tuple[float, float | None]:
    """Observed agreement and Cohen's kappa for two raters' pass/fail labels."""
    total = len(pairs)
    observed = sum(a == b for a, b in pairs) / total
    a_pass = sum(a for a, _ in pairs) / total
    b_pass = sum(b for _, b in pairs) / total
    expected = a_pass * b_pass + (1 - a_pass) * (1 - b_pass)
    kappa = (observed - expected) / (1 - expected) if expected < 1 else None
    return observed, kappa


def krippendorff_alpha(units: list[list[float]], *, metric: str = "interval") -> float | None:
    """Krippendorff's alpha for any number of raters with missing ratings.

    Each unit is the list of values the raters gave one sample. Units with fewer than two
    values cannot be paired and are ignored. Returns None when alpha is undefined
    (fewer than two pairable values, or no variation at all in the pairable values).
    """
    if metric not in {"interval", "nominal"}:
        raise ValueError("metric must be 'interval' or 'nominal'")

    def delta(a: float, b: float) -> float:
        return (a - b) ** 2 if metric == "interval" else float(a != b)

    pairable = [unit for unit in units if len(unit) >= 2]
    values = [value for unit in pairable for value in unit]
    n = len(values)
    if n < 2:
        return None
    disagreement_observed = sum(
        sum(delta(unit[i], unit[j]) for i in range(len(unit)) for j in range(len(unit)) if i != j) / (len(unit) - 1)
        for unit in pairable
    ) / n
    disagreement_expected = sum(delta(values[i], values[j]) for i in range(n) for j in range(n) if i != j) / (n * (n - 1))
    if disagreement_expected == 0:
        return None
    return 1 - disagreement_observed / disagreement_expected


def _round(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def compare_score_agreement(
    annotations: list[HumanAnnotation], sealed_key: dict[str, Any], *,
    pass_threshold: float = 0.7, tolerance: float = 0.1,
) -> dict[str, Any]:
    if not 0 <= pass_threshold <= 1 or not 0 <= tolerance <= 1:
        raise ValueError("pass_threshold and tolerance must be in [0, 1]")
    seen = [(item.sample_id, item.reviewer_id) for item in annotations]
    if len(seen) != len(set(seen)):
        raise ValueError("Each reviewer may score a sample_id only once")

    by_sample: dict[str, dict[str, float]] = defaultdict(dict)
    grader_by_sample: dict[str, float] = {}
    condition_by_sample: dict[str, str] = {}
    excluded = {"failed_run": 0, "no_grader_score": 0, "not_in_sealed_key": 0}
    for annotation in annotations:
        key = sealed_key.get(annotation.sample_id) if not annotation.sample_id.startswith("__") else None
        if not isinstance(key, dict):
            excluded["not_in_sealed_key"] += 1
            continue
        if key.get("error"):
            # Also catches keys written before failed runs were sealed without a score.
            excluded["failed_run"] += 1
            continue
        score = key.get("grader_score")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            excluded["no_grader_score"] += 1
            continue
        by_sample[annotation.sample_id][annotation.reviewer_id] = annotation.human_score
        grader_by_sample[annotation.sample_id] = float(score)
        condition_by_sample[annotation.sample_id] = str(key.get("condition") or "unknown")
    if not by_sample:
        raise ValueError("No annotations match successful, numerically graded runs in the sealed key")

    reviewers = sorted({reviewer for scores in by_sample.values() for reviewer in scores})
    sample_ids = sorted(by_sample)
    # Grader versus the human consensus: the mean of every reviewer's score for the sample.
    consensus = {sid: sum(by_sample[sid].values()) / len(by_sample[sid]) for sid in sample_ids}
    deltas = [grader_by_sample[sid] - consensus[sid] for sid in sample_ids]
    absolute = [abs(delta) for delta in deltas]
    within = sum(value <= tolerance for value in absolute)
    labels = [(consensus[sid] >= pass_threshold, grader_by_sample[sid] >= pass_threshold) for sid in sample_ids]
    observed, kappa = _binary_agreement(labels)
    matrix = {
        "human_pass_grader_pass": sum(h and g for h, g in labels),
        "human_fail_grader_pass": sum(g and not h for h, g in labels),
        "human_pass_grader_fail": sum(h and not g for h, g in labels),
        "human_fail_grader_fail": sum(not h and not g for h, g in labels),
    }
    groups: dict[str, list[str]] = defaultdict(list)
    for sid in sample_ids:
        groups[condition_by_sample[sid]].append(sid)
    per_condition = {
        condition: {
            "samples": len(ids),
            "mean_absolute_error": round(sum(abs(grader_by_sample[s] - consensus[s]) for s in ids) / len(ids), 4),
            "pass_fail_agreement": round(sum((consensus[s] >= pass_threshold) == (grader_by_sample[s] >= pass_threshold) for s in ids) / len(ids), 4),
        }
        for condition, ids in groups.items()
    }

    grader_vs_each_reviewer = {}
    for reviewer in reviewers:
        ids = [sid for sid in sample_ids if reviewer in by_sample[sid]]
        pairs = [(by_sample[sid][reviewer] >= pass_threshold, grader_by_sample[sid] >= pass_threshold) for sid in ids]
        agree, k = _binary_agreement(pairs)
        grader_vs_each_reviewer[reviewer] = {
            "samples": len(ids),
            "mean_absolute_error": round(sum(abs(grader_by_sample[s] - by_sample[s][reviewer]) for s in ids) / len(ids), 4),
            "agreement_rate": round(agree, 4),
            "cohen_kappa": _round(k),
        }

    return {
        "sample_count": len(sample_ids),
        "reviewer_count": len(reviewers),
        "reviewers": reviewers,
        "human_reference": "mean of all reviewer scores for each sample",
        "excluded_annotations": excluded,
        "excluded_runs_before_review": len(sealed_key.get("__excluded_runs__") or []),
        "pass_threshold": pass_threshold,
        "score_metrics": {
            "mean_absolute_error": round(sum(absolute) / len(absolute), 4),
            "root_mean_squared_error": round(math.sqrt(sum(d * d for d in deltas) / len(deltas)), 4),
            "within_tolerance_rate": round(within / len(sample_ids), 4),
            "tolerance": tolerance,
        },
        "pass_fail_metrics": {
            "agreement_rate": round(observed, 4),
            "cohen_kappa": _round(kappa),
            "confusion_matrix": matrix,
        },
        "grader_vs_each_reviewer": grader_vs_each_reviewer,
        "human_agreement": _human_agreement(by_sample, grader_by_sample, reviewers, pass_threshold),
        "by_condition_after_unblinding": per_condition,
        "limitations": "Agreement is descriptive and depends on reviewer consistency, rubric quality, sample selection, and threshold choice. It does not establish benchmark validity.",
    }


def _human_agreement(
    by_sample: dict[str, dict[str, float]], grader_by_sample: dict[str, float],
    reviewers: list[str], pass_threshold: float,
) -> dict[str, Any]:
    """How much reviewers agree with each other, and whether the grader fits inside that range."""
    shared = sorted(sid for sid, scores in by_sample.items() if len(scores) >= 2)
    if not shared:
        return {
            "multi_reviewed_samples": 0,
            "status": "not_measured",
            "reason": "No sample was scored by two or more reviewers, so there is no human baseline for the grader.",
        }

    pairwise = []
    for index, first in enumerate(reviewers):
        for second in reviewers[index + 1:]:
            ids = [sid for sid in shared if first in by_sample[sid] and second in by_sample[sid]]
            if not ids:
                continue
            pairs = [(by_sample[s][first] >= pass_threshold, by_sample[s][second] >= pass_threshold) for s in ids]
            agree, k = _binary_agreement(pairs)
            pairwise.append({
                "reviewers": [first, second],
                "samples": len(ids),
                "mean_absolute_error": round(sum(abs(by_sample[s][first] - by_sample[s][second]) for s in ids) / len(ids), 4),
                "agreement_rate": round(agree, 4),
                "cohen_kappa": _round(k),
            })

    human_units = [list(by_sample[sid].values()) for sid in shared]
    with_grader_units = [list(by_sample[sid].values()) + [grader_by_sample[sid]] for sid in shared]

    def as_pass(units: list[list[float]]) -> list[list[float]]:
        return [[float(value >= pass_threshold) for value in unit] for unit in units]

    alphas = {
        "humans_only": {
            "score_alpha_interval": _round(krippendorff_alpha(human_units, metric="interval")),
            "pass_fail_alpha_nominal": _round(krippendorff_alpha(as_pass(human_units), metric="nominal")),
        },
        "humans_plus_grader": {
            "score_alpha_interval": _round(krippendorff_alpha(with_grader_units, metric="interval")),
            "pass_fail_alpha_nominal": _round(krippendorff_alpha(as_pass(with_grader_units), metric="nominal")),
        },
    }
    return {
        "multi_reviewed_samples": len(shared),
        "status": "measured",
        "pairwise": pairwise,
        "krippendorff_alpha": alphas,
        "reading": (
            "Compare humans_only with humans_plus_grader on the same samples. If adding the grader as one more "
            "rater lowers alpha, the grader disagrees with reviewers more than they disagree with each other. "
            "Alpha from a small number of samples is unstable."
        ),
    }


def compare_decision_agreement(rows: list[dict[str, str]], *, predicted_key: str, human_key: str, labels: list[str]) -> dict[str, Any]:
    if len(labels) < 2 or len(labels) != len(set(labels)):
        raise ValueError("labels must contain at least two unique decision classes")
    if not rows:
        raise ValueError("At least one decision annotation is required")
    matrix = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    for row in rows:
        predicted, actual = row.get(predicted_key), row.get(human_key)
        if predicted not in matrix or actual not in matrix:
            raise ValueError("decision labels must be declared in labels")
        matrix[actual][predicted] += 1
    total = len(rows)
    accuracy = sum(matrix[label][label] for label in labels) / total
    per_label = {}
    for label in labels:
        tp = matrix[label][label]
        fp = sum(matrix[other][label] for other in labels if other != label)
        fn = sum(matrix[label][other] for other in labels if other != label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        per_label[label] = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0}
    human_marginals = [sum(matrix[label][predicted] for predicted in labels) for label in labels]
    predicted_marginals = [sum(matrix[actual][label] for actual in labels) for label in labels]
    expected = sum(a * b for a, b in zip(human_marginals, predicted_marginals)) / (total * total)
    return {
        "sample_count": total,
        "accuracy": round(accuracy, 4),
        "cohen_kappa": round((accuracy - expected) / (1 - expected), 4) if expected < 1 else None,
        "labels": labels,
        "confusion_matrix_actual_by_predicted": matrix,
        "per_label": per_label,
    }
