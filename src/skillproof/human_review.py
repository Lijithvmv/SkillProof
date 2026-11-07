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
    for run in experiment.get("runs", []):
        task = task_by_id.get(run.get("task_id"))
        if task is None:
            continue
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
            "grader_score": run.get("score"),
            "grader_evidence": run.get("grader_evidence", []),
            "model": run.get("model"),
            "grader_model": run.get("grader_model"),
            "error": run.get("error"),
        }
    sealed_key["__task_heuristics__"] = task_heuristics
    return {
        "review_samples": samples,
        "annotation_template": annotations,
        "task_review_samples": task_review_samples,
        "task_review_template": task_review_template,
        "sealed_unblinding_key": sealed_key,
        "instructions": "Give reviewers only review_samples and annotation_template. Keep sealed_unblinding_key separate until annotations are complete.",
    }


def compare_score_agreement(
    annotations: list[HumanAnnotation], sealed_key: dict[str, Any], *,
    pass_threshold: float = 0.7, tolerance: float = 0.1,
) -> dict[str, Any]:
    if not 0 <= pass_threshold <= 1 or not 0 <= tolerance <= 1:
        raise ValueError("pass_threshold and tolerance must be in [0, 1]")
    ids = [item.sample_id for item in annotations]
    if len(ids) != len(set(ids)):
        raise ValueError("sample_id values must be unique")
    paired = []
    for annotation in annotations:
        key = sealed_key.get(annotation.sample_id)
        if not key or not isinstance(key.get("grader_score"), (int, float)):
            continue
        paired.append((annotation, float(key["grader_score"]), key))
    if not paired:
        raise ValueError("No annotations match numeric grader scores in the sealed key")

    deltas = [grader - human.human_score for human, grader, _ in paired]
    absolute = [abs(delta) for delta in deltas]
    squared = [delta * delta for delta in deltas]
    within = sum(value <= tolerance for value in absolute)
    true_pass = false_pass = true_fail = false_fail = 0
    groups: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for human, grader, key in paired:
        human_pass = human.human_score >= pass_threshold
        grader_pass = grader >= pass_threshold
        groups[str(key.get("condition") or "unknown")].append((human.human_score, grader))
        if human_pass and grader_pass:
            true_pass += 1
        elif grader_pass:
            false_pass += 1
        elif human_pass:
            false_fail += 1
        else:
            true_fail += 1
    agreements = true_pass + true_fail
    observed = agreements / len(paired)
    human_positive = true_pass + false_fail
    grader_positive = true_pass + false_pass
    human_negative = true_fail + false_pass
    grader_negative = true_fail + false_fail
    expected = (human_positive * grader_positive + human_negative * grader_negative) / (len(paired) ** 2)
    denominator = 1 - expected
    per_condition = {}
    for condition, values in groups.items():
        per_condition[condition] = {
            "samples": len(values),
            "mean_absolute_error": round(sum(abs(g - h) for h, g in values) / len(values), 4),
            "pass_fail_agreement": round(sum((h >= pass_threshold) == (g >= pass_threshold) for h, g in values) / len(values), 4),
        }
    return {
        "sample_count": len(paired),
        "pass_threshold": pass_threshold,
        "score_metrics": {
            "mean_absolute_error": round(sum(absolute) / len(absolute), 4),
            "root_mean_squared_error": round(math.sqrt(sum(squared) / len(squared)), 4),
            "within_tolerance_rate": round(within / len(paired), 4),
            "tolerance": tolerance,
        },
        "pass_fail_metrics": {
            "agreement_rate": round(observed, 4),
            "cohen_kappa": round((observed - expected) / denominator, 4) if denominator else None,
            "confusion_matrix": {
                "human_pass_grader_pass": true_pass,
                "human_fail_grader_pass": false_pass,
                "human_pass_grader_fail": false_fail,
                "human_fail_grader_fail": true_fail,
            },
        },
        "by_condition_after_unblinding": per_condition,
        "limitations": "Agreement is descriptive and depends on reviewer consistency, rubric quality, sample selection, and threshold choice. It does not establish benchmark validity.",
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
