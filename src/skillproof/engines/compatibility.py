"""Cross-model skill lift and consistency summaries from execution records."""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any


def _stats(scores: list[float], threshold: float) -> dict[str, Any]:
    if not scores:
        return {"runs": 0, "mean_score": None, "population_stddev": None, "pass_rate": None}
    mean = sum(scores) / len(scores)
    variance = sum((score - mean) ** 2 for score in scores) / len(scores)
    return {
        "runs": len(scores),
        "mean_score": round(mean, 4),
        "population_stddev": round(math.sqrt(variance), 4),
        "pass_rate": round(sum(score >= threshold for score in scores) / len(scores), 4),
    }


def analyze_model_compatibility(
    records: list[dict[str, Any]], *, pass_threshold: float = 0.7,
    minimum_pairs: int = 3, sensitivity_threshold_pp: float = 15.0,
) -> dict[str, Any]:
    groups: dict[tuple[str, str], dict[str, dict[str, dict[str, float]]]] = defaultdict(lambda: defaultdict(dict))
    for record in records:
        provider, model = record.get("provider"), record.get("model")
        score, condition, trial_id = record.get("score"), record.get("condition"), record.get("trial_id")
        if not provider or not model or condition not in {"baseline", "skill_enabled"}:
            continue
        if not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
            continue
        groups[(provider, model)][condition][str(trial_id)] = {"score": float(score)}

    models = []
    findings: list[dict[str, str]] = []
    measured_lifts: list[tuple[str, float]] = []
    for (provider, model), conditions in sorted(groups.items()):
        baseline = list(conditions["baseline"].values())
        enabled = list(conditions["skill_enabled"].values())
        paired = set(conditions["baseline"]) & set(conditions["skill_enabled"])
        base_scores = [item["score"] for item in baseline]
        enabled_scores = [item["score"] for item in enabled]
        paired_base = [conditions["baseline"][trial]["score"] for trial in sorted(paired)]
        paired_enabled = [conditions["skill_enabled"][trial]["score"] for trial in sorted(paired)]
        lift = (sum(paired_enabled) - sum(paired_base)) / len(paired) if paired else None
        key = f"{provider}/{model}"
        if lift is not None and len(paired) >= minimum_pairs:
            measured_lifts.append((key, lift))
        if lift is not None and len(paired) >= minimum_pairs and lift < 0:
            findings.append({"code": "SKILL_REGRESSION_ON_MODEL", "severity": "warning", "message": "Skill-enabled mean is lower than baseline for this model.", "evidence": f"{key}: {lift * 100:.2f} percentage points across {len(paired)} paired trials"})
        models.append({
            "provider": provider,
            "model": model,
            "baseline": _stats(base_scores, pass_threshold),
            "skill_enabled": _stats(enabled_scores, pass_threshold),
            "paired_trials": len(paired),
            "skill_lift_percentage_points": round(lift * 100, 2) if lift is not None else None,
            "pass_rate_change_percentage_points": round((_stats(enabled_scores, pass_threshold)["pass_rate"] - _stats(base_scores, pass_threshold)["pass_rate"]) * 100, 2) if base_scores and enabled_scores else None,
            "assessment": "measured" if len(paired) >= minimum_pairs else "insufficient_data",
        })

    if len(measured_lifts) >= 2:
        spread = (max(value for _, value in measured_lifts) - min(value for _, value in measured_lifts)) * 100
        if spread >= sensitivity_threshold_pp:
            findings.append({"code": "MODEL_SENSITIVE_SKILL_LIFT", "severity": "info", "message": "Skill lift differs materially across evaluated models.", "evidence": f"Lift spread: {spread:.2f} percentage points across {len(measured_lifts)} models"})
    else:
        spread = None
    return {
        "method": "paired_execution_record_aggregation",
        "minimum_pairs_for_assessment": minimum_pairs,
        "models": models,
        "measured_model_count": len(measured_lifts),
        "lift_spread_percentage_points": round(spread, 2) if spread is not None else None,
        "findings": findings,
        "limitations": "Model identifiers come from the injected runner and are not mapped to capability tiers. Results require paired runs with matching provider/model labels; small samples are descriptive only.",
    }
