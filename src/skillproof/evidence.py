"""Behavioural evidence from stored experiments, bound to the exact skill text they ran.

A catalogue version cites experiments by id. Each must be in the tenant's history for that skill and must have run
with this version's SKILL.md (same SHA-256 as the uploaded text); lift counts only when the experiment showed it
(a lift withheld by the calibration gate is not evidence). Several experiments combine: runs add up, models are
counted once, lift and cost are weighted by complete pairs.
"""
from __future__ import annotations

import hashlib
from typing import Any


class EvidenceError(ValueError):
    """Cited experiments cannot support this version."""


def instructions_fingerprint(skill_text: str) -> str:
    return hashlib.sha256(skill_text.encode("utf-8")).hexdigest()


def measured_evidence(records: list[dict[str, Any]], experiment_ids: list[str], skill_text: str) -> dict[str, Any]:
    """AssuranceInput fields measured by the cited experiments, plus where each came from."""
    if not experiment_ids:
        raise EvidenceError("no experiment ids were cited")
    by_id = {record["experiment_id"]: record for record in records}
    missing = [e for e in experiment_ids if e not in by_id]
    if missing:
        raise EvidenceError(f"experiments not found for this skill in this tenant: {', '.join(missing)}")
    expected = instructions_fingerprint(skill_text)
    wrong = [e for e in experiment_ids if by_id[e]["instructions_fingerprint"] != expected]
    if wrong:
        raise EvidenceError(f"experiments ran a different SKILL.md than this version: {', '.join(wrong)}")
    pairs = lift_weight = cost_weight = adherence_weight = 0
    lift_sum = cost_sum = adherence_sum = 0.0
    models: set[str] = set()
    withheld: list[str] = []
    for experiment_id in experiment_ids:
        summary = by_id[experiment_id]["summary"]
        comparison = summary.get("comparison") or {}
        complete = int((comparison.get("coverage") or {}).get("complete_pairs") or 0)
        pairs += complete
        lift = comparison.get("skill_lift_percentage_points")
        if lift is None:
            withheld.append(experiment_id)
        elif complete:
            lift_sum += lift * complete
            lift_weight += complete
        for model in (summary.get("model_compatibility") or {}).get("models", []):
            if model.get("assessment") == "measured":
                models.add(f"{model.get('provider')}/{model.get('model')}")
        overhead = (summary.get("efficiency") or {}).get("paired_skill_overhead") or {}
        cost = (overhead.get("cost_usd") or {}).get("mean_relative_change_percent")
        if cost is None:
            cost = (overhead.get("input_tokens") or {}).get("mean_relative_change_percent")
        if cost is not None and complete:
            cost_sum += cost * complete
            cost_weight += complete
        followed = (comparison.get("adherence") or {}).get("adherence_rate")
        if followed is not None and complete:
            adherence_sum += followed * complete
            adherence_weight += complete
    return {
        "adherence_rate": round(adherence_sum / adherence_weight, 4) if adherence_weight else None,
        "behavioral_lift_pp": round(lift_sum / lift_weight, 2) if lift_weight else None,
        "paired_runs": pairs,
        "measured_models": len(models),
        "cost_overhead_percent": round(cost_sum / cost_weight, 2) if cost_weight else None,
        "provenance": {"source": "measured", "experiment_ids": list(experiment_ids), "instructions_fingerprint": expected,
                       "models": sorted(models), "lift_withheld_by_calibration": withheld},
    }
