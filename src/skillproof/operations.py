"""Operational cost and latency summaries for paired experiment records."""
from __future__ import annotations

import math
from collections import defaultdict
from statistics import median
from typing import Any


METRICS = {
    "duration_ms": "latency",
    "input_tokens": "input_tokens",
    "output_tokens": "output_tokens",
    "cost_usd": "cost_usd",
    "grader_duration_ms": "grader_latency",
    "grader_input_tokens": "grader_input_tokens",
    "grader_output_tokens": "grader_output_tokens",
}


def _stats(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"observations": 0, "mean": None, "median": None, "total": None}
    return {
        "observations": len(values),
        "mean": round(sum(values) / len(values), 4),
        "median": round(median(values), 4),
        "total": round(sum(values), 4),
    }


def _paired_delta(records: list[dict[str, Any]], metric: str) -> dict[str, Any]:
    by_trial: dict[str, dict[str, float]] = defaultdict(dict)
    for record in records:
        value = record.get(metric)
        if isinstance(value, (int, float)) and math.isfinite(value):
            by_trial[record["trial_id"]][record["condition"]] = float(value)
    deltas = [pair["skill_enabled"] - pair["baseline"] for pair in by_trial.values() if "baseline" in pair and "skill_enabled" in pair]
    base_values = [pair["baseline"] for pair in by_trial.values() if "baseline" in pair and "skill_enabled" in pair]
    enabled_values = [pair["skill_enabled"] for pair in by_trial.values() if "baseline" in pair and "skill_enabled" in pair]
    mean_delta = sum(deltas) / len(deltas) if deltas else None
    base_mean = sum(base_values) / len(base_values) if base_values else None
    return {
        "paired_observations": len(deltas),
        "mean_absolute_change": round(mean_delta, 4) if mean_delta is not None else None,
        "mean_relative_change_percent": round(mean_delta / base_mean * 100, 2) if mean_delta is not None and base_mean else None,
        "direction": "overhead" if mean_delta is not None and mean_delta > 0 else "reduction" if mean_delta is not None and mean_delta < 0 else "unchanged" if mean_delta == 0 else "insufficient_data",
        "baseline_paired_mean": round(base_mean, 4) if base_mean is not None else None,
        "skill_enabled_paired_mean": round(sum(enabled_values) / len(enabled_values), 4) if enabled_values else None,
    }


def summarize_efficiency(records: list[dict[str, Any]]) -> dict[str, Any]:
    conditions: dict[str, dict[str, Any]] = {}
    overhead: dict[str, Any] = {}
    for condition in ("baseline", "skill_enabled"):
        selected = [record for record in records if record.get("condition") == condition]
        conditions[condition] = {
            label: _stats([float(record[key]) for record in selected if isinstance(record.get(key), (int, float)) and math.isfinite(record[key])])
            for key, label in METRICS.items()
        }
    for key, label in METRICS.items():
        overhead[label] = _paired_delta(records, key)
    return {
        "by_condition": conditions,
        "paired_skill_overhead": overhead,
        "cost_source": "provider_reported",
        "limitations": "Token, latency, and cost fields are optional adapter telemetry. Reported cost is not independently priced or validated. Paired comparisons omit trials missing either condition's metric.",
    }
