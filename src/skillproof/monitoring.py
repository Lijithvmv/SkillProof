"""Scheduled health checks over persisted evaluation history."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from skillproof.history import EvaluationHistoryStore


def monitor_skill_history(
    store: EvaluationHistoryStore, skill_key: str, *, max_age_days: float = 30,
    minimum_models: int = 1, maximum_failure_rate: float = 0.1,
    maximum_cost_overhead_percent: float = 100, regression_threshold_pp: float = 5,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not skill_key.strip():
        raise ValueError("skill_key is required")
    if max_age_days < 0 or minimum_models < 1 or not 0 <= maximum_failure_rate <= 1 or maximum_cost_overhead_percent < 0 or regression_threshold_pp < 0:
        raise ValueError("monitor thresholds are outside supported ranges")
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    history = store.list_history(skill_key, limit=500)
    alerts: list[dict[str, str]] = []
    latest = history[0] if history else None

    def alert(code: str, severity: str, message: str, evidence: str) -> None:
        alerts.append({"code": code, "severity": severity, "message": message, "evidence": evidence})

    if latest is None:
        alert("EVALUATION_HISTORY_MISSING", "warning", "No evaluation history exists for this skill key.", skill_key)
    else:
        created = datetime.fromisoformat(latest["created_at"].replace("Z", "+00:00"))
        age_days = max(0.0, (current_time - created).total_seconds() / 86400)
        if age_days > max_age_days:
            alert("EVALUATION_STALE", "warning", "Latest evaluation is older than the configured freshness window.", f"age_days={age_days:.2f}, maximum={max_age_days}")

        summary = latest["summary"]
        comparison = summary.get("comparison", {})
        lift = comparison.get("skill_lift_percentage_points")
        if isinstance(lift, (int, float)) and lift < 0:
            alert("NEGATIVE_SKILL_LIFT", "critical", "Latest evaluation shows the skill reduced measured performance.", f"lift_pp={lift}")

        compatibility = summary.get("model_compatibility", {})
        model_count = compatibility.get("measured_model_count", 0)
        if model_count < minimum_models:
            alert("MODEL_COVERAGE_LOW", "warning", "Latest evaluation does not meet minimum measured model coverage.", f"measured={model_count}, minimum={minimum_models}")

        config = summary.get("configuration", {})
        runs_per_condition = config.get("task_count", 0) * config.get("repeats", 0)
        failures = summary.get("failure_counts", {})
        total_failures = failures.get("baseline", 0) + failures.get("skill_enabled", 0)
        denominator = runs_per_condition * 2
        if denominator:
            failure_rate = total_failures / denominator
            if failure_rate > maximum_failure_rate:
                alert("EXECUTION_FAILURE_RATE_HIGH", "warning", "Latest evaluation exceeds the configured provider/execution failure rate.", f"rate={failure_rate:.4f}, maximum={maximum_failure_rate}")

        cost = summary.get("efficiency", {}).get("paired_skill_overhead", {}).get("cost_usd", {})
        cost_change = cost.get("mean_relative_change_percent")
        if cost_change is not None and cost_change > maximum_cost_overhead_percent:
            alert("COST_OVERHEAD_HIGH", "warning", "Latest evaluation exceeds the configured provider-reported cost overhead.", f"overhead_percent={cost_change}, maximum={maximum_cost_overhead_percent}")

        regression = store.regression_status(skill_key, threshold_pp=regression_threshold_pp)
        if regression["status"] == "regression":
            alert("BEHAVIORAL_REGRESSION", "critical", "Skill lift declined beyond the configured threshold on the same benchmark.", f"change_pp={regression['change_percentage_points']}, threshold_pp={regression_threshold_pp}")

    alerts.sort(key=lambda item: (0 if item["severity"] == "critical" else 1, item["code"]))
    status = "alert" if any(item["severity"] == "critical" for item in alerts) else "needs_attention" if alerts else "healthy"
    return {
        "monitor_version": "1.4.0",
        "skill_key": skill_key,
        "status": status,
        "latest_experiment_id": latest["experiment_id"] if latest else None,
        "history_count": len(history),
        "thresholds": {
            "max_age_days": max_age_days,
            "minimum_models": minimum_models,
            "maximum_failure_rate": maximum_failure_rate,
            "maximum_cost_overhead_percent": maximum_cost_overhead_percent,
            "regression_threshold_pp": regression_threshold_pp,
        },
        "alerts": alerts,
        "limitations": "Monitoring evaluates stored summaries when invoked. It does not schedule itself, deliver notifications, or verify telemetry supplied by model adapters.",
    }
