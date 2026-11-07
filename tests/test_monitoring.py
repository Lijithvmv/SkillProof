import json
from datetime import datetime, timedelta, timezone

from skillproof.cli import main
from skillproof.history import EvaluationHistoryStore
from skillproof.monitoring import monitor_skill_history


def report(experiment_id, lift=10, benchmark="b", cost=20, measured_models=2, failures=0):
    return {
        "experiment_id": experiment_id,
        "instructions_fingerprint": "a" * 64,
        "benchmark_fingerprint": benchmark * 64,
        "engine_version": "1.4.0",
        "configuration": {"task_count": 2, "repeats": 3},
        "comparison": {"skill_lift_percentage_points": lift},
        "efficiency": {"paired_skill_overhead": {"cost_usd": {"mean_relative_change_percent": cost}}},
        "model_compatibility": {"measured_model_count": measured_models},
        "failure_counts": {"baseline": failures, "skill_enabled": failures},
    }


def test_monitor_reports_healthy_recent_history(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    store.record(report("current"), skill_key="docs-skill")
    result = monitor_skill_history(store, "docs-skill")
    assert result["status"] == "healthy"
    assert result["alerts"] == []
    store.close()


def test_monitor_alerts_negative_lift_failures_and_cost(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    store.record(report("current", lift=-2, cost=150, measured_models=0, failures=2), skill_key="docs-skill")
    result = monitor_skill_history(store, "docs-skill", maximum_failure_rate=0.1, maximum_cost_overhead_percent=100)
    assert result["status"] == "alert"
    assert {item["code"] for item in result["alerts"]} >= {
        "NEGATIVE_SKILL_LIFT", "MODEL_COVERAGE_LOW", "EXECUTION_FAILURE_RATE_HIGH", "COST_OVERHEAD_HIGH"
    }
    store.close()


def test_monitor_detects_stale_evaluation_and_behavioral_regression(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    store.record(report("older", lift=20), skill_key="docs-skill")
    store.record(report("newer", lift=10), skill_key="docs-skill")
    stale_time = datetime.now(timezone.utc) + timedelta(days=45)
    result = monitor_skill_history(store, "docs-skill", now=stale_time, max_age_days=30)
    codes = {item["code"] for item in result["alerts"]}
    assert result["status"] == "alert"
    assert "EVALUATION_STALE" in codes
    assert "BEHAVIORAL_REGRESSION" in codes
    store.close()


def test_missing_history_and_cli_exit_codes(tmp_path):
    database = tmp_path / "history.db"
    store = EvaluationHistoryStore(database)
    assert monitor_skill_history(store, "missing") ["status"] == "needs_attention"
    store.close()
    output = tmp_path / "monitor.json"
    exit_code = main(["monitor", "--history-db", str(database), "--skill-key", "missing", "--output", str(output)])
    assert exit_code == 1
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "needs_attention"


def test_cli_monitor_invalid_threshold_returns_error(tmp_path):
    database = tmp_path / "history.db"
    store = EvaluationHistoryStore(database)
    store.close()
    exit_code = main(["monitor", "--history-db", str(database), "--skill-key", "x", "--maximum-failure-rate", "2", "--output", str(tmp_path / "result.json")])
    assert exit_code == 4
