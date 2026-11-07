import sqlite3

import pytest

from skillproof.history import EvaluationHistoryStore


def report(experiment_id, instructions, benchmark, lift, output="sensitive raw output"):
    return {
        "experiment_id": experiment_id,
        "instructions_fingerprint": instructions * 64,
        "benchmark_fingerprint": benchmark * 64,
        "engine_version": "1.1.0",
        "configuration": {"repeats": 3},
        "comparison": {"skill_lift_percentage_points": lift, "pass_rate_change_percentage_points": 5},
        "efficiency": {"paired_skill_overhead": {"latency": {"mean_absolute_change": 10}}},
        "model_compatibility": {"measured_model_count": 1},
        "failure_counts": {"baseline": 0, "skill_enabled": 0},
        "runs": [{"output": output}],
    }


def test_persists_fingerprinted_summary_without_raw_outputs(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    original = report("exp-1", "a", "b", 12)
    saved = store.record(original, skill_key="finance-skill")
    assert saved["skill_key"] == "finance-skill"
    assert len(saved["report_hash"]) == 64
    assert "runs" not in saved["summary"]
    assert "sensitive raw output" not in str(saved)
    assert store.record(original, skill_key="finance-skill")["report_hash"] == saved["report_hash"]
    store.close()


def test_regression_uses_only_same_benchmark_fingerprint(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    store.record(report("exp-old", "a", "b", 20), skill_key="same-skill")
    store.record(report("exp-new", "c", "b", 12), skill_key="same-skill")
    result = store.regression_status("same-skill", threshold_pp=5)
    assert result["status"] == "regression"
    assert result["change_percentage_points"] == -8
    store.close()


def test_changed_benchmark_is_not_compared(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    store.record(report("exp-old", "a", "b", 20), skill_key="same-skill")
    store.record(report("exp-new", "a", "c", 10), skill_key="same-skill")
    assert store.regression_status("same-skill")["status"] == "insufficient_comparable_history"
    store.close()


def test_experiment_id_cannot_be_reused_for_changed_metrics(tmp_path):
    store = EvaluationHistoryStore(tmp_path / "history.db")
    store.record(report("exp-1", "a", "b", 12))
    with pytest.raises(ValueError, match="different summary"):
        store.record(report("exp-1", "a", "b", 99))
    store.close()


def test_history_rows_are_append_only(tmp_path):
    database = tmp_path / "history.db"
    store = EvaluationHistoryStore(database)
    store.record(report("exp-1", "a", "b", 12))
    with sqlite3.connect(database) as direct:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute("DELETE FROM evaluation_history WHERE experiment_id = 'exp-1'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            direct.execute("UPDATE evaluation_history SET skill_key = 'tampered' WHERE experiment_id = 'exp-1'")
    store.close()

