"""Append-only SQLite storage for evaluation summaries and regression trends."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

class EvaluationHistoryStore:
    """Stores metrics and provenance only; raw model outputs are intentionally omitted."""

    def __init__(self, database: str | Path):
        self.database = str(database)
        if self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.database, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.executescript("""
                CREATE TABLE IF NOT EXISTS evaluation_history (
                    experiment_id TEXT PRIMARY KEY,
                    skill_key TEXT NOT NULL,
                    instructions_fingerprint TEXT NOT NULL,
                    benchmark_fingerprint TEXT NOT NULL,
                    report_hash TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evaluation_history_skill ON evaluation_history(skill_key, created_at DESC);
                CREATE TRIGGER IF NOT EXISTS evaluation_history_no_update
                BEFORE UPDATE ON evaluation_history BEGIN SELECT RAISE(ABORT, 'evaluation history is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS evaluation_history_no_delete
                BEFORE DELETE ON evaluation_history BEGIN SELECT RAISE(ABORT, 'evaluation history is append-only'); END;
            """)

    @staticmethod
    def _valid_fingerprint(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def record(self, report: dict[str, Any], *, skill_key: str | None = None) -> dict[str, Any]:
        experiment_id = report.get("experiment_id")
        instructions_fp = report.get("instructions_fingerprint")
        benchmark_fp = report.get("benchmark_fingerprint")
        if not isinstance(experiment_id, str) or not experiment_id.strip():
            raise ValueError("report requires experiment_id")
        if not self._valid_fingerprint(instructions_fp) or not self._valid_fingerprint(benchmark_fp):
            raise ValueError("report requires valid SHA-256 instruction and benchmark fingerprints")
        skill_key = (skill_key or instructions_fp).strip()
        if not skill_key or len(skill_key) > 256:
            raise ValueError("skill_key must contain 1 to 256 characters")
        summary = {
            "engine_version": report.get("engine_version"),
            "configuration": report.get("configuration", {}),
            "comparison": report.get("comparison", {}),
            "efficiency": report.get("efficiency", {}),
            "model_compatibility": report.get("model_compatibility", {}),
            "failure_counts": report.get("failure_counts", {}),
        }
        encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        report_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        now = self._now()
        with self._lock:
            existing = self._connection.execute("SELECT * FROM evaluation_history WHERE experiment_id = ?", (experiment_id,)).fetchone()
            if existing:
                if existing["report_hash"] != report_hash:
                    raise ValueError("experiment_id already exists with different summary metrics")
                return self._decode_row(existing)
            self._connection.execute(
                "INSERT INTO evaluation_history VALUES (?, ?, ?, ?, ?, ?, ?)",
                (experiment_id, skill_key, instructions_fp, benchmark_fp, report_hash, encoded, now),
            )
            row = self._connection.execute("SELECT * FROM evaluation_history WHERE experiment_id = ?", (experiment_id,)).fetchone()
        return self._decode_row(row)

    @staticmethod
    def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
        return {**dict(row), "summary": json.loads(row["summary_json"])}

    def list_history(self, skill_key: str, *, limit: int = 50) -> list[dict[str, Any]]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be from 1 to 500")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM evaluation_history WHERE skill_key = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (skill_key, limit),
            ).fetchall()
        return [self._decode_row(row) for row in rows]

    def regression_status(self, skill_key: str, *, threshold_pp: float = 5.0) -> dict[str, Any]:
        if threshold_pp < 0:
            raise ValueError("threshold_pp cannot be negative")
        history = self.list_history(skill_key)
        if not history:
            return {"status": "no_history", "skill_key": skill_key}
        latest = history[0]
        latest_lift = latest["summary"].get("comparison", {}).get("skill_lift_percentage_points")
        previous = next((item for item in history[1:] if item["benchmark_fingerprint"] == latest["benchmark_fingerprint"]), None)
        if previous is None:
            return {"status": "insufficient_comparable_history", "latest_experiment_id": latest["experiment_id"], "skill_lift_percentage_points": latest_lift}
        previous_lift = previous["summary"].get("comparison", {}).get("skill_lift_percentage_points")
        if latest_lift is None or previous_lift is None:
            return {"status": "missing_behavioral_metrics", "latest_experiment_id": latest["experiment_id"], "previous_experiment_id": previous["experiment_id"]}
        delta = latest_lift - previous_lift
        return {
            "status": "regression" if delta <= -threshold_pp else "stable_or_improved",
            "latest_experiment_id": latest["experiment_id"],
            "previous_experiment_id": previous["experiment_id"],
            "benchmark_fingerprint": latest["benchmark_fingerprint"],
            "latest_skill_lift_percentage_points": latest_lift,
            "previous_skill_lift_percentage_points": previous_lift,
            "change_percentage_points": round(delta, 2),
            "regression_threshold_percentage_points": threshold_pp,
        }

    def close(self) -> None:
        with self._lock:
            self._connection.close()
