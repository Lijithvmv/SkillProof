"""Small local helpers for repeatable provider-backed pilot runs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillproof.evaluation import BenchmarkTask


def load_benchmark(path: str | Path) -> list[BenchmarkTask]:
    tasks: list[BenchmarkTask] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            tasks.append(BenchmarkTask.model_validate(item))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid benchmark row at line {line_number}: {exc}") from exc
    if not tasks:
        raise ValueError("Benchmark contains no tasks")
    if len({task.task_id for task in tasks}) != len(tasks):
        raise ValueError("Benchmark task_id values must be unique")
    return tasks


def read_manifest(benchmark_path: str | Path) -> dict[str, Any]:
    manifest_path = Path(benchmark_path).with_name("manifest.json")
    if not manifest_path.exists():
        return {"benchmark_id": Path(benchmark_path).stem, "version": "unknown", "status": "manifest_missing"}
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Benchmark manifest must be a JSON object")
    return data
