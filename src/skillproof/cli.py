"""Command-line gates for local and CI evaluation pipelines."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from pydantic import ValidationError

from skillproof import __version__
from skillproof.analyzer import analyze_files
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance
from skillproof.evaluation import validate_benchmark_task
from skillproof.ingestion import PackageError, read_skill_zip
from skillproof.history import EvaluationHistoryStore
from skillproof.monitoring import monitor_skill_history
from skillproof.pilot import load_benchmark, read_manifest
from skillproof.openai_adapter import OpenAIResponsesEvaluator, OpenAIResponsesRunner
from skillproof.ollama_adapter import OllamaEvaluator, OllamaRunner
from skillproof.execution import execute_experiment
from skillproof.human_review import HumanAnnotation, compare_decision_agreement, compare_score_agreement, create_blind_review_bundle


def _write_json(payload: dict[str, Any], destination: str, stdout: TextIO = sys.stdout) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)
    if destination == "-":
        stdout.write(rendered + "\n")
    else:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")


def _read_annotation_rows(path: str) -> list[dict[str, Any]]:
    """Read annotations as a JSON array or JSONL; rows not yet scored (human_score null) are skipped."""
    text = Path(path).read_text(encoding="utf-8")
    if text.lstrip().startswith("["):
        rows = json.loads(text)
    else:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"{path}: every annotation must be a JSON object")
    return [row for row in rows if row.get("human_score") is not None]


def scan_archive(path: str) -> tuple[dict[str, Any], int]:
    try:
        files = read_skill_zip(Path(path).read_bytes())
        report = analyze_files(files)
    except (OSError, PackageError) as exc:
        return {"error": str(exc)}, 2
    structural_errors = any(item["severity"] == "error" for item in report["findings"])
    high_security = any(item["severity"] in {"critical", "high"} for item in report["security"]["findings"])
    return report, 2 if structural_errors or high_security else 0


def assurance_gate(document: dict[str, Any]) -> tuple[dict[str, Any], int]:
    try:
        evidence = AssuranceInput.model_validate(document.get("evidence", {}))
        policy = AssurancePolicy.model_validate(document.get("policy", {}))
    except ValidationError as exc:
        return {"error": "invalid assurance input", "details": exc.errors(include_input=False)}, 4
    result = evaluate_assurance(evidence, policy)
    if result["decision"] == "eligible_for_human_approval":
        return result, 0
    if result["decision"] == "human_review_required":
        return result, 1
    if result["decision"] == "insufficient_evidence":
        return result, 3
    return result, 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skillproof", description="Analyze agent skill packages and enforce assurance gates.")
    parser.add_argument("--version", action="version", version=f"SkillProof {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Analyze a skill ZIP and emit a JSON report.")
    scan.add_argument("archive", help="Path to skill package ZIP.")
    scan.add_argument("--output", default="-", help="Report destination; use - for stdout.")

    gate = commands.add_parser("assurance-gate", help="Evaluate an evidence/policy JSON file for CI.")
    gate.add_argument("input", help="JSON object with evidence and optional policy fields.")
    gate.add_argument("--output", default="-", help="Decision report destination; use - for stdout.")

    monitor = commands.add_parser("monitor", help="Check persisted evaluation history for regressions and stale results.")
    monitor.add_argument("--history-db", required=True, help="SQLite evaluation history database path.")
    monitor.add_argument("--skill-key", required=True, help="Skill history key to monitor.")
    monitor.add_argument("--max-age-days", type=float, default=30)
    monitor.add_argument("--minimum-models", type=int, default=1)
    monitor.add_argument("--maximum-failure-rate", type=float, default=0.1)
    monitor.add_argument("--maximum-cost-overhead-percent", type=float, default=100)
    monitor.add_argument("--regression-threshold-pp", type=float, default=5)
    monitor.add_argument("--output", default="-", help="Monitor report destination; use - for stdout.")

    pilot = commands.add_parser("pilot", help="Run a paired agent/grader pilot on a JSONL benchmark (OpenAI or local Ollama).")
    pilot.add_argument("--skill-file", required=True)
    pilot.add_argument("--benchmark", required=True)
    pilot.add_argument("--provider", choices=["openai", "ollama"], default=os.getenv("SKILLPROOF_PROVIDER", "openai"), help="openai needs OPENAI_API_KEY; ollama runs locally with no key.")
    pilot.add_argument("--ollama-url", default=os.getenv("SKILLPROOF_OLLAMA_URL", "http://127.0.0.1:11434"), help="Loopback Ollama server for --provider ollama.")
    pilot.add_argument("--seed", type=int, default=0, help="Order randomization seed, and the sampling seed for Ollama.")
    pilot.add_argument("--temperature", type=float, default=0.7, help="Ollama agent sampling temperature (the grader always uses 0).")
    pilot.add_argument("--model", default=os.getenv("SKILLPROOF_MODEL") or os.getenv("SKILLPROOF_OPENAI_MODEL"), help="Agent model ID; defaults to SKILLPROOF_MODEL or SKILLPROOF_OPENAI_MODEL.")
    pilot.add_argument("--grader-model", default=os.getenv("SKILLPROOF_GRADER_MODEL") or os.getenv("SKILLPROOF_OPENAI_GRADER_MODEL"), help="Grader model ID; defaults to SKILLPROOF_GRADER_MODEL or SKILLPROOF_OPENAI_GRADER_MODEL.")
    pilot.add_argument("--repeats", type=int, default=2)
    pilot.add_argument("--output", required=True, help="Experiment report JSON path.")
    pilot.add_argument("--review-output", required=True, help="Blind review bundle JSON path.")
    pilot.add_argument("--unblinding-key-output", required=True, help="Keep this separate from reviewers until scoring is complete.")

    agreement = commands.add_parser("grader-agreement", help="Compare completed human scores to blinded grader scores.")
    agreement.add_argument("annotations", help="Completed annotations (JSON array or JSONL) of sample_id, human_score, reviewer_id, rationale objects.")
    agreement.add_argument("unblinding_key", help="Separate unblinding key JSON from the pilot run.")
    agreement.add_argument("--extra-annotations", action="append", default=[], metavar="FILE", help="Another reviewer's completed annotations; repeat once per file.")
    agreement.add_argument("--pass-threshold", type=float, default=0.7)
    agreement.add_argument("--tolerance", type=float, default=0.1)
    agreement.add_argument("--output", default="-", help="Agreement report destination; use - for stdout.")

    decision_agreement = commands.add_parser("decision-agreement", help="Measure automated decision agreement with human labels.")
    decision_agreement.add_argument("annotations", help="JSON array containing automated and human decision labels.")
    decision_agreement.add_argument("--predicted-key", required=True)
    decision_agreement.add_argument("--human-key", required=True)
    decision_agreement.add_argument("--labels", required=True, help="Comma-separated complete label set.")
    decision_agreement.add_argument("--output", default="-", help="Agreement report destination; use - for stdout.")

    args = parser.parse_args(argv)
    if args.command == "scan":
        result, exit_code = scan_archive(args.archive)
    elif args.command == "assurance-gate":
        try:
            document = json.loads(Path(args.input).read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise ValueError("top-level JSON must be an object")
            result, exit_code = assurance_gate(document)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "monitor":
        store = EvaluationHistoryStore(args.history_db)
        try:
            result = monitor_skill_history(
                store, args.skill_key, max_age_days=args.max_age_days,
                minimum_models=args.minimum_models, maximum_failure_rate=args.maximum_failure_rate,
                maximum_cost_overhead_percent=args.maximum_cost_overhead_percent,
                regression_threshold_pp=args.regression_threshold_pp,
            )
            exit_code = 0 if result["status"] == "healthy" else 1
        except (OSError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
        finally:
            store.close()
    elif args.command == "pilot":
        try:
            if not args.model or not args.grader_model:
                raise ValueError("Set explicit --model and --grader-model values, or configure SKILLPROOF_MODEL and SKILLPROOF_GRADER_MODEL.")
            if args.provider == "ollama":
                runner = OllamaRunner(model=args.model, base_url=args.ollama_url, seed=args.seed, temperature=args.temperature)
                evaluator = OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed)
            else:
                runner = OpenAIResponsesRunner(model=args.model)
                evaluator = OpenAIResponsesEvaluator(model=args.grader_model)
            skill_instructions = Path(args.skill_file).read_text(encoding="utf-8")
            tasks = load_benchmark(args.benchmark)
            manifest = read_manifest(args.benchmark)
            task_reviews = [validate_benchmark_task(skill_instructions, task) for task in tasks]
            experiment = execute_experiment(
                tasks=tasks,
                skill_instructions=skill_instructions,
                runner=runner,
                evaluator=evaluator,
                repeats=args.repeats,
                seed=args.seed,
            )
            experiment["benchmark"] = {"benchmark_id": manifest.get("benchmark_id"), "version": manifest.get("version"), "validation_status": manifest.get("status")}
            bundle = create_blind_review_bundle(experiment, tasks, task_reviews)
            _write_json({"review_samples": bundle["review_samples"], "annotation_template": bundle["annotation_template"], "task_review_samples": bundle["task_review_samples"], "task_review_template": bundle["task_review_template"], "instructions": bundle["instructions"]}, args.review_output)
            _write_json(bundle["sealed_unblinding_key"], args.unblinding_key_output)
            result = experiment
            failure_count = sum(experiment["failure_counts"].values())
            total_calls = len(tasks) * args.repeats * 2
            exit_code = 2 if failure_count == total_calls else 1 if failure_count else 0
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
            _write_json(result, args.output)
    elif args.command == "grader-agreement":
        try:
            annotation_data = [row for path in [args.annotations, *args.extra_annotations] for row in _read_annotation_rows(path)]
            key_data = json.loads(Path(args.unblinding_key).read_text(encoding="utf-8"))
            annotations = [HumanAnnotation.model_validate(item) for item in annotation_data]
            result = compare_score_agreement(annotations, key_data, pass_threshold=args.pass_threshold, tolerance=args.tolerance)
            exit_code = 0
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    else:
        try:
            rows = json.loads(Path(args.annotations).read_text(encoding="utf-8"))
            result = compare_decision_agreement(rows, predicted_key=args.predicted_key, human_key=args.human_key, labels=[x.strip() for x in args.labels.split(",") if x.strip()])
            exit_code = 0
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    _write_json(result, args.output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
