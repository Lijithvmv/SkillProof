"""Command-line gates for local and CI evaluation pipelines."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, TextIO

from pydantic import ValidationError

from skillproof import __version__
from skillproof.config import settings
from skillproof.analyzer import analyze_files
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance
from skillproof.evaluation import validate_benchmark_task
from skillproof.ingestion import PackageError, read_skill_zip
from skillproof.history import EvaluationHistoryStore
from skillproof.monitoring import monitor_skill_history
from skillproof.pilot import load_benchmark, read_manifest
from skillproof.openai_adapter import OpenAIResponsesEvaluator, OpenAIResponsesRunner
from skillproof.ollama_adapter import OllamaActivationProbe, OllamaEvaluator, OllamaRunner
from skillproof.security import record_validation
from skillproof.inventory import inventory
from skillproof.installed import default_roots, scan_installed
from skillproof.apm_lock import check_lockfile
from skillproof.update_report import build_update_report
from skillproof.capabilities import build_manifest, diff_manifests, read_package_bytes
from skillproof.triage import triage
from skillproof.activation import measure_activation, read_distractors, read_requests, read_skill_card
from skillproof.execution import execute_experiment
from skillproof.grader_check import check_grader, read_cases
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
    _conf = settings()
    parser = argparse.ArgumentParser(prog="skillproof", description="Analyze agent skill packages and enforce assurance gates.")
    parser.add_argument("--version", action="version", version=f"SkillProof {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Analyze a skill ZIP and emit a JSON report.")
    scan.add_argument("archive", help="Path to skill package ZIP.")
    scan.add_argument("--output", default="-", help="Report destination; use - for stdout.")

    update = commands.add_parser("update-report", help="Join capability diff, load rate, lift and grader agreement for one skill update. Exit 2 block, 1 review or no decision, 0 accept.")
    update.add_argument("old", help="Old skill directory or ZIP.")
    update.add_argument("new", help="New skill directory or ZIP.")
    update.add_argument("--old-activation", help="Load-rate JSON (activation section or file) for the old version.")
    update.add_argument("--new-activation", help="Load-rate JSON for the new version.")
    update.add_argument("--old-pilot", help="Pilot report JSON for the old version.")
    update.add_argument("--new-pilot", help="Pilot report JSON for the new version.")
    update.add_argument("--agreement", help="grader-agreement report JSON.")
    update.add_argument("--grader-check", help="grader-check report JSON (labelled answers; not a substitute for --agreement).")
    update.add_argument("--policy", help="Your decision rules (JSON). Without it no decision is made.")
    update.add_argument("--output", default="-", help="Destination; use - for stdout.")

    lock = commands.add_parser("lock-check", help="For each git dependency in an apm.lock.yaml, report what updating from the locked commit would add. Exit 1 when an update adds capabilities.")
    lock.add_argument("lockfile")
    lock.add_argument("--cache", default=str(Path.home() / ".skillproof" / "repos"), help="Where bare clones are kept (nothing is checked out).")
    lock.add_argument("--to", help="Commit, tag or branch to compare against. Default: tip of the locked branch, or newest semver tag for a locked tag.")
    lock.add_argument("--output", default="-")

    watch = commands.add_parser("watch-installed", help="Diff installed skills against the last scan and report what each update adds. Exit 1 when an update adds capabilities.")
    watch.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common Claude, Codex, Cursor and VS Code locations that exist.")
    watch.add_argument("--state", default=str(Path.home() / ".skillproof" / "installed-state.json"), help="Local state file (manifests of the last scan, not skill contents).")
    watch.add_argument("--output", default="-")

    feed = commands.add_parser("catalogue-import", help="Register the skills installed on this machine in the catalogue. Unchanged skills are skipped; a changed skill becomes a new version ranked block / ask / note against the one before. Exit 1 when an update has a block-level addition.")
    feed.add_argument("--data-dir", default=_conf.data_dir or str(Path.home() / ".skillproof" / "catalogue"), help="Catalogue storage (the same folder the API uses as SKILLPROOF_DATA_DIR).")
    feed.add_argument("--tenant", default="local", help="Catalogue tenant to register into (the API's local development tenant is 'local').")
    feed.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common Claude, Codex, Cursor and VS Code locations that exist.")
    feed.add_argument("--output", default="-")

    feed.add_argument("--policy", help="Assurance policy JSON (thresholds) for the imported versions; default policy otherwise.")

    draft = commands.add_parser("benchmark-draft", help="Read what a skill says about itself (claims) and draft a conformance benchmark that tests them, with a local model. The draft must be reviewed before its results count.")
    draft.add_argument("skill", help="Skill folder (holding SKILL.md).")
    draft.add_argument("--model", required=True, help="Local Ollama model that drafts the tasks.")
    draft.add_argument("--ollama-url", default=_conf.ollama_url)
    draft.add_argument("--tasks", type=int, default=8)
    draft.add_argument("--mode", choices=("templates", "model"), default="templates",
                       help="templates: tests built from the rule's own words, the model writes only background (default); "
                            "model: the model drafts whole tests (needs review).")
    draft.add_argument("--seed", type=int, default=0)
    draft.add_argument("--output-dir", required=True, help="Writes claims.json, benchmark.jsonl, manifest.json and draft-review.json here.")
    draft.add_argument("--output", default="-", help="Summary destination; use - for stdout.")

    evaluate = commands.add_parser("evaluate-skill", help="Run a skill's benchmark with and without the skill on a local model, measure lift and claim adherence, and record it in the catalogue's history so the catalogue cites it.")
    evaluate.add_argument("skill", help="Skill folder (holding SKILL.md).")
    evaluate.add_argument("--benchmark", required=True, help="benchmark.jsonl (claims.json beside it is used for adherence).")
    evaluate.add_argument("--model", required=True, help="Agent model (local Ollama).")
    evaluate.add_argument("--grader-model", help="Judge for free-text criteria; not needed for a checks-only benchmark.")
    evaluate.add_argument("--ollama-url", default=_conf.ollama_url)
    evaluate.add_argument("--repeats", type=int, default=2)
    evaluate.add_argument("--seed", type=int, default=0)
    evaluate.add_argument("--max-output-tokens", type=int, default=3000)
    evaluate.add_argument("--name", help="Catalogue skill name to record under (default: the SKILL.md name).")
    evaluate.add_argument("--data-dir", help="Catalogue storage to record into (as catalogue-import). Omit to only report.")
    evaluate.add_argument("--tenant", default="local")
    evaluate.add_argument("--output", default="-")

    report = commands.add_parser("fleet-report", help="Send this machine's installed skills (names and package fingerprints, never contents) to a SkillProof server, which compares them with the approved versions. Exit 1 when a skill runs unapproved.")
    report.add_argument("--server", required=True, help="Server base URL, e.g. https://skillproof.example.org")
    report.add_argument("--token-env", default="SKILLPROOF_TOKEN", help="Environment variable holding the bearer access token (a reporter-role token).")
    report.add_argument("--host", default=None, help="Machine name to report as (default: this computer's name).")
    report.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common agent locations that exist.")
    report.add_argument("--output", default="-")

    check = commands.add_parser("catalogue-check", help="Compare the skills installed on this machine with the versions the catalogue approved. Registers nothing. Exit 1 when an installed skill differs from its approved version (running unapproved); with --strict also when a skill was never approved.")
    check.add_argument("--data-dir", default=_conf.data_dir or str(Path.home() / ".skillproof" / "catalogue"), help="Catalogue storage (the same folder the API uses as SKILLPROOF_DATA_DIR).")
    check.add_argument("--tenant", default="local")
    check.add_argument("--root", action="append", default=[], help="Folder to search for SKILL.md; repeat. Default: common agent locations that exist.")
    check.add_argument("--strict", action="store_true", help="Also fail when an installed skill has no approved version.")
    check.add_argument("--output", default="-")

    serve_cmd = commands.add_parser("serve", help="Run the API from a configuration file (storage, sign-in, scheduled backups).")
    serve_cmd.add_argument("--config", required=True)
    migrate_cmd = commands.add_parser("migrate", help="Apply pending schema steps to every store, then exit. Run it with a schema-owning role before starting a service that runs with SKILLPROOF_SCHEMA=verify.")
    migrate_cmd.add_argument("--config", required=True)
    migrate_cmd.add_argument("--output", default="-")
    backup_cmd = commands.add_parser("backup", help="Back up the catalogue, approvals and history now (consistent copy, hashed manifest, retention).")
    backup_cmd.add_argument("--config", required=True)
    backup_cmd.add_argument("--output", default="-")
    restore_cmd = commands.add_parser("restore", help="Restore a SQLite backup after checking its hashes. The server must be stopped.")
    restore_cmd.add_argument("--config", required=True)
    restore_cmd.add_argument("--from", dest="source", required=True)
    restore_cmd.add_argument("--output", default="-")
    unit_cmd = commands.add_parser("service-file", help="Print a systemd unit or a Windows scheduled-task definition that runs 'serve'.")
    unit_cmd.add_argument("--config", required=True)
    unit_cmd.add_argument("--kind", choices=("systemd", "windows-task"), default="systemd")

    inventory_cmd = commands.add_parser("inventory", help="Find duplicate skill names and competing descriptions across installed skills. Exit 1 if a name has divergent copies.")
    inventory_cmd.add_argument("roots", nargs="+", help="Folders to search for SKILL.md (e.g. ~/.claude).")
    inventory_cmd.add_argument("--overlap-threshold", type=float, default=0.3)
    inventory_cmd.add_argument("--output", default="-", help="Destination; use - for stdout.")

    validate = commands.add_parser("validate-findings", help="Record confirmed/rejected decisions on security findings. Exit 2 if a high or critical finding is confirmed, 1 if any medium+ finding is still unvalidated.")
    validate.add_argument("report", help="A scan report (with a security section) or a security report JSON.")
    validate.add_argument("decisions", help="JSON array of {finding_id, status, reviewer, reason}.")
    validate.add_argument("--output", default="-", help="Destination; use - for stdout.")

    manifest = commands.add_parser("manifest", help="List what a skill (directory or ZIP) can reach or change, after decoding hidden content.")
    manifest.add_argument("package", help="Skill directory or ZIP.")
    manifest.add_argument("--output", default="-", help="Manifest destination; use - for stdout.")

    diff = commands.add_parser("diff", help="Report capabilities a new skill version adds over an old one. Exit 1 when it adds any.")
    diff.add_argument("old", help="Old skill directory or ZIP.")
    diff.add_argument("new", help="New skill directory or ZIP.")
    diff.add_argument("--output", default="-", help="Diff destination; use - for stdout.")

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
    pilot.add_argument("--provider", choices=["openai", "ollama"], default=_conf.pilot_provider, help="openai needs OPENAI_API_KEY; ollama runs locally with no key.")
    pilot.add_argument("--ollama-url", default=_conf.ollama_url, help="Loopback Ollama server for --provider ollama.")
    pilot.add_argument("--seed", type=int, default=0, help="Order randomization seed, and the sampling seed for Ollama.")
    pilot.add_argument("--temperature", type=float, default=0.7, help="Ollama agent sampling temperature (the grader always uses 0).")
    pilot.add_argument("--distractor-skills", help="JSONL of other skills (name, description). Turns on the load-rate test (Ollama only).")
    pilot.add_argument("--unrelated-tasks", help="JSONL of prompts the skill should NOT be picked for (false activation).")
    pilot.add_argument("--model", default=_conf.pilot_model or None, help="Agent model ID; defaults to SKILLPROOF_MODEL or SKILLPROOF_OPENAI_MODEL.")
    pilot.add_argument("--grader-model", default=_conf.pilot_grader_model or None, help="Grader model ID; defaults to SKILLPROOF_GRADER_MODEL or SKILLPROOF_OPENAI_GRADER_MODEL.")
    pilot.add_argument("--repeats", type=int, default=2)
    pilot.add_argument("--output", required=True, help="Experiment report JSON path.")
    pilot.add_argument("--review-output", required=True, help="Blind review bundle JSON path.")
    pilot.add_argument("--unblinding-key-output", required=True, help="Keep this separate from reviewers until scoring is complete.")

    gcheck = commands.add_parser("grader-check", help="Grade answers with known per-criterion labels and list where the grader disagrees. Exit 1 on any disagreement or grader failure.")
    gcheck.add_argument("--benchmark", required=True)
    gcheck.add_argument("--cases", required=True, help="JSONL of case_id, task_id, output, expected (one 0/1 per criterion), note.")
    gcheck.add_argument("--provider", choices=["openai", "ollama"], default=_conf.pilot_provider)
    gcheck.add_argument("--ollama-url", default=_conf.ollama_url)
    gcheck.add_argument("--grader-model", default=_conf.pilot_grader_model or None)
    gcheck.add_argument("--seed", type=int, default=0)
    gcheck.add_argument("--output", default="-")

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
    elif args.command == "update-report":
        try:
            result = build_update_report(
                args.old, args.new, old_activation=args.old_activation, new_activation=args.new_activation,
                old_pilot=args.old_pilot, new_pilot=args.new_pilot, agreement=args.agreement, policy=args.policy,
                grader_check=args.grader_check,
            )
            exit_code = {"block": 2, "review": 1, "reviewer_decision_required": 1, "accept": 0}[result["decision"]]
        except (OSError, ValueError, KeyError, PackageError, json.JSONDecodeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "lock-check":
        try:
            result = check_lockfile(args.lockfile, cache=args.cache, to=args.to)
            exit_code = 1 if result["updates_adding_capabilities"] else 0
        except (OSError, ValueError, RuntimeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "watch-installed":
        try:
            roots = [Path(r) for r in args.root] or default_roots()
            if not roots:
                raise ValueError("No skill folders found; pass --root.")
            result = scan_installed(roots, args.state)
            exit_code = 1 if result["changes_adding_capabilities"] else 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "catalogue-import":
        try:

            roots = [Path(r) for r in args.root] or default_roots()
            if not roots:
                raise ValueError("No skill folders found; pass --root.")
            data = Path(args.data_dir)
            governance = _catalogue_governance(data)
            principal = _import_principal(args.tenant)
            try:
                policy = AssurancePolicy.model_validate(json.loads(Path(args.policy).read_text(encoding="utf-8"))) if args.policy else None
                result = _import_installed(governance, principal, roots, policy)
            finally:
                governance.registry.close()
                governance.approvals.close()
            exit_code = 1 if result["updates_with_block"] else 0
        except (OSError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "fleet-report":
        try:
            roots = [Path(r) for r in args.root] or default_roots()
            if not roots:
                raise ValueError("No skill folders found; pass --root.")
            result = _fleet_report(args.server, os.environ.get(args.token_env, "").strip(), args.host, roots)
            exit_code = 1 if result.get("counts", {}).get("running_unapproved") else 0
        except (OSError, ValueError, RuntimeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "benchmark-draft":
        try:
            result, exit_code = _benchmark_draft(args), 0
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "evaluate-skill":
        try:
            result = _evaluate_skill(args)
            followed = (result["comparison"].get("adherence") or {}).get("adherence_rate")
            exit_code = 1 if sum(result["failure_counts"].values()) or (followed is not None and followed < 0.7) else 0
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "serve":
        from skillproof.service import ServiceError, load_config, serve
        try:
            serve(load_config(args.config))
            return 0
        except (OSError, ValueError, ServiceError) as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 4
    elif args.command == "service-file":
        from skillproof.service import ServiceError, service_file
        try:
            sys.stdout.write(service_file(args.config, args.kind))
            return 0
        except ServiceError as exc:
            print(json.dumps({"error": str(exc)}), file=sys.stderr)
            return 4
    elif args.command == "migrate":
        from skillproof.service import ServiceError, load_config, migrate_all
        try:
            result, exit_code = migrate_all(load_config(args.config)), 0
        except (OSError, ValueError, ServiceError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command in {"backup", "restore"}:
        from skillproof.service import ServiceError, backup, load_config, restore
        try:
            config = load_config(args.config)
            result = backup(config) if args.command == "backup" else restore(config, args.source)
            exit_code = 0
        except (OSError, ValueError, ServiceError, subprocess.CalledProcessError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "catalogue-check":
        try:
            roots = [Path(r) for r in args.root] or default_roots()
            if not roots:
                raise ValueError("No skill folders found; pass --root.")
            governance = _catalogue_governance(Path(args.data_dir))
            try:
                result = _check_installed(governance, _check_principal(args.tenant), roots)
            finally:
                governance.registry.close()
                governance.approvals.close()
            exit_code = 1 if result["running_unapproved"] or (args.strict and result["never_approved"]) else 0
        except (OSError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "inventory":
        try:
            result = inventory(args.roots, overlap_threshold=args.overlap_threshold)
            exit_code = 1 if result["divergent_duplicates"] else 0
        except (OSError, ValueError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "validate-findings":
        try:
            report = json.loads(Path(args.report).read_text(encoding="utf-8"))
            decisions = json.loads(Path(args.decisions).read_text(encoding="utf-8"))
            if not isinstance(decisions, list):
                raise ValueError("Decisions file must be a JSON array")
            result = record_validation(report.get("security", report), decisions)
            exit_code = {"blocked": 2, "review_required": 1, "cleared": 0}[result["decision"]]
        except (OSError, json.JSONDecodeError, ValueError, AttributeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "manifest":
        try:
            result, exit_code = build_manifest(read_package_bytes(args.package)), 0
        except (OSError, PackageError) as exc:
            result, exit_code = {"error": str(exc)}, 4
    elif args.command == "diff":
        try:
            old_manifest = build_manifest(read_package_bytes(args.old))
            new_manifest = build_manifest(read_package_bytes(args.new))
            result = diff_manifests(old_manifest, new_manifest)
            result["triage"] = triage(result, new_manifest=new_manifest)
            result["new_decode_trail"] = new_manifest["decode_trail"]
            exit_code = 1 if result["status"] == "new_capabilities" else 0
        except (OSError, PackageError) as exc:
            result, exit_code = {"error": str(exc)}, 4
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
            if args.distractor_skills:
                if args.provider != "ollama":
                    raise ValueError("The load-rate test currently needs --provider ollama.")
                experiment["activation"] = measure_activation(
                    target=read_skill_card(args.skill_file),
                    distractors=read_distractors(args.distractor_skills),
                    relevant_requests=[task.prompt for task in tasks],
                    unrelated_requests=read_requests(args.unrelated_tasks) if args.unrelated_tasks else [],
                    probe=OllamaActivationProbe(model=args.model, base_url=args.ollama_url, seed=args.seed, temperature=args.temperature),
                    repeats=args.repeats,
                    seed=args.seed,
                    forced_lift_percentage_points=experiment["comparison"].get("skill_lift_percentage_points"),
                )
            elif args.unrelated_tasks:
                raise ValueError("--unrelated-tasks needs --distractor-skills.")
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
    elif args.command == "grader-check":
        try:
            if not args.grader_model:
                raise ValueError("Set --grader-model or SKILLPROOF_GRADER_MODEL.")
            evaluator = (OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed)
                         if args.provider == "ollama" else OpenAIResponsesEvaluator(model=args.grader_model))
            result = check_grader(load_benchmark(args.benchmark), read_cases(args.cases), evaluator)
            exit_code = 1 if result["disagreements"] or result["grader_failures"] else 0
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            result, exit_code = {"error": str(exc)}, 4
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




def _catalogue_governance(data: Path):
    from skillproof.approvals import SQLiteApprovalStore
    from skillproof.authorization import GovernanceAccess
    from skillproof.history import EvaluationHistoryStore as HistoryStore
    from skillproof.registry import SQLiteSkillRegistry

    url = settings().database_url  # PostgreSQL, the same database the API uses
    from skillproof.jobs import JobStore
    from skillproof.notify import NotificationStore

    if url:
        return GovernanceAccess(registry=SQLiteSkillRegistry(url), approvals=SQLiteApprovalStore(url), history=HistoryStore(url),
                                jobs=JobStore(url), notifications=NotificationStore(url))
    return GovernanceAccess(registry=SQLiteSkillRegistry(data / "registry.db"),
                            approvals=SQLiteApprovalStore(data / "approvals.db"),
                            history=HistoryStore(data / "history.db"), jobs=JobStore(data / "jobs.db"),
                            notifications=NotificationStore(data / "notify.db"))


def _import_principal(tenant: str):
    from skillproof.authorization import Principal

    return Principal(user_id="installed-skill-import", tenant_id=tenant, role="evaluator")


def _check_principal(tenant: str):
    from skillproof.authorization import Principal

    return Principal(user_id="installed-skill-check", tenant_id=tenant, role="viewer")


def _check_installed(governance, principal, roots):
    from skillproof.catalogue_import import check_installed

    return check_installed(governance, principal, roots)


def _import_installed(governance, principal, roots, policy=None):
    from skillproof.catalogue_import import import_installed

    return import_installed(governance, principal, roots, policy)


def _fleet_report(server: str, token: str, host: str | None, roots: list[Path], *, send=None) -> dict[str, Any]:
    """Collect installed skills (catalogue names and folder fingerprints, as catalogue-import computes them) and POST them."""
    import socket
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse

    from skillproof.catalogue_import import _installed_families

    parsed = urlparse(server)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}):
        raise ValueError("the server must be an https URL (plain http only to this machine)")
    _, names, packages, errors = _installed_families(roots)
    body = json.dumps({"host": host or socket.gethostname(),
                       "skills": [{"skill_name": name, "fingerprint": packages[key][2]} for key, name in sorted(names.items(), key=lambda p: p[1])]}).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:  # a local development server with sign-in off
        headers.update({"X-SkillProof-Dev-User": f"reporter@{host or socket.gethostname()}", "X-SkillProof-Dev-Role": "reporter"})
    if send is not None:
        return send(server.rstrip("/") + "/api/v1/fleet/reports", body, headers)
    request = urllib.request.Request(server.rstrip("/") + "/api/v1/fleet/reports", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"server answered HTTP {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}") from exc
    result["unreadable"] = errors
    return result


def _skill_text(folder: str) -> str:
    path = Path(folder)
    path = path if path.name == "SKILL.md" else path / "SKILL.md"
    return path.read_bytes().decode("utf-8-sig")  # the same decoding the catalogue fingerprints


def _benchmark_draft(args) -> dict[str, Any]:
    from skillproof.conformance import draft_benchmark, extract_claims, write_benchmark
    from skillproof.ollama_adapter import ollama_json_asker

    text = _skill_text(args.skill)
    claims = extract_claims(text)
    if not claims["claims"]:
        raise ValueError("no claims found in SKILL.md (no rules, steps or 'Use when' requests)")
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "claims.json").write_text(json.dumps(claims, indent=2, ensure_ascii=False), encoding="utf-8")
    ask = ollama_json_asker(args.model, args.ollama_url, seed=args.seed)
    if args.mode == "templates":
        from skillproof.templates import generate_benchmark

        drafted = generate_benchmark(text, claims, ask, tasks=args.tasks)
        status = "generated_from_rules"
        review = {"coverage": drafted["coverage"], "rejected": drafted["rejected"], "uncovered": drafted["uncovered"],
                  "task_reviews": drafted["reviews"]}
    else:
        drafted = draft_benchmark(text, claims, ask, tasks=args.tasks)
        status = "draft_needs_review"
        review = {"dropped": drafted["dropped"], "task_reviews": drafted["reviews"]}
    write_benchmark(out / "benchmark.jsonl", drafted["tasks"], skill=claims["skill"], claims_file="claims.json",
                    generator=f"{args.mode}:{args.model}", status=status)
    (out / "draft-review.json").write_text(json.dumps(review, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"skill": claims["skill"], "claims": len(claims["claims"]), "mode": args.mode, "tasks": len(drafted["tasks"]),
            "checks": sum(len(t.checks) for t in drafted["tasks"]), "coverage": drafted.get("coverage"),
            "status": status, "output_dir": str(out)}


def _evaluate_skill(args) -> dict[str, Any]:
    from skillproof.checks import CheckedEvaluator
    from skillproof.conformance import adherence, extract_claims

    text = _skill_text(args.skill)
    tasks = load_benchmark(args.benchmark)
    manifest = read_manifest(args.benchmark)
    claims_path = Path(args.benchmark).with_name("claims.json")
    claims = json.loads(claims_path.read_text(encoding="utf-8")) if claims_path.exists() else extract_claims(text)
    judge = OllamaEvaluator(model=args.grader_model, base_url=args.ollama_url, seed=args.seed) if args.grader_model else None
    runner = OllamaRunner(model=args.model, base_url=args.ollama_url, seed=args.seed, max_output_tokens=args.max_output_tokens)
    experiment = execute_experiment(tasks=tasks, skill_instructions=text, runner=runner, evaluator=CheckedEvaluator(judge),
                                    repeats=args.repeats, seed=args.seed)
    experiment["comparison"]["adherence"] = adherence(experiment, claims)
    experiment["benchmark"] = {"benchmark_id": manifest.get("benchmark_id"), "version": manifest.get("version"),
                               "validation_status": manifest.get("status")}
    name = args.name or claims.get("skill") or Path(args.skill).name
    if args.data_dir:
        governance = _catalogue_governance(Path(args.data_dir))
        try:
            from skillproof.authorization import Principal
            stored = governance.record_evaluation(Principal(user_id="skill-evaluation", tenant_id=args.tenant, role="evaluator"),
                                                  experiment, skill_key=name)
        finally:
            governance.registry.close()
            governance.approvals.close()
        experiment["recorded"] = {"skill_name": name, "tenant": args.tenant, "experiment_id": stored["experiment_id"]}
    return experiment


if __name__ == "__main__":
    raise SystemExit(main())
