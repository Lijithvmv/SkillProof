"""Analysis commands: scan a package, list or diff its capabilities, the update decision report, install inventory,
security-finding decisions, and the assurance gate for CI."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from skillproof.engines.analyzer import analyze_files
from skillproof.engines.capabilities import build_manifest, diff_manifests, read_package_bytes
from skillproof.governance import AssuranceInput, AssurancePolicy, evaluate_assurance
from skillproof.ingestion import PackageError, read_skill_zip
from skillproof.engines.inventory import inventory
from skillproof.engines.security import record_validation
from skillproof.engines.triage import triage
from skillproof.engines.update_report import build_update_report

Result = tuple[dict[str, Any], int]


def scan_archive(path: str) -> Result:
    try:
        files = read_skill_zip(Path(path).read_bytes())
        report = analyze_files(files)
    except (OSError, PackageError) as exc:
        return {"error": str(exc)}, 2
    structural_errors = any(item["severity"] == "error" for item in report["findings"])
    high_security = any(item["severity"] in {"critical", "high"} for item in report["security"]["findings"])
    return report, 2 if structural_errors or high_security else 0


def assurance_gate(document: dict[str, Any]) -> Result:
    try:
        evidence = AssuranceInput.model_validate(document.get("evidence", {}))
        policy = AssurancePolicy.model_validate(document.get("policy", {}))
    except ValidationError as exc:
        return {"error": "invalid assurance input", "details": exc.errors(include_input=False)}, 4
    result = evaluate_assurance(evidence, policy)
    return result, {"eligible_for_human_approval": 0, "human_review_required": 1, "insufficient_evidence": 3}.get(result["decision"], 2)


def run_scan(args) -> Result:
    return scan_archive(args.archive)


def run_update_report(args) -> Result:
    try:
        result = build_update_report(args.old, args.new, old_activation=args.old_activation, new_activation=args.new_activation,
                                     old_pilot=args.old_pilot, new_pilot=args.new_pilot, agreement=args.agreement, policy=args.policy,
                                     grader_check=args.grader_check)
        return result, {"block": 2, "review": 1, "reviewer_decision_required": 1, "accept": 0}[result["decision"]]
    except (OSError, ValueError, KeyError, PackageError, json.JSONDecodeError) as exc:
        return {"error": str(exc)}, 4


def run_inventory(args) -> Result:
    try:
        result = inventory(args.roots, overlap_threshold=args.overlap_threshold)
        return result, 1 if result["divergent_duplicates"] else 0
    except (OSError, ValueError) as exc:
        return {"error": str(exc)}, 4


def run_validate_findings(args) -> Result:
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
        decisions = json.loads(Path(args.decisions).read_text(encoding="utf-8"))
        if not isinstance(decisions, list):
            raise ValueError("Decisions file must be a JSON array")
        result = record_validation(report.get("security", report), decisions)
        return result, {"blocked": 2, "review_required": 1, "cleared": 0}[result["decision"]]
    except (OSError, json.JSONDecodeError, ValueError, AttributeError) as exc:
        return {"error": str(exc)}, 4


def run_manifest(args) -> Result:
    try:
        return build_manifest(read_package_bytes(args.package)), 0
    except (OSError, PackageError) as exc:
        return {"error": str(exc)}, 4


def run_diff(args) -> Result:
    try:
        old_manifest = build_manifest(read_package_bytes(args.old))
        new_manifest = build_manifest(read_package_bytes(args.new))
        result = diff_manifests(old_manifest, new_manifest)
        result["triage"] = triage(result, new_manifest=new_manifest)
        result["new_decode_trail"] = new_manifest["decode_trail"]
        return result, 1 if result["status"] == "new_capabilities" else 0
    except (OSError, PackageError) as exc:
        return {"error": str(exc)}, 4


def run_assurance_gate(args) -> Result:
    try:
        document = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("top-level JSON must be an object")
        return assurance_gate(document)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"error": str(exc)}, 4


def add(commands, conf) -> None:
    scan = commands.add_parser("scan", help="Analyze a skill ZIP and emit a JSON report.")
    scan.add_argument("archive", help="Path to skill package ZIP.")
    scan.add_argument("--output", default="-", help="Report destination; use - for stdout.")
    scan.set_defaults(run=run_scan)

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
    update.set_defaults(run=run_update_report)

    inventory_cmd = commands.add_parser("inventory", help="Find duplicate skill names and competing descriptions across installed skills. Exit 1 if a name has divergent copies.")
    inventory_cmd.add_argument("roots", nargs="+", help="Folders to search for SKILL.md (e.g. ~/.claude).")
    inventory_cmd.add_argument("--overlap-threshold", type=float, default=0.3)
    inventory_cmd.add_argument("--output", default="-", help="Destination; use - for stdout.")
    inventory_cmd.set_defaults(run=run_inventory)

    validate = commands.add_parser("validate-findings", help="Record confirmed/rejected decisions on security findings. Exit 2 if a high or critical finding is confirmed, 1 if any medium+ finding is still unvalidated.")
    validate.add_argument("report", help="A scan report (with a security section) or a security report JSON.")
    validate.add_argument("decisions", help="JSON array of {finding_id, status, reviewer, reason}.")
    validate.add_argument("--output", default="-", help="Destination; use - for stdout.")
    validate.set_defaults(run=run_validate_findings)

    manifest = commands.add_parser("manifest", help="List what a skill (directory or ZIP) can reach or change, after decoding hidden content.")
    manifest.add_argument("package", help="Skill directory or ZIP.")
    manifest.add_argument("--output", default="-", help="Manifest destination; use - for stdout.")
    manifest.set_defaults(run=run_manifest)

    diff = commands.add_parser("diff", help="Report capabilities a new skill version adds over an old one. Exit 1 when it adds any.")
    diff.add_argument("old", help="Old skill directory or ZIP.")
    diff.add_argument("new", help="New skill directory or ZIP.")
    diff.add_argument("--output", default="-", help="Diff destination; use - for stdout.")
    diff.set_defaults(run=run_diff)

    gate = commands.add_parser("assurance-gate", help="Evaluate an evidence/policy JSON file for CI.")
    gate.add_argument("input", help="JSON object with evidence and optional policy fields.")
    gate.add_argument("--output", default="-", help="Decision report destination; use - for stdout.")
    gate.set_defaults(run=run_assurance_gate)
