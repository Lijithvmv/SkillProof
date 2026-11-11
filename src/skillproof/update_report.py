"""The update decision: should v_old of a skill be replaced by v_new?

Scanners answer "is this dangerous?", evaluators answer "does this help?". An update decision needs both at once:
what the new version can do that the old one could not, whether it is picked when it should be, whether it helps
when used, and whether the grader that measured "helps" agrees with people. This module joins those measurements
into one report for one update.

It does not invent cut-offs. Without a policy file the decision is "reviewer_decision_required", with the reasons
listed. A policy written by the user (from their own measured data) turns the same evidence into accept / review /
block. Missing evidence is listed, never assumed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillproof.activation import read_skill_card
from skillproof.capabilities import build_manifest, diff_manifests, read_package_bytes

DECISIONS = ("accept", "review", "block")


def _load(path: str | Path | None) -> dict[str, Any] | None:
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def _description(skill_dir: str | Path) -> dict[str, str] | None:
    path = Path(skill_dir)
    path = path if path.name == "SKILL.md" else path / "SKILL.md"
    try:
        card = read_skill_card(path)
    except (OSError, ValueError):
        return None
    return {"name": card.name, "description": card.description}


def _activation(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    worst = min((r for r in report.get("by_request", []) if r["kind"] == "relevant" and r["target_rate"] is not None),
                key=lambda r: r["target_rate"], default=None)
    return {
        "activation_rate": report["relevant"]["activation_rate"],
        "trials": report["relevant"]["trials"],
        "false_activation_rate": report["unrelated"]["false_activation_rate"],
        "worst_relevant_request": {"request": worst["request"], "rate": worst["target_rate"]} if worst else None,
    }


def _lift(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    comparison = report.get("comparison", {})
    coverage = comparison.get("coverage", {})
    return {
        "lift_percentage_points": comparison.get("skill_lift_percentage_points"),
        "complete_pairs": coverage.get("complete_pairs", comparison.get("baseline", {}).get("runs")),
        "total_pairs": coverage.get("total_pairs"),
        "failures": sum((report.get("failure_counts") or {}).values()),
        "uneven_failures": coverage.get("uneven_failures"),
    }


def _agreement(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    return {
        "cohen_kappa": report.get("pass_fail_metrics", {}).get("cohen_kappa"),
        "samples": report.get("sample_count"),
        "reviewers": report.get("reviewer_count"),
    }


def build_update_report(
    old: str | Path, new: str | Path, *, old_activation: str | Path | None = None, new_activation: str | Path | None = None,
    old_pilot: str | Path | None = None, new_pilot: str | Path | None = None, agreement: str | Path | None = None,
    policy: str | Path | None = None,
) -> dict[str, Any]:
    diff = diff_manifests(build_manifest(read_package_bytes(old)), build_manifest(read_package_bytes(new)))
    metadata = {"old": _description(old), "new": _description(new)}
    evidence = {
        "capability_delta": {
            "status": diff["status"],
            "added": {category: sorted(values) for category, values in diff["added"].items()},
            "added_by_source": diff["added_by_source"],
            "only_in_tests": sorted(f"{c}:{v}" for c, vals in diff["added_sources"].items() for v, kinds in vals.items() if kinds == ["test"]),
            "removed": diff["removed"],
        },
        "description_changed": bool(metadata["old"] and metadata["new"] and metadata["old"] != metadata["new"]),
        "load_rate": {"old": _activation(_load(old_activation)), "new": _activation(_load(new_activation))},
        "lift": {"old": _lift(_load(old_pilot)), "new": _lift(_load(new_pilot))},
        "grader_agreement": _agreement(_load(agreement)),
    }
    missing = [name for name, present in (
        ("load rate (old)", evidence["load_rate"]["old"]), ("load rate (new)", evidence["load_rate"]["new"]),
        ("lift (old)", evidence["lift"]["old"]), ("lift (new)", evidence["lift"]["new"]),
        ("grader agreement with humans", evidence["grader_agreement"]),
    ) if not present]

    reasons = []
    if diff["added"]:
        reasons.append("new capabilities: " + ", ".join(f"{c} ({len(v)})" for c, v in diff["added"].items()))
    old_rate = (evidence["load_rate"]["old"] or {}).get("activation_rate")
    new_rate = (evidence["load_rate"]["new"] or {}).get("activation_rate")
    if old_rate is not None and new_rate is not None:
        reasons.append(f"load rate {old_rate:.0%} -> {new_rate:.0%}")
    new_false = (evidence["load_rate"]["new"] or {}).get("false_activation_rate")
    old_false = (evidence["load_rate"]["old"] or {}).get("false_activation_rate")
    if new_false is not None and old_false is not None and new_false > old_false:
        reasons.append(f"false activation rose {old_false:.0%} -> {new_false:.0%}")
    if missing:
        reasons.append("missing evidence: " + ", ".join(missing))

    decision, applied = "reviewer_decision_required", []
    rules = _load(policy)
    if rules:
        decision, applied = _apply_policy(rules, diff, evidence)
    return {
        "method": "update_decision_report",
        "old": str(old),
        "new": str(new),
        "metadata": metadata,
        "evidence": evidence,
        "missing_evidence": missing,
        "decision": decision,
        "reasons": reasons,
        "policy_rules_applied": applied,
        "limitations": (
            "Each column is only as good as its own measurement (capability facts are static; load rate is a model "
            "routing proxy; lift and agreement come from small local runs). Without a policy no decision is made."
        ),
    }


def _apply_policy(rules: dict[str, Any], diff: dict[str, Any], evidence: dict[str, Any]) -> tuple[str, list[str]]:
    """Policy keys (all optional): block_categories, review_categories (or "any"), min_load_rate,
    max_false_activation_rate, min_lift_percentage_points, min_kappa, require_evidence (list of column names)."""
    applied: list[str] = []
    level = 0  # 0 accept, 1 review, 2 block

    def raise_to(new_level: int, why: str) -> None:
        nonlocal level
        level = max(level, new_level)
        applied.append(f"{DECISIONS[new_level]}: {why}")

    for category in rules.get("block_categories", []):
        if category in diff["added"]:
            raise_to(2, f"added {category}")
    review = rules.get("review_categories", [])
    for category in diff["added"]:
        if review == "any" or category in review:
            raise_to(1, f"added {category}")
    new_load = evidence["load_rate"]["new"] or {}
    if "min_load_rate" in rules:
        rate = new_load.get("activation_rate")
        if rate is None or rate < rules["min_load_rate"]:
            raise_to(1, f"load rate {rate} below {rules['min_load_rate']}")
    if "max_false_activation_rate" in rules:
        rate = new_load.get("false_activation_rate")
        if rate is None or rate > rules["max_false_activation_rate"]:
            raise_to(1, f"false activation {rate} above {rules['max_false_activation_rate']}")
    if "min_lift_percentage_points" in rules:
        lift = (evidence["lift"]["new"] or {}).get("lift_percentage_points")
        if lift is None or lift < rules["min_lift_percentage_points"]:
            raise_to(1, f"lift {lift} below {rules['min_lift_percentage_points']}")
    if "min_kappa" in rules:
        kappa = (evidence["grader_agreement"] or {}).get("cohen_kappa")
        if kappa is None or kappa < rules["min_kappa"]:
            raise_to(1, f"grader kappa {kappa} below {rules['min_kappa']}")
    return DECISIONS[level], applied
