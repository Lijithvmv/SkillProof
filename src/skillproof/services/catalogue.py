"""Assessing a skill package for the catalogue: the single place that turns files into a registered version's
analysis, capability manifest and assurance report. The API upload, the installed-skill importer and the evaluation
worker all use it, so the same package is always judged by the same rules (static analysis, capability change against
the approved version, run evidence, the tenant's policy)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skillproof import package
from skillproof.analyzer import analyze_files
from skillproof.authorization import GovernanceAccess, Principal
from skillproof.capabilities import build_manifest
from skillproof.evidence import instructions_fingerprint, measured_evidence
from skillproof.governance import AssuranceInput, AssurancePolicy, assess_version
from skillproof.second_opinion import add_second_opinions


@dataclass
class Assessment:
    report: dict[str, Any]          # static analysis, with the canonical package fingerprint and the catalogue name
    manifest: dict[str, Any]        # capability manifest (with second opinions when configured)
    assurance: dict[str, Any]       # gates and decision, with inputs, policy, evidence provenance and subject
    skill_md: str                   # the main SKILL.md text the run evidence is bound to

    @property
    def name(self) -> str:
        return self.report["metadata"]["name"]

    @property
    def fingerprint(self) -> str:
        return self.report["package_fingerprint"]


def runs_for(governance: GovernanceAccess, principal: Principal, name: str, skill_md: str) -> tuple[list[dict[str, Any]], list[str]]:
    """The tenant's recorded runs for a skill name, and the ids of those that ran this exact SKILL.md."""
    records = governance.list_evaluations(principal, skill_key=name, limit=500)
    expected = instructions_fingerprint(skill_md)
    return records, [r["experiment_id"] for r in records if r["instructions_fingerprint"] == expected]


def assess_package(governance: GovernanceAccess, principal: Principal, files: dict[str, bytes], *,
                   oversize: dict[str, str] | None = None, name: str | None = None, folder: str | None = None,
                   declared: dict[str, Any] | None = None, cite: list[str] | None = None, cite_all_runs: bool = False,
                   policy: AssurancePolicy | None = None) -> Assessment:
    """Analyse a package and assess it for registration.

    Run evidence: `cite` names recorded experiments (each must have run this SKILL.md); `cite_all_runs` cites every
    run recorded for it; `declared` carries numbers typed by the uploader (labelled as declared, never as measured).
    The policy is the tenant's stored policy unless one is given."""
    text = package.as_text(files)
    # Authoring rules look at the skill's folder name (it should match the SKILL.md name); the package itself is rooted
    # at that folder, so the name is passed separately.
    report = analyze_files({f"{folder}/{p}": t for p, t in text.items()} if folder else text)
    report["package_fingerprint"] = package.fingerprint(files, oversize)
    if name:
        report["metadata"] = dict(report.get("metadata") or {}, name=name)
    catalogue_name = (report.get("metadata") or {}).get("name")
    if not catalogue_name or not isinstance(catalogue_name, str):
        raise ValueError("the package needs a SKILL.md with a name to be registered")
    skill_md = package.skill_md(text)
    manifest = build_manifest(files)
    add_second_opinions(manifest, files)
    manifest["not_scanned"] = sorted(oversize or {})

    behaviour: dict[str, Any] = {}
    provenance: dict[str, Any] = {"source": "none"}
    if cite or cite_all_runs:
        records, matching = runs_for(governance, principal, catalogue_name, skill_md)
        cited = list(cite or []) or matching
        if cited:
            measured = measured_evidence(records, cited, skill_md)
            provenance = measured.pop("provenance")
            behaviour = measured
    elif declared:
        behaviour, provenance = dict(declared), {"source": "declared_by_uploader"}

    change = governance.preview_change(principal, catalogue_name, manifest)
    security = report.get("security") or {}
    assurance = assess_version(AssuranceInput(
        structural_score=report.get("structural_score"),
        instruction_quality_score=(report.get("instruction_quality") or {}).get("quality_score"),
        security_score=security.get("security_score"),
        security_findings=[{"code": f["code"], "severity": f["severity"]} for f in security.get("findings", [])],
        capability_decision=change["decision"], capability_counts=change["counts"],
        **behaviour,
    ), policy or governance.tenant_policy(principal))
    assurance["evidence"] = provenance
    # Bind the report to this exact package so an approval of one version can never promote another.
    assurance["subject"] = {"tenant_id": principal.tenant_id, "skill_name": catalogue_name, "package_fingerprint": report["package_fingerprint"]}
    return Assessment(report=report, manifest=manifest, assurance=assurance, skill_md=skill_md)


def reassess_on_runs(governance: GovernanceAccess, principal: Principal, version: dict[str, Any], skill_md: str,
                     policy: AssurancePolicy | None = None) -> dict[str, Any] | None:
    """Assess a version still waiting for a decision again, on every run recorded for its exact SKILL.md, keeping its
    static inputs and judging on the tenant's policy now. Returns the updated version, or None when there is nothing
    new to judge or the version is no longer waiting (an approved version keeps the report it was approved on)."""
    from skillproof.governance import reassess_with_runs

    if version["state"] not in {"pending_review", "not_eligible"}:
        return None
    records, matching = runs_for(governance, principal, version["skill_name"], skill_md)
    if not matching:
        return None
    measured = measured_evidence(records, matching, skill_md)
    provenance = measured.pop("provenance")
    report = reassess_with_runs(version["assurance"], measured, provenance, policy or governance.tenant_policy(principal))
    return governance.reassess_skill(principal, version["version_id"], report)


def register(governance: GovernanceAccess, principal: Principal, assessment: Assessment, *, artifact_uri: str | None = None) -> dict[str, Any]:
    return governance.register_skill(principal, assessment.report, assessment.assurance, artifact_uri=artifact_uri,
                                     capability_manifest=assessment.manifest)
