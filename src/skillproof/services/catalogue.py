"""Assessing a skill package for the catalogue: the single place that turns files into a registered version's
analysis, capability manifest and assurance report. The API upload, the installed-skill importer and the evaluation
worker all use it, so the same package is always judged by the same rules (static analysis, capability change against
the approved version, run evidence, the tenant's policy)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from skillproof import package, provenance as authorship_rules
from skillproof.ingestion import PackageError
from skillproof.engines.analyzer import analyze_files
from skillproof.authorization import GovernanceAccess, Principal
from skillproof.engines.capabilities import build_manifest
from skillproof.evidence import instructions_fingerprint, measured_evidence
from skillproof.governance import AssuranceInput, AssurancePolicy, SecurityFinding, assess_version
from skillproof.models import EvaluationJob, SkillVersion
from skillproof.engines.second_opinion import add_second_opinions
from skillproof.engines.triage import LEVELS
from skillproof.services import alerts


@dataclass
class Assessment:
    report: dict[str, Any]          # static analysis, with the canonical package fingerprint and the catalogue name
    manifest: dict[str, Any]        # capability manifest (with second opinions when configured)
    assurance: dict[str, Any]       # gates and decision, with inputs, policy, evidence provenance and subject
    skill_md: str                   # the main SKILL.md text the run evidence is bound to
    files: dict[str, bytes] = field(default_factory=dict)      # the package itself, kept so it can be distributed
    oversize: dict[str, str] = field(default_factory=dict)     # files too large to read (installed folders only)
    authorship: dict[str, Any] | None = None                    # who wrote it (skillproof.provenance), stored with the version

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


def observed_behaviour(records: list[dict[str, Any]], cited: list[str]) -> dict[str, Any] | None:
    """What the cited sandboxed runs showed the skill makes agents do (trajectory.summarize per experiment), merged:
    the highest decision, and the rule hits and undeclared behaviours the skill caused. None when no cited experiment
    was sandboxed."""
    wanted = set(cited)
    found: list[tuple[str, dict[str, Any]]] = []
    for r in records:
        b = ((r.get("summary") or {}).get("comparison") or {}).get("behaviour")
        if r["experiment_id"] in wanted and isinstance(b, dict):
            found.append((r["experiment_id"], b))
    if not found:
        return None
    decision = max((b["decision"] for _, b in found), key=lambda level: LEVELS.get(level, 0))
    counts = {level: max(b["counts"].get(level, 0) for _, b in found) for level in LEVELS}
    hits = [{**h, "experiment_id": e} for e, b in found for h in b.get("rule_hits", []) if h.get("caused_by_skill")]
    undeclared = [{**h, "experiment_id": e} for e, b in found for h in b.get("behaviours", [])
                  if h.get("caused_by_skill") and h.get("declared") is False]
    return {"experiments": [e for e, _ in found], "decision": decision, "counts": counts,
            "rule_hits_caused_by_skill": hits[:20], "undeclared_behaviours": undeclared[:20],
            "runs": {e: b.get("runs") for e, b in found}}


def assess_package(governance: GovernanceAccess, principal: Principal, files: dict[str, bytes], *,
                   oversize: dict[str, str] | None = None, name: str | None = None, folder: str | None = None,
                   declared: dict[str, Any] | None = None, cite: list[str] | None = None, cite_all_runs: bool = False,
                   policy: AssurancePolicy | None = None, authored: dict[str, Any] | None = None,
                   source: authorship_rules.Source = "upload") -> Assessment:
    """Analyse a package and assess it for registration.

    Run evidence: `cite` names recorded experiments (each must have run this SKILL.md); `cite_all_runs` cites every
    run recorded for it; `declared` carries numbers typed by the uploader (labelled as declared, never as measured).
    The policy is the tenant's stored policy unless one is given.

    Authorship: `authored` is what the registering identity declares about who wrote the package; together with
    whether that identity is a person or an agent, and the source, it decides the review bar (skillproof.provenance).
    A version not attested as human-written is compared with nothing, as a new skill, and the assurance report records
    the author kind, so an approval is bound to it."""
    authorship = dict(authorship_rules.resolve(principal, authored, source=source))
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
    observed = None
    if cite or cite_all_runs:
        records, matching = runs_for(governance, principal, catalogue_name, skill_md)
        cited = list(cite or []) or matching
        observed = observed_behaviour(records, cited)
        if cited:
            measured = measured_evidence(records, cited, skill_md)
            provenance = measured.pop("provenance")
            behaviour = measured
    elif declared:
        behaviour, provenance = dict(declared), {"source": "declared_by_uploader"}

    change = governance.preview_change(principal, catalogue_name, manifest, full_review=authorship_rules.full_review(authorship))
    security = report.get("security") or {}
    decision, counts = change["decision"], dict(change["counts"])
    if observed and LEVELS.get(observed["decision"], 0) > LEVELS.get(decision, 0):
        # What the skill made agents do in sandboxed runs outranks what its files show: the gate sees the higher one.
        decision = observed["decision"]
        counts = {level: max(counts.get(level, 0), observed["counts"].get(level, 0)) for level in LEVELS}
    assurance = assess_version(AssuranceInput(
        structural_score=report.get("structural_score"),
        instruction_quality_score=(report.get("instruction_quality") or {}).get("quality_score"),
        security_score=security.get("security_score"),
        security_findings=[SecurityFinding(code=f["code"], severity=f["severity"]) for f in security.get("findings", [])],
        capability_decision=decision, capability_counts=counts,
        **behaviour,
    ), policy or governance.tenant_policy(principal))
    assurance["evidence"] = provenance
    if observed:
        assurance["observed_behaviour"] = observed
    # Bind the report to this exact package so an approval of one version can never promote another.
    assurance["subject"] = {"tenant_id": principal.tenant_id, "skill_name": catalogue_name, "package_fingerprint": report["package_fingerprint"]}
    assurance["authorship"] = {"author_kind": authorship["author_kind"], "review_bar": authorship["review_bar"]}
    return Assessment(report=report, manifest=manifest, assurance=assurance, skill_md=skill_md, files=files,
                      oversize=dict(oversize or {}), authorship=authorship)


def reassess_on_runs(governance: GovernanceAccess, principal: Principal, version: SkillVersion, skill_md: str,
                     policy: AssurancePolicy | None = None) -> SkillVersion | None:
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
    previous = version.get("assurance")
    if not previous:
        return None
    report = reassess_with_runs(dict(previous), measured, provenance, policy or governance.tenant_policy(principal))
    if "authorship" in previous:  # who wrote it does not change with new runs
        report["authorship"] = previous["authorship"]
    return governance.reassess_skill(principal, version["version_id"], report)


def register(governance: GovernanceAccess, principal: Principal, assessment: Assessment, *, artifact_uri: str | None = None) -> SkillVersion:
    """Register the version and keep its exact package so the catalogue can distribute it once approved. A package
    that cannot be kept (a file over the size limit, or more files than a package may hold) is still registered and
    analysed; it is reported as not distributable."""
    version = governance.register_skill(principal, assessment.report, assessment.assurance, artifact_uri=artifact_uri,
                                        capability_manifest=assessment.manifest, provenance=assessment.authorship)
    if governance.artifacts is not None and assessment.files:
        try:
            governance.store_package(principal, assessment.files, assessment.oversize)
            version["distributable"] = True
        except (ValueError, PackageError) as exc:
            version["distributable"] = False
            version["not_distributable_reason"] = str(exc)
    alerts.version_registered(governance, principal, version)
    return version


def promote(governance: GovernanceAccess, principal: Principal, version_id: str, request_id: str, *, capability_ack: str | None = None) -> SkillVersion:
    version = governance.promote_version(principal, version_id, request_id, capability_ack=capability_ack)
    alerts.version_promoted(governance, principal, version, request_id)
    return version


def rollback(governance: GovernanceAccess, principal: Principal, skill_name: str, reason: str) -> SkillVersion:
    restored = governance.rollback_skill(principal, skill_name, reason)
    alerts.version_rolled_back(governance, principal, skill_name, restored, reason)
    return restored


def request_evaluation(governance: GovernanceAccess, principal: Principal, version_id: str, skill_md: str) -> EvaluationJob:
    """Queue a run-evidence job for a version, bound to the exact SKILL.md text it holds."""
    payload = {"skill_md": skill_md, "instructions_fingerprint": instructions_fingerprint(skill_md)}
    return governance.enqueue_evaluation(principal, version_id, payload)
