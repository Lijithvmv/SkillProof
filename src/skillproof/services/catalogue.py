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


def load_rate_evidence(records: list[dict[str, Any]], cited: list[str]) -> dict[str, Any] | None:
    """The most recent cited experiment that measured load rate (records come newest first), or None."""
    wanted = set(cited)
    for r in records:
        load = ((r.get("summary") or {}).get("comparison") or {}).get("load_rate")
        if r["experiment_id"] in wanted and isinstance(load, dict):
            relevant, unrelated = load.get("relevant") or {}, load.get("unrelated") or {}
            return {"experiment_id": r["experiment_id"], "activation_rate": relevant.get("activation_rate"),
                    "relevant_trials": relevant.get("trials"), "false_activation_rate": unrelated.get("false_activation_rate"),
                    "unrelated_trials": unrelated.get("trials"), "candidate_skills": load.get("candidate_skills"),
                    "interval_95": relevant.get("interval_95"), "worst_request_rate": relevant.get("worst_request_rate"),
                    "false_interval_95": unrelated.get("interval_95"),
                    "requests_lost_to": relevant.get("requests_lost_to"),
                    "expected_lift_percentage_points": load.get("expected_lift_percentage_points"), "model": load.get("model"),
                    "competitors": (load.get("competitors") or {}).get("selection")}
    return None


def apply_load_rate(assurance: dict[str, Any], evidence: dict[str, Any] | None,
                    thresholds: dict[str, float] | None = None) -> None:
    """The LOAD_RATE gate. A skill agents rarely pick for the requests it is for does little, and one they pick for
    unrelated requests gets in the way: either makes the version not ready. Without a load-rate run the gate says so
    and does not change the decision.

    With a 95% interval (recorded runs have one), the gate decides only what the data can show: fail when the whole
    interval is below the floor (or, for unrelated requests, above the ceiling), pass when it is clear of it, and
    insufficient evidence when the threshold lies inside the interval. On real data two runs of one skill gave 3 of 8
    and 9 of 12, on either side of the 50% floor, with intervals 14-69% and 47-91%: a hard verdict there is noise."""
    from skillproof.config import settings

    floor = (thresholds or {}).get("min_load_rate", settings().min_load_rate)
    ceiling = (thresholds or {}).get("max_false_load_rate", settings().max_false_load_rate)
    gates = assurance.setdefault("gates", [])
    if evidence is None or evidence.get("activation_rate") is None:
        gates.append({"code": "LOAD_RATE", "status": "not_measured",
                      "message": "How often agents pick this skill from its description was not measured (evaluate-skill --load-rate)."})
        return
    assurance["load_rate"] = evidence
    rate, false_rate = evidence["activation_rate"], evidence.get("false_activation_rate")
    among = f"among {evidence.get('candidate_skills')} competing skills"
    interval = evidence.get("interval_95")
    if interval:
        among += f" (95% interval {interval[0]:.0%} to {interval[1]:.0%} over {evidence.get('relevant_trials')} choices)"
    lost = evidence.get("requests_lost_to") or {}
    if lost:
        among += "; lost requests to " + ", ".join(f"{name} ({len(indexes)})" for name, indexes in lost.items())
    low, high = interval if interval else (rate, rate)
    false_interval = evidence.get("false_interval_95")
    false_low = false_interval[0] if false_interval else false_rate
    problems, unsure = [], []
    if high < floor:
        problems.append(f"picked for {rate:.0%} of the requests it is for {among} (minimum {floor:.0%})")
    elif low < floor:
        unsure.append(f"picked for {rate:.0%} of the requests it is for {among}: the minimum {floor:.0%} lies inside the "
                      "interval, so run more choices before deciding")
    if false_rate is not None and false_low is not None and false_low > ceiling:
        problems.append(f"picked for {false_rate:.0%} of unrelated requests (maximum {ceiling:.0%})")
    elif false_rate is not None and false_rate > ceiling:
        unsure.append(f"picked for {false_rate:.0%} of unrelated requests, above the maximum {ceiling:.0%} but within the "
                      "uncertainty of the run")
    if problems:
        gates.append({"code": "LOAD_RATE", "status": "fail", "message": "Agents " + " and ".join(problems + unsure) + "."})
        if assurance.get("decision") != "blocked":
            assurance["decision"] = "not_ready"
    elif unsure:
        gates.append({"code": "LOAD_RATE", "status": "insufficient_evidence", "message": "Agents " + " and ".join(unsure) + "."})
        if assurance.get("decision") in {"eligible_for_human_approval", "human_review_required"}:
            assurance["decision"] = "insufficient_evidence"
    else:
        unrelated = "not measured" if false_rate is None else f"{false_rate:.0%}"
        gates.append({"code": "LOAD_RATE", "status": "pass",
                      "message": f"Agents picked it for {rate:.0%} of the requests it is for {among}; unrelated requests: {unrelated}."})


def assess_package(governance: GovernanceAccess, principal: Principal, files: dict[str, bytes], *,
                   oversize: dict[str, str] | None = None, name: str | None = None, folder: str | None = None,
                   declared: dict[str, Any] | None = None, cite: list[str] | None = None, cite_all_runs: bool = False,
                   policy: AssurancePolicy | None = None, authored: dict[str, Any] | None = None,
                   source: authorship_rules.Source = "upload", binding: tuple[bool, str] | None = None) -> Assessment:
    """Analyse a package and assess it for registration.

    Run evidence: `cite` names recorded experiments (each must have run this SKILL.md); `cite_all_runs` cites every
    run recorded for it; `declared` carries numbers typed by the uploader (labelled as declared, never as measured).
    The policy is the tenant's stored policy unless one is given.

    Authorship: `authored` is what the registering identity declares about who wrote the package; together with
    whether that identity is a person or an agent, and the source, it decides the review bar (skillproof.provenance).
    A version not attested as human-written is compared with nothing, as a new skill, and the assurance report records
    the author kind, so an approval is bound to it."""
    from skillproof.config import settings

    key = authorship_rules.sign_in_key(principal) if settings().human_attestation_once_per_sign_in else None
    used_by = governance.attestation_of(principal, key) if key and source != "installed_import" else None
    authorship = dict(authorship_rules.resolve(principal, authored, source=source, sign_in_used_by=used_by, binding=binding))
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

    change = governance.preview_change(principal, catalogue_name, manifest, full_review=authorship_rules.full_review(authorship),
                                       exclude_fingerprint=report["package_fingerprint"])
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
    apply_load_rate(assurance, load_rate_evidence(records, cited) if cite or cite_all_runs else None,
                    governance.gate_settings(principal)["settings"])
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
    observed = observed_behaviour(records, matching) or previous.get("observed_behaviour")
    if observed:
        report["observed_behaviour"] = observed
    apply_load_rate(report, load_rate_evidence(records, matching), governance.gate_settings(principal)["settings"])
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
