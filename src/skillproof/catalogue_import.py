"""Feed the skills installed on this machine into the catalogue.

Each installed skill folder becomes a registered version. Run it again after skills update: an unchanged folder is
recognised by its fingerprint and skipped, and a changed one becomes a new version that the registry compares with
the active version (or, while nothing is approved yet, with the previous version) and ranks block / ask / note.

Installed skills arrive with static evidence only (structure, instruction quality, security scan), so their assurance
decision is "insufficient_evidence" until run evidence is supplied. That is the honest state of a skill nobody has
measured; it does not stop the comparison from showing what each update adds.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

from skillproof.analyzer import analyze_files
from skillproof.authorization import GovernanceAccess, Principal
from skillproof.capabilities import PackageError, build_manifest
from skillproof.evidence import instructions_fingerprint, measured_evidence
from skillproof.governance import AssuranceInput, AssurancePolicy, assess_version
from skillproof.second_opinion import add_second_opinions
from skillproof.installed import NAME, _read_installed, family_key, find_skill_dirs

# Which agent a skill belongs to, from the folder it was found under. Used only to tell apart skills that share a name.
SOURCE_LABELS = {
    ".claude": "claude-code", ".codex": "codex", ".cursor": "cursor", ".agents": "agents",
    "extensions": "vscode-extension", "microsoft vs code": "vscode", "claude": "claude-desktop",
}


def source_label(root: Path) -> str:
    return SOURCE_LABELS.get(root.name.lower(), root.name.lower() or "local")


def _package(skill_dir: Path) -> tuple[dict[str, bytes], dict[str, str], str]:
    files, oversize = _read_installed(skill_dir)
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name])
    for name in sorted(oversize):  # a change inside an unscanned file still changes the fingerprint
        digest.update(name.encode() + b"\0" + oversize[name].encode())
    return files, oversize, digest.hexdigest()


def _skill_name(files: dict[str, bytes], skill_dir: Path) -> str:
    match = NAME.search(files.get("SKILL.md", b"").decode("utf-8", "replace")[:2000])
    return match.group(1).strip() if match else skill_dir.name


def check_installed(governance: GovernanceAccess, principal: Principal, roots: list[Path]) -> dict[str, Any]:
    """Compare what is installed with what the catalogue approved, without registering anything.

    For every installed skill: `approved` when its folder fingerprint is the tenant's active version, `running_unapproved`
    when an approved version exists but the installed folder differs from it (the alert: something changed the skill
    after approval, or an unapproved update was installed), `never_approved` when nothing is approved for that name."""
    families, names_by_family, packages, errors = _installed_families(roots)
    skills: list[dict[str, Any]] = []
    for key, name in sorted(names_by_family.items(), key=lambda pair: pair[1]):
        _, skill_dir = families[key]
        fingerprint = packages[key][2]
        versions = governance.list_skill_versions(principal, name)
        active = next((v for v in versions if v["state"] == "active"), None)
        known = next((v for v in versions if v["package_fingerprint"] == fingerprint), None)
        status = "never_approved" if active is None else "approved" if active["package_fingerprint"] == fingerprint else "running_unapproved"
        entry = {"skill_name": name, "path": str(skill_dir), "status": status, "installed_fingerprint": fingerprint,
                 "approved_version_id": active["version_id"] if active else None,
                 "approved_fingerprint": active["package_fingerprint"] if active else None,
                 "installed_version_id": known["version_id"] if known else None}
        if status == "running_unapproved" and known and known.get("capability_change"):
            change = known["capability_change"]
            entry["adds_over_approved"] = {"decision": change.get("decision"), "counts": change.get("counts"),
                                           "against": change.get("against")}
        skills.append(entry)
    counts = {s: sum(e["status"] == s for e in skills) for s in ("approved", "running_unapproved", "never_approved")}
    import socket

    for entry in (e for e in skills if e["status"] == "running_unapproved"):
        governance.emit(principal.tenant_id, "fleet.running_unapproved", {
            "skill_name": entry["skill_name"], "host": socket.gethostname(), "installed_fingerprint": entry["installed_fingerprint"],
            "approved_version_id": entry["approved_version_id"], "adds_over_approved": entry.get("adds_over_approved")})
    return {"method": "installed_vs_approved", "tenant_id": principal.tenant_id, "roots": [str(r) for r in roots],
            "skills_found": len(skills), **counts,
            "alerts": [e for e in skills if e["status"] == "running_unapproved"], "skills": skills, "errors": errors}


def _installed_families(roots: list[Path]):
    found: list[tuple[Path, Path]] = []
    for root in roots:
        for skill_dir in find_skill_dirs([root]):
            found.append((root, skill_dir))
    families: dict[str, tuple[Path, Path]] = {}
    for root, skill_dir in found:
        families.setdefault(family_key(skill_dir), (root, skill_dir))
    names_by_family: dict[str, str] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    errors: list[dict[str, str]] = []
    packages: dict[str, tuple[dict[str, bytes], dict[str, str], str]] = {}
    for key, (root, skill_dir) in sorted(families.items()):
        try:
            packages[key] = _package(skill_dir)
        except (OSError, PackageError) as exc:
            errors.append({"path": str(skill_dir), "error": str(exc)})
            continue
        by_name[_skill_name(packages[key][0], skill_dir)].append(key)
    for name, keys in by_name.items():
        if len(keys) == 1:
            names_by_family[keys[0]] = name
            continue
        labelled: dict[str, list[str]] = defaultdict(list)
        for key in keys:
            labelled[f"{name} ({source_label(families[key][0])})"].append(key)
        for label, members in labelled.items():
            for key in members:
                names_by_family[key] = label if len(members) == 1 else f"{label[:-1]} {hashlib.sha256(key.encode()).hexdigest()[:6]})"
    return families, names_by_family, packages, errors


def import_installed(
    governance: GovernanceAccess, principal: Principal, roots: list[Path], policy: AssurancePolicy | None = None,
) -> dict[str, Any]:
    policy = policy or governance.tenant_policy(principal)  # the tenant's stored policy unless one is passed
    # One catalogue name per install family (see _installed_families): a name shared by different families gets the
    # agent label, then a short path hash if still ambiguous.
    families, names_by_family, packages, errors = _installed_families(roots)

    registered: list[dict[str, Any]] = []
    evidence_not_attached: list[dict[str, Any]] = []
    reassessed: list[dict[str, Any]] = []
    known: dict[str, list[dict[str, Any]]] = {}
    unchanged = 0
    for key, name in sorted(names_by_family.items(), key=lambda pair: pair[1]):
        root, skill_dir = families[key]
        files, oversize, fingerprint = packages[key]
        text = {}
        for path, raw in files.items():
            try:
                text[path] = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                text[path] = ""
        # Run evidence recorded for this exact SKILL.md (skillproof evaluate-skill) is cited automatically.
        skill_md = text.get("SKILL.md", "")
        records = governance.list_evaluations(principal, skill_key=name, limit=500)
        cited = [r["experiment_id"] for r in records if r["instructions_fingerprint"] == instructions_fingerprint(skill_md)]
        existing = next((v for v in known.setdefault(name, governance.list_skill_versions(principal, name))
                         if v["package_fingerprint"] == fingerprint), None)
        if existing is not None:
            unchanged += 1  # checked before any analysis, so a re-run only reads and hashes the folders
            had = set(((existing.get("assurance") or {}).get("evidence") or {}).get("experiment_ids") or [])
            if not set(cited) - had:
                continue
            if existing["state"] in {"pending_review", "not_eligible"}:
                # Runs recorded after registration: the version waiting for a decision is assessed again on them.
                report = _report(text, fingerprint, name)
                change = existing.get("capability_change") or {}
                assurance = _assurance(report, records, cited, skill_md, principal, name, fingerprint, policy, change)
                version = governance.reassess_skill(principal, existing["version_id"], assurance)
                reassessed.append({"skill_name": name, "version_id": version["version_id"], "state": version["state"],
                                   "assurance_decision": assurance["decision"], "experiments": sorted(cited)})
            else:
                # An approved version keeps the report it was approved on; new evidence is listed for the reviewer.
                evidence_not_attached.append({"skill_name": name, "version_id": existing["version_id"],
                                              "state": existing["state"], "experiments": sorted(set(cited) - had)})
            continue
        report = _report(text, fingerprint, name)
        manifest = build_manifest(files)
        add_second_opinions(manifest, files)
        manifest["not_scanned"] = sorted(oversize)
        change = governance.preview_change(principal, name, manifest)
        assurance = _assurance(report, records, cited, skill_md, principal, name, fingerprint, policy, change)
        provenance = assurance["evidence"]
        version = governance.register_skill(principal, report, assurance, artifact_uri=skill_dir.as_uri(), capability_manifest=manifest)
        change = version["capability_change"] or {}
        registered.append({
            "skill_name": name, "version_id": version["version_id"], "path": str(skill_dir),
            "against": change.get("against"), "decision": change.get("decision"), "counts": change.get("counts"),
            "state": version["state"], "assurance_decision": assurance["decision"], "evidence": provenance.get("source"),
        })
    updates = [r for r in registered if r["against"] != "nothing_active"]
    return {
        "method": "installed_skill_import",
        "tenant_id": principal.tenant_id,
        "roots": [str(root) for root in roots],
        "skills_found": len(names_by_family),
        "new_versions": len(registered),
        "unchanged": unchanged,
        "updates": len(updates),
        "updates_with_block": sum(r["decision"] == "block" for r in updates),
        "updates_with_ask": sum(r["decision"] == "ask" for r in updates),
        "registered": registered,
        "reassessed": reassessed,
        "evidence_not_attached": evidence_not_attached,
        "errors": errors,
        "limitations": "A skill's assurance cites the experiments recorded for its exact SKILL.md (evaluate-skill); "
                       "without them it stays insufficient_evidence. A version still waiting for a decision is assessed "
                       "again when new runs exist (an approval request made on the old report no longer matches); an "
                       "approved version keeps its report and new runs are listed under evidence_not_attached. A first "
                       "import has no earlier version to compare with, so every capability a skill has counts as added.",
    }


def _report(text: dict[str, str], fingerprint: str, name: str) -> dict[str, Any]:
    report = analyze_files(text)
    report["package_fingerprint"] = fingerprint
    report["metadata"] = dict(report.get("metadata") or {}, name=name)
    return report


def _assurance(report: dict[str, Any], records: list[dict[str, Any]], cited: list[str], skill_md: str,
               principal: Principal, name: str, fingerprint: str, policy: AssurancePolicy,
               change: dict[str, Any] | None = None) -> dict[str, Any]:
    behaviour: dict[str, Any] = {}
    provenance: dict[str, Any] = {"source": "none"}
    if cited:
        measured = measured_evidence(records, cited, skill_md)
        provenance = measured.pop("provenance")
        behaviour = measured
    security = report.get("security") or {}
    assurance = assess_version(AssuranceInput(
        structural_score=report.get("structural_score"),
        instruction_quality_score=(report.get("instruction_quality") or {}).get("quality_score"),
        security_score=security.get("security_score"),
        security_findings=[{"code": f["code"], "severity": f["severity"]} for f in security.get("findings", [])],
        capability_decision=(change or {}).get("decision"), capability_counts=(change or {}).get("counts"),
        **behaviour,
    ), policy)
    assurance["evidence"] = provenance
    assurance["subject"] = {"tenant_id": principal.tenant_id, "skill_name": name, "package_fingerprint": fingerprint}
    return assurance
