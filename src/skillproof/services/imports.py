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

from skillproof import package
from skillproof.authorization import GovernanceAccess, Principal
from skillproof.governance import AssurancePolicy
from skillproof.ingestion import PackageError
from skillproof.engines.installed import NAME, family_key, find_skill_dirs
from skillproof.models import SkillVersion
from skillproof.services import alerts, catalogue

# Which agent a skill belongs to, from the folder it was found under. Used only to tell apart skills that share a name.
SOURCE_LABELS = {
    ".claude": "claude-code", ".codex": "codex", ".cursor": "cursor", ".agents": "agents",
    "extensions": "vscode-extension", "microsoft vs code": "vscode", "claude": "claude-desktop",
}


def source_label(root: Path) -> str:
    return SOURCE_LABELS.get(root.name.lower(), root.name.lower() or "local")


def _package(skill_dir: Path) -> tuple[dict[str, bytes], dict[str, str], str]:
    """Files, files too large to read, and the canonical package fingerprint of an installed skill folder."""
    files, oversize = package.read_folder(skill_dir)
    return files, oversize, package.fingerprint(files, oversize)


def _skill_name(files: dict[str, bytes], skill_dir: Path) -> str:
    match = NAME.search(files.get("SKILL.md", b"").decode("utf-8", "replace")[:2000])
    return match.group(1).strip() if match else skill_dir.name


def check_installed(governance: GovernanceAccess, principal: Principal, roots: list[Path]) -> dict[str, Any]:
    """Compare what is installed with what the catalogue approved, without registering anything.

    For every installed skill: `approved` when its folder fingerprint is the tenant's active version, `running_unapproved`
    when an approved version exists but the installed folder differs from it (the alert: something changed the skill
    after approval, or an unapproved update was installed), `never_approved` when nothing is approved for that name."""
    families, names_by_family, packages, errors = installed_families(roots)
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
        change = (known or {}).get("capability_change")
        if status == "running_unapproved" and change:
            entry["adds_over_approved"] = {"decision": change.get("decision"), "counts": change.get("counts"),
                                           "against": change.get("against")}
        skills.append(entry)
    counts = {s: sum(e["status"] == s for e in skills) for s in ("approved", "running_unapproved", "never_approved")}
    import socket

    for entry in (e for e in skills if e["status"] == "running_unapproved"):
        alerts.fleet_unapproved(governance, principal.tenant_id, socket.gethostname(), {
            "skill_name": entry["skill_name"], "installed_fingerprint": entry["installed_fingerprint"],
            "approved_version_id": entry["approved_version_id"], "adds_over_approved": entry.get("adds_over_approved") or {}})
    return {"method": "installed_vs_approved", "tenant_id": principal.tenant_id, "roots": [str(r) for r in roots],
            "skills_found": len(skills), **counts,
            "alerts": [e for e in skills if e["status"] == "running_unapproved"], "skills": skills, "errors": errors}


def installed_families(roots: list[Path]):
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
    for key, (_root, skill_dir) in sorted(families.items()):
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
    # One catalogue name per install family (see installed_families): a name shared by different families gets the
    # agent label, then a short path hash if still ambiguous.
    families, names_by_family, packages, errors = installed_families(roots)

    registered: list[dict[str, Any]] = []
    evidence_not_attached: list[dict[str, Any]] = []
    reassessed: list[dict[str, Any]] = []
    known: dict[str, list[SkillVersion]] = {}
    backfilled: list[dict[str, Any]] = []
    unchanged = 0
    for key, name in sorted(names_by_family.items(), key=lambda pair: pair[1]):
        root, skill_dir = families[key]
        files, oversize, fingerprint = packages[key]
        existing = next((v for v in known.setdefault(name, governance.list_skill_versions(principal, name))
                         if v["package_fingerprint"] == fingerprint), None)
        if existing is not None:
            unchanged += 1  # recognised by its fingerprint before any analysis
            if governance.artifacts is not None and not oversize and not governance.artifacts.has(principal.tenant_id, fingerprint):
                # Registered before packages were kept: these are its exact bytes (same fingerprint), so keep them now and
                # the version becomes distributable.
                governance.store_package(principal, files)
                backfilled.append({"skill_name": name, "version_id": existing["version_id"], "state": existing["state"]})
            skill_md = package.skill_md(package.as_text(files))
            _, matching = catalogue.runs_for(governance, principal, name, skill_md)
            had = set(((existing.get("assurance") or {}).get("evidence") or {}).get("experiment_ids") or [])
            if not set(matching) - had:
                continue
            # Runs recorded after registration: a version waiting for a decision is assessed again on them; an approved
            # version keeps the report it was approved on and the new runs are listed for the reviewer.
            version = catalogue.reassess_on_runs(governance, principal, existing, skill_md, policy)
            if version is not None:
                reassessed.append({"skill_name": name, "version_id": version["version_id"], "state": version["state"],
                                   "assurance_decision": (version.get("assurance") or {}).get("decision"), "experiments": sorted(matching)})
            else:
                evidence_not_attached.append({"skill_name": name, "version_id": existing["version_id"],
                                              "state": existing["state"], "experiments": sorted(set(matching) - had)})
            continue
        assessment = catalogue.assess_package(governance, principal, files, oversize=oversize, name=name,
                                              folder=skill_dir.name, cite_all_runs=True, policy=policy)
        version = catalogue.register(governance, principal, assessment, artifact_uri=skill_dir.as_uri())
        change = version["capability_change"] or {}
        registered.append({
            "skill_name": name, "version_id": version["version_id"], "path": str(skill_dir),
            "against": change.get("against"), "decision": change.get("decision"), "counts": change.get("counts"),
            "state": version["state"], "assurance_decision": assessment.assurance["decision"],
            "evidence": assessment.assurance["evidence"].get("source"),
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
        "packages_stored_for_existing_versions": backfilled,
        "evidence_not_attached": evidence_not_attached,
        "errors": errors,
        "limitations": "A skill's assurance cites the experiments recorded for its exact SKILL.md (evaluate-skill); "
                       "without them it stays insufficient_evidence. A version still waiting for a decision is assessed "
                       "again when new runs exist (an approval request made on the old report no longer matches); an "
                       "approved version keeps its report and new runs are listed under evidence_not_attached. A first "
                       "import has no earlier version to compare with, so every capability a skill has counts as added.",
    }

