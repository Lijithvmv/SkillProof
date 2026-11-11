"""Install-wide checks: duplicate skill names and competing descriptions across every skill an agent can see.

A single skill can be fine on its own and still cause trouble next to the others:

- **Duplicate names.** The same name installed from two places (a plugin and a synced folder, say). If both copies
  are identical this is clutter. If they differ, which version an agent loads depends on the tool's precedence
  rules, so a reviewer may be approving one version while another one runs.
- **Competing descriptions.** An agent picks a skill from its description. Two descriptions that say nearly the
  same thing compete for the same requests, and a load-rate test showed a close competitor can take a task
  completely.

Overlap uses IDF-weighted Jaccard similarity on description words; the 0.3 threshold comes from the
skills-manager project and has not been validated here, so treat overlaps as candidates to look at.
"""
from __future__ import annotations

import hashlib
import itertools
import math
import re
from pathlib import Path
from typing import Any

import yaml

from skillproof.capabilities import read_package_bytes
from skillproof.ingestion import PackageError

FRONTMATTER = re.compile(r"\A---\s*\r?\n(.*?)\r?\n---", re.S)
WORD = re.compile(r"[a-z][a-z0-9]+")
STOP = {"the", "and", "for", "with", "use", "when", "this", "that", "from", "into", "your", "you", "are", "any",
        "can", "skill", "skills", "user", "users", "asks", "using", "used", "also", "about", "such", "their"}


def _skill_dirs(roots: list[str | Path]) -> list[Path]:
    found = set()
    for root in roots:
        for path in Path(root).rglob("SKILL.md"):
            if not {"node_modules", ".git"} & set(path.parts):
                found.add(path.parent)
    return sorted(found)


def _metadata(skill_md: Path) -> dict[str, str]:
    match = FRONTMATTER.match(skill_md.read_text(encoding="utf-8", errors="replace"))
    try:
        data = yaml.safe_load(match.group(1)) if match else None
    except yaml.YAMLError:
        data = None
    if not isinstance(data, dict) and match:
        # Invalid YAML (often an unquoted colon inside the description) is reported by the analyzer; for the
        # inventory, read the plain "key: value" lines so the skill is still compared.
        data = dict(re.findall(r"^(name|description):\s*(.+?)\s*$", match.group(1), re.M))
    data = data if isinstance(data, dict) else {}
    return {"name": str(data.get("name") or "").strip(), "description": str(data.get("description") or "").strip()}


def _fingerprint(directory: Path) -> str:
    digest = hashlib.sha256()
    for name, content in sorted(read_package_bytes(directory).items()):
        digest.update(name.encode("utf-8") + b"\0" + content + b"\0")
    return digest.hexdigest()


def _terms(text: str) -> set[str]:
    return {w for w in WORD.findall(text.lower()) if len(w) > 2 and w not in STOP}


def inventory(roots: list[str | Path], *, overlap_threshold: float = 0.3) -> dict[str, Any]:
    skills = []
    errors = []
    for directory in _skill_dirs(roots):
        meta = _metadata(directory / "SKILL.md")
        try:
            fingerprint = _fingerprint(directory)
        except (OSError, PackageError) as exc:
            errors.append({"path": str(directory), "error": str(exc)})
            continue
        skills.append({"name": meta["name"] or directory.name, "description": meta["description"], "path": str(directory), "fingerprint": fingerprint})

    by_name: dict[str, list[dict[str, Any]]] = {}
    for skill in skills:
        by_name.setdefault(skill["name"], []).append(skill)
    duplicates = []
    for name, copies in sorted(by_name.items()):
        if len(copies) > 1:
            versions = len({copy["fingerprint"] for copy in copies})
            duplicates.append({
                "name": name,
                "copies": len(copies),
                "distinct_versions": versions,
                "status": "divergent" if versions > 1 else "identical",
                "paths": [copy["path"] for copy in copies],
            })

    # One entry per name, so a skill installed twice does not overlap with itself.
    unique = [copies[0] for copies in by_name.values() if copies[0]["description"]]
    documents = [_terms(skill["description"]) for skill in unique]
    frequency: dict[str, int] = {}
    for terms in documents:
        for term in terms:
            frequency[term] = frequency.get(term, 0) + 1
    count = len(documents)
    idf = {term: math.log((count + 1) / (n + 0.5)) for term, n in frequency.items()}
    overlaps = []
    for i, j in itertools.combinations(range(len(unique)), 2):
        union = documents[i] | documents[j]
        if not union:
            continue
        score = sum(idf[t] for t in documents[i] & documents[j]) / sum(idf[t] for t in union)
        if score >= overlap_threshold:
            overlaps.append({"skills": sorted([unique[i]["name"], unique[j]["name"]]), "similarity": round(score, 3),
                             "shared_terms": sorted(documents[i] & documents[j])[:12]})
    overlaps.sort(key=lambda item: -item["similarity"])
    return {
        "method": "install_inventory",
        "skills_found": len(skills),
        "distinct_names": len(by_name),
        "duplicate_names": duplicates,
        "divergent_duplicates": sum(item["status"] == "divergent" for item in duplicates),
        "description_overlaps": overlaps,
        "overlap_threshold": overlap_threshold,
        "errors": errors,
        "limitations": (
            "Which duplicate an agent loads depends on that tool's precedence rules, which this check does not know. "
            "Overlap is lexical: two descriptions can compete without sharing words, and the threshold is unvalidated."
        ),
    }
