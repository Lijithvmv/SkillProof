from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

import yaml
from skillproof.semantic import analyze_instructions
from skillproof.security import scan_security


class DuplicateKeyError(yaml.YAMLError):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.YAMLError("frontmatter contains an unhashable mapping key") from exc
        if duplicate:
            raise DuplicateKeyError(f"duplicate key {key!r} in frontmatter")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)

FRONTMATTER = re.compile(r"\A---\s*\r?\n(.*?)\r?\n---(?:\s*\r?\n|\Z)", re.DOTALL)
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)|!?\[[^\]]*\]\[([^\]]*)\]", re.MULTILINE)
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?", re.MULTILINE)


def _finding(code: str, severity: str, message: str, evidence: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message, "evidence": evidence[:500]}


def _normal_path(value: str) -> str:
    return str(PurePosixPath(value.replace("\\", "/")))


def analyze_files(files: dict[str, str]) -> dict[str, Any]:
    """Analyze an in-memory package represented by normalized relative paths."""
    normalized = {_normal_path(path).lstrip("./"): content for path, content in files.items()}
    skill_paths = sorted(path for path in normalized if PurePosixPath(path).name == "SKILL.md")
    findings: list[dict[str, str]] = []
    if not skill_paths:
        findings.append(_finding("SKILL_MISSING", "error", "No SKILL.md file was found.", "Expected a SKILL.md at the skill root."))
        main_path, body, metadata = "", "", {}
    else:
        main_path = skill_paths[0]
        if len(skill_paths) > 1:
            findings.append(_finding("MULTIPLE_SKILLS", "warning", "Multiple SKILL.md files were found; the first is analyzed.", ", ".join(skill_paths)))
        source = normalized[main_path]
        match = FRONTMATTER.match(source)
        metadata = {}
        body = source
        if not match:
            findings.append(_finding("FRONTMATTER_MISSING", "error", "SKILL.md must begin with YAML frontmatter delimited by ---.", source[:160]))
        else:
            body = source[match.end():]
            try:
                parsed = yaml.load(match.group(1), Loader=UniqueKeyLoader)
                if not isinstance(parsed, dict):
                    findings.append(_finding("FRONTMATTER_TYPE", "error", "YAML frontmatter must be a mapping.", type(parsed).__name__))
                else:
                    metadata = parsed
            except DuplicateKeyError as exc:
                findings.append(_finding("YAML_DUPLICATE_KEY", "error", "YAML frontmatter contains a duplicate key.", str(exc)))
            except yaml.YAMLError as exc:
                findings.append(_finding("YAML_INVALID", "error", "YAML frontmatter could not be parsed.", str(exc)))

        for key in ("name", "description"):
            value = metadata.get(key)
            if value is None or value == "":
                findings.append(_finding(f"METADATA_{key.upper()}_MISSING", "error", f"Required metadata '{key}' is missing.", f"frontmatter.{key}"))
            elif not isinstance(value, str):
                findings.append(_finding(f"METADATA_{key.upper()}_TYPE", "error", f"Metadata '{key}' must be a string.", f"frontmatter.{key} is {type(value).__name__}"))
        name = metadata.get("name")
        if isinstance(name, str):
            if len(name) > 64:
                findings.append(_finding("NAME_TOO_LONG", "error", "Skill name exceeds 64 characters.", f"Length: {len(name)}"))
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
                findings.append(_finding("NAME_FORMAT", "error", "Skill name must use lowercase letters, numbers, and single hyphens.", name))
            directory = str(PurePosixPath(main_path).parent)
            if directory not in (".", "") and PurePosixPath(directory).name != name:
                findings.append(_finding("DIRECTORY_NAME_MISMATCH", "warning", "Skill directory name does not match frontmatter name.", f"directory={directory}, name={name}"))
        description = metadata.get("description")
        if isinstance(description, str) and len(description) > 1024:
            findings.append(_finding("DESCRIPTION_TOO_LONG", "error", "Description exceeds 1024 characters.", f"Length: {len(description)}"))

    references: dict[str, list[str]] = defaultdict(list)
    for source_path, content in normalized.items():
        if not source_path.lower().endswith(".md"):
            continue
        targets: list[str] = []
        for match in LINK.finditer(content):
            raw = (match.group(1) or match.group(2) or "").strip()
            if not raw or raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            raw = raw.split("#", 1)[0].split("?", 1)[0]
            if not raw:
                continue
            target = _normal_path(str(PurePosixPath(source_path).parent / raw)).lstrip("./")
            targets.append(target)
        for raw in REF_DEF.findall(content):
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = _normal_path(str(PurePosixPath(source_path).parent / raw.split("#", 1)[0])).lstrip("./")
            targets.append(target)
        references[source_path] = sorted(set(targets))

    referenced = {target for values in references.values() for target in values}
    missing = sorted(target for target in referenced if target not in normalized)
    for target in missing:
        sources = [source for source, values in references.items() if target in values]
        findings.append(_finding("BROKEN_REFERENCE", "error", f"Referenced file '{target}' does not exist.", ", ".join(sources)))
    orphans = sorted(path for path in normalized if path.lower().endswith(".md") and path != main_path and path not in referenced)
    for orphan in orphans:
        findings.append(_finding("ORPHAN_REFERENCE_FILE", "info", f"Markdown file '{orphan}' is not referenced by another Markdown file.", orphan))

    main_lines = len(normalized.get(main_path, "").splitlines()) if main_path else 0
    if main_path and main_lines > 500:
        findings.append(_finding("SKILL_TOO_LONG", "warning", "SKILL.md exceeds the recommended 500-line guidance threshold.", f"Line count: {main_lines}"))
    support_files = [p for p in normalized if p != main_path]
    metrics = {
        "skill_markdown_lines": main_lines,
        "supporting_file_count": len(support_files),
        "linked_supporting_file_count": len(set(referenced) & set(support_files)),
        "reference_count": sum(map(len, references.values())),
        "orphan_markdown_count": len(orphans),
        "main_skill_under_500_lines": main_lines <= 500 if main_path else False,
    }
    digest = hashlib.sha256()
    for path, content in sorted(normalized.items()):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content.encode("utf-8"))
        digest.update(b"\0")
    score = max(0, 100 - sum(20 if f["severity"] == "error" else 8 if f["severity"] == "warning" else 2 for f in findings))
    semantic = analyze_instructions(body) if main_path else analyze_instructions("")
    security = scan_security(normalized)
    return {
        "schema_version": "1.7.0",
        "package_fingerprint": digest.hexdigest(),
        "skill_path": main_path or None,
        "metadata": metadata,
        "file_manifest": [{"path": p, "size_bytes": len(c.encode("utf-8"))} for p, c in sorted(normalized.items())],
        "reference_graph": {key: value for key, value in sorted(references.items())},
        "progressive_disclosure": metrics,
        "structural_score": score,
        "instruction_quality": semantic,
        "security": security,
        "findings": findings,
    }
