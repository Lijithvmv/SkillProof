"""Explainable heuristic checks for instruction quality (not an LLM judgment)."""
from __future__ import annotations

import re
from typing import Any

ACTION = re.compile(r"\b(use|open|read|write|create|generate|run|execute|check|verify|validate|test|review|compare|save|return|provide|ask|install|configure|inspect|summarize|transform|delete|update|build|deploy)\b", re.I)
VAGUE = re.compile(r"\b(as appropriate|as needed|when appropriate|if necessary|etc\.?|and so on|production[- ]ready|high[- ]quality|best practices|use your judgment|make it good)\b", re.I)
TASK_CUES = re.compile(r"\b(generate|create|write|build|produce|draft|implement|return|output|deliver)\b", re.I)
TECH_CUES = re.compile(r"\b(api|cli|command|python|javascript|typescript|package|dependency|tool|database|server|browser|file|repository|repo)\b", re.I)
VERIFY_CUES = re.compile(r"\b(verify|validate|test|check|review|confirm|lint|assert|inspect)\b", re.I)
OUTPUT_CUES = re.compile(r"\b(output|return|provide|save|format|schema|json|markdown|file path|deliverable)\b", re.I)
PREREQ_CUES = re.compile(r"\b(before|prerequisite|requires?|install|dependency|assumptions?|access|permission|credential|environment|precondition)\b", re.I)
RECOVERY_CUES = re.compile(r"\b(if .*fails?|error|retry|recover|fallback|otherwise|report .*failure|failure handling)\b", re.I)


def _evidence(lines: list[str]) -> str:
    return "\n".join(line.strip() for line in lines[:3])[:500]


def _finding(code: str, severity: str, message: str, evidence: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message, "evidence": evidence[:500]}


def _instruction_lines(body: str) -> list[str]:
    in_fence = False
    result: list[str] = []
    for raw in body.splitlines():
        stripped = raw.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence or not stripped or stripped.startswith("<!--"):
            continue
        text = re.sub(r"^(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+|>\s*)", "", stripped)
        if text and not re.fullmatch(r"[*_`~#\-]+", text):
            result.append(text)
    return result


def analyze_instructions(body: str) -> dict[str, Any]:
    """Return deterministic quality indicators with evidence from instruction text."""
    lines = _instruction_lines(body)
    text = "\n".join(lines)
    findings: list[dict[str, str]] = []
    categories: dict[str, bool] = {
        "actionable_steps": any(ACTION.search(line) for line in lines),
        "prerequisites": bool(PREREQ_CUES.search(text)),
        "output_expectations": bool(OUTPUT_CUES.search(text)),
        "verification": bool(VERIFY_CUES.search(text)),
        "error_recovery": bool(RECOVERY_CUES.search(text)),
    }

    if len(text) < 40 or not categories["actionable_steps"]:
        findings.append(_finding("INSTRUCTIONS_NOT_ACTIONABLE", "warning", "Instructions may not contain enough concrete actions for an agent to follow.", _evidence(lines) or "No usable instruction text found."))

    vague_lines = [line for line in lines if VAGUE.search(line)]
    for line in vague_lines[:5]:
        findings.append(_finding("VAGUE_INSTRUCTION", "warning", "Instruction contains a broad or subjective phrase that may not produce consistent behavior.", line))

    if TASK_CUES.search(text) and not categories["output_expectations"]:
        findings.append(_finding("OUTPUT_EXPECTATION_MISSING", "info", "The skill asks the agent to produce work but does not clearly specify the expected output or format.", _evidence([line for line in lines if TASK_CUES.search(line)])))
    if TECH_CUES.search(text) and not categories["prerequisites"]:
        findings.append(_finding("PREREQUISITES_UNCLEAR", "info", "Technical tools or resources are mentioned without explicit prerequisites or access requirements.", _evidence([line for line in lines if TECH_CUES.search(line)])))
    if re.search(r"\b(code|script|application|config|configuration|command|deploy|migration)\b", text, re.I) and not categories["verification"]:
        findings.append(_finding("VERIFICATION_STEP_MISSING", "warning", "Technical work is described without a clear verification or validation step.", _evidence([line for line in lines if re.search(r"\b(code|script|application|config|configuration|command|deploy|migration)\b", line, re.I)])))
    if re.search(r"\b(run|execute|install|deploy|write|create|generate)\b", text, re.I) and not categories["error_recovery"]:
        findings.append(_finding("ERROR_RECOVERY_UNSPECIFIED", "info", "Operational instructions do not describe what to do when a step fails.", _evidence([line for line in lines if ACTION.search(line)])))
    if len(lines) >= 3 and sum(bool(ACTION.search(line)) for line in lines) >= 3 and not re.search(r"\b(first|then|next|finally|step\s+\d|\d+[.)])\b", body, re.I):
        findings.append(_finding("WORKFLOW_SEQUENCE_UNCLEAR", "info", "Several actions appear without explicit sequencing cues.", _evidence([line for line in lines if ACTION.search(line)])))

    # Catch only direct polarity conflicts that share the same action and object.
    polarities: dict[str, tuple[bool, str]] = {}
    conflict_pairs: list[str] = []
    for line in lines:
        match = re.search(r"\b(always|never|must|must not|do not|don't)\s+(.+)", line, re.I)
        if not match:
            continue
        directive, action = match.group(1).lower(), re.sub(r"[^a-z0-9 ]", "", match.group(2).lower()).strip()
        negative = directive in {"never", "must not", "do not", "don't"}
        key = re.sub(r"\b(always|never|must|must not|do not|don't)\b", "", action).strip()
        if key in polarities and polarities[key][0] != negative:
            conflict_pairs.extend([polarities[key][1], line])
        else:
            polarities[key] = (negative, line)
    if conflict_pairs:
        findings.append(_finding("POSSIBLE_INSTRUCTION_CONFLICT", "warning", "Instructions contain direct opposing directives with matching wording; review them for a contradiction.", _evidence(conflict_pairs)))

    deductions = sum(25 if f["severity"] == "warning" else 12 if f["severity"] == "info" else 35 for f in findings)
    return {
        "method": "deterministic_heuristics",
        "instruction_count": len(lines),
        "actionable_instruction_count": sum(bool(ACTION.search(line)) for line in lines),
        "quality_score": max(0, 100 - deductions),
        "coverage": categories,
        "findings": findings,
        "limitations": "Heuristic signals can miss context and may flag intentional flexibility. Review evidence before treating findings as defects.",
    }
