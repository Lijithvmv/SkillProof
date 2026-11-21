"""Does the skill do what it is written to do? Claims from a SKILL.md, a draft benchmark that tests them, and adherence
per claim from a paired experiment.

A catalogue version needs run evidence before anyone can approve it, and run evidence needs tasks. Until now only a
hand-written example benchmark existed, so every real skill stopped at `insufficient_evidence`. This module closes that:

1. **Claims** (deterministic): what the skill says about itself. The requests it is meant for (the "Use when ..."
   phrases of its description), the rules it sets (never / always / must / do not), and its workflow steps.
2. **Draft benchmark** (local model, then validated): realistic requests with source material, each tagged with the
   claims it tests and carrying exact checks on the answer. Every check names its claim (`[C3] ...`). The draft is
   marked `draft_needs_review`: a person reads and corrects it before its results count for anything.
3. **Adherence** (exact): after `execute_experiment`, the share of each claim's checks the agent passed with the skill
   and without it. A claim the agent breaks with the skill loaded is listed as broken.

Nothing here runs skill code. The skill's SKILL.md text is what the agent receives, exactly as in the paired runs.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

import yaml

from skillproof.checks import Check
from skillproof.evaluation import BenchmarkTask, validate_benchmark_task

FRONTMATTER = re.compile(r"\A---\s*\r?\n(.*?)\r?\n---\s*(?:\r?\n|\Z)", re.S)
RULE = re.compile(r"\b(?:never|always|must|must not|do not|don't|cannot|only when|is never|are never)\b", re.I)
STEP = re.compile(r"^#{2,4}\s*(?:step\s*\d+\s*[—:.-]+\s*)(.+?)\s*$", re.I | re.M)
TRIGGER = re.compile(r"[\"“]([^\"”]{6,160})[\"”]")
CLAIM_TAG = re.compile(r"^\[(C\d+)\]")
MAX_CLAIMS = 40


def _frontmatter(text: str) -> tuple[dict[str, Any], str]:
    match = FRONTMATTER.match(text)
    if not match:
        return {}, text
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        data = dict(re.findall(r"^(name|description):\s*(.+?)\s*$", match.group(1), re.M))
    return (data if isinstance(data, dict) else {}), text[match.end():]


LIST_START = re.compile(r"^(?:[-*+]\s|\d+[.)]\s|>|→)")


def _paragraphs(body: str) -> list[tuple[int, str]]:
    """Prose paragraphs (hard-wrapped lines joined; each list item its own paragraph) with their first line number.
    Code fences, tables, headings and comments are left out."""
    out: list[tuple[int, str]] = []
    current: list[str] = []
    start, fenced = 0, False

    def flush() -> None:
        if current:
            out.append((start, " ".join(current)))
            current.clear()

    for number, raw in enumerate(body.splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith(("```", "~~~")):
            flush()
            fenced = not fenced
            continue
        if fenced or not stripped or stripped.startswith(("|", "<!--", "#")) or set(stripped) <= set("-*_ "):
            flush()
            continue
        if LIST_START.match(stripped):
            flush()
        if not current:
            start = number
        current.append(stripped)
    flush()
    return out


def _clean(text: str) -> str:
    text = re.sub(r"^(?:[-*+]|\d+[.)]|>|→)\s*", "", text.strip())
    text = re.sub(r"\*\*|__|`|(?<!\w)\*|\*(?!\w)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_claims(skill_text: str) -> dict[str, Any]:
    """What a SKILL.md says about itself: the requests it is for, its rules and its steps, each with an id and the
    line it came from. Deterministic; no model involved."""
    meta, body = _frontmatter(skill_text)
    description = str(meta.get("description") or "")
    offset = skill_text[: len(skill_text) - len(body)].count("\n")
    claims: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(kind: str, text: str, line: int | None) -> None:
        text = _clean(text)
        key = text.lower()
        if len(text) < 12 or key in seen or len(claims) >= MAX_CLAIMS:
            return
        seen.add(key)
        claims.append({"id": f"C{len(claims) + 1}", "kind": kind, "text": text[:400], "line": line})

    use_when = description.split("Use when", 1)[1] if "Use when" in description else ""
    triggers = [t.strip() for t in TRIGGER.findall(use_when)]
    for sentence in re.split(r"(?<=[.!?])\s+", description.split("Use when", 1)[0]):
        if RULE.search(sentence):
            add("rule", sentence, 1)
    for match in STEP.finditer(body):
        add("step", match.group(1), offset + body[: match.start()].count("\n") + 1)
    for number, paragraph in _paragraphs(body):
        for sentence in re.split(r"(?<=[.!?])(?:\*\*|\*|_)?\s+(?=[A-Z*\"“])", paragraph):
            if RULE.search(sentence) and 20 <= len(sentence) <= 400:
                add("rule", sentence, offset + number)
    return {"skill": str(meta.get("name") or ""), "description": description, "triggers": triggers, "claims": claims,
            "method": "deterministic_claim_extraction",
            "limitations": "Claims are sentences the skill writes about itself (rules, steps, intended requests). "
                           "Rules written without never/always/must wording, and claims made only in referenced files, "
                           "are not picked up."}


DRAFT_SCHEMA = {
    "type": "object",
    "properties": {
        "tasks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                    "context": {"type": "string"},
                    "claims": {"type": "array", "items": {"type": "string"}},
                    "checks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "kind": {"type": "string", "enum": ["contains", "not_contains", "regex", "not_regex", "heading", "min_words", "max_words"]},
                                "claim": {"type": "string"},
                                "description": {"type": "string"},
                                "value": {"type": "string"},
                                "limit": {"type": "integer"},
                            },
                            "required": ["kind", "claim", "description", "value"],
                        },
                    },
                },
                "required": ["prompt", "context", "claims", "checks"],
            },
        }
    },
    "required": ["tasks"],
}

DRAFT_PROMPT = """You write test scenarios for an AI-agent skill. The scenarios check whether an agent that loads the
skill actually does what the skill says.

Skill name: {name}
Skill description: {description}
Requests the skill says it is for: {triggers}

Claims the skill makes (id: text):
{claims}

Write {n} scenarios. For each one:
- prompt: a request a real person would send, in their own words (do not copy the skill's sentences).
- context: the source material the request needs (an inspection note, measurements, records). Realistic, specific,
  with concrete numbers and names. Leave out on purpose anything a claim says must be flagged when missing.
- claims: the ids of the claims this scenario tests (2 to 5).
- checks: 2 to 6 exact checks on the agent's answer, each for one claim id. Use only:
  contains / not_contains (value = a short literal phrase), regex / not_regex (value = a Python regex),
  heading (value = heading text), min_words / max_words (limit = a number).
  A check must be decidable from the answer text alone and must follow from the claim, not from taste.
  EVERY check has a value: the exact short phrase the answer must (or must not) contain, or a Python regex.
  A check like "the report should be clear" has no value and is useless. Good examples:
  {{"kind": "contains", "claim": "C11", "description": "flags the record as blocking when no requirement is given", "value": "blocking"}}
  {{"kind": "regex", "claim": "C4", "description": "states the suspect quantity as a number", "value": "\\\\b\\\\d+\\\\s*(?:parts|units|pcs)\\\\b"}}
  {{"kind": "not_contains", "claim": "C16", "description": "never writes 0 parts for an unchecked location", "value": "0 parts"}}
Return only the JSON."""

QUOTED_PHRASE = re.compile(r"[\"“]([^\"”]{3,60})[\"”]")


def literal_checks(claim: dict[str, Any]) -> list[Check]:
    """Checks that follow from a rule's own wording: a phrase the rule says to write ("say \"not yet known\"") must
    appear; a phrase it says never to write ("never \"0 parts\"") must not."""
    checks = []
    for match in QUOTED_PHRASE.finditer(claim["text"]):
        phrase = match.group(1).strip().strip(",.")
        before = claim["text"][: match.start()].lower()[-40:]
        kind = "not_contains" if re.search(r"\b(?:never|not|do not|don't)\b[^\"“]*$", before) else "contains"
        if kind == "contains" and not re.search(r"\b(?:say|says|write|writes|reads|mark|marked|print|state)\b", before):
            continue  # a quoted example, not a phrase the skill commits to writing
        checks.append(Check(kind=kind, value=phrase, description=f"[{claim['id']}] {'never writes' if kind == 'not_contains' else 'writes'} \"{phrase}\" (from the rule's own wording)"))
    return checks


def draft_benchmark(skill_text: str, claims: dict[str, Any], ask: Callable[[str, dict], str], *, tasks: int = 3,
                    skill_name: str | None = None) -> dict[str, Any]:
    """Ask a local model for draft scenarios, then keep only what validates: tasks that BenchmarkTask accepts and
    checks that compile. Returns the tasks, what was dropped and why, and the lexical review of each task."""
    claim_ids = {c["id"] for c in claims["claims"]}
    prompt = DRAFT_PROMPT.format(
        name=skill_name or claims.get("skill") or "", description=claims.get("description", "")[:1500],
        triggers="; ".join(claims.get("triggers", [])[:12]) or "(none stated)",
        claims="\n".join(f"{c['id']}: {c['text']}" for c in claims["claims"]), n=tasks)
    raw = ask(prompt, DRAFT_SCHEMA)
    proposed = json.loads(raw).get("tasks", [])
    kept, dropped, reviews = [], [], []
    for index, item in enumerate(proposed, 1):
        checks = []
        for check in item.get("checks", []):
            claim = str(check.get("claim", "")).strip()
            if claim not in claim_ids:
                dropped.append({"task": index, "check": check, "reason": f"unknown claim id {claim!r}"})
                continue
            fields = {"kind": check["kind"], "description": f"[{claim}] {str(check.get('description', '')).strip()}"[:300]}
            if check["kind"] in {"min_words", "max_words"}:
                fields["limit"] = check.get("limit")
            else:
                fields["value"] = check.get("value")
            try:
                checks.append(Check.model_validate(fields))
            except (ValueError, re.error) as exc:
                dropped.append({"task": index, "check": check, "reason": str(exc).splitlines()[0][:200]})
        targeted = [c for c in item.get("claims", []) if c in claim_ids]
        have = {(c.kind, (c.value or "").lower()) for c in checks}
        for claim in (c for c in claims["claims"] if c["id"] in targeted):
            for check in literal_checks(claim):
                if (check.kind, check.value.lower()) not in have:
                    checks.append(check)
                    have.add((check.kind, check.value.lower()))
        if not checks:
            dropped.append({"task": index, "reason": "no valid check"})
            continue
        try:
            task = BenchmarkTask(task_id=f"t{index}", prompt=item["prompt"], context=item.get("context") or None,
                                 checks=checks, target_behaviors=targeted or sorted({CLAIM_TAG.match(c.description).group(1) for c in checks}))
        except ValueError as exc:
            dropped.append({"task": index, "reason": str(exc).splitlines()[0][:200]})
            continue
        kept.append(task)
        reviews.append(validate_benchmark_task(skill_text, task))
    return {"tasks": kept, "dropped": dropped, "reviews": reviews}


def write_benchmark(path: str | Path, tasks: list[BenchmarkTask], *, skill: str, claims_file: str, generator: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(task.model_dump_json(exclude_none=True) + "\n" for task in tasks), encoding="utf-8")
    tmp.replace(path)
    manifest = {"benchmark_id": f"{skill}-conformance", "version": "draft", "status": "draft_needs_review",
                "skill": skill, "claims": claims_file, "generator": generator,
                "review": "A person must read every task and check, fix or delete them, then set status to 'reviewed'. "
                          "Results from a draft benchmark are labelled as such."}
    (path.parent / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def adherence(experiment: dict[str, Any], claims: dict[str, Any] | None = None) -> dict[str, Any]:
    """Per claim: share of its checks passed with the skill and without it, over every graded run."""
    texts = {c["id"]: c["text"] for c in (claims or {}).get("claims", [])}
    passed: dict[tuple[str, str], list[float]] = defaultdict(list)
    for run in experiment.get("runs", []):
        if run.get("error"):
            continue
        for item in run.get("grader_criterion_scores") or []:
            match = CLAIM_TAG.match(str(item.get("criterion", "")))
            if match and item.get("kind") == "check":
                passed[(match.group(1), run["condition"])].append(float(item.get("score", 0)))

    def rate(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 4) if values else None

    per_claim = []
    for claim in sorted({c for c, _ in passed}, key=lambda c: int(c[1:])):
        with_skill, without = passed.get((claim, "skill_enabled"), []), passed.get((claim, "baseline"), [])
        per_claim.append({"claim": claim, "text": texts.get(claim), "with_skill": rate(with_skill),
                          "without_skill": rate(without), "check_results_with_skill": len(with_skill)})
    enabled = [v for (c, cond), values in passed.items() if cond == "skill_enabled" for v in values]
    baseline = [v for (c, cond), values in passed.items() if cond == "baseline" for v in values]
    return {
        "method": "claim_checks_over_paired_runs",
        "adherence_rate": rate(enabled),
        "baseline_rate": rate(baseline),
        "claims_tested": len(per_claim),
        "broken_with_skill": [c for c in per_claim if c["with_skill"] is not None and c["with_skill"] < 0.5],
        "per_claim": per_claim,
        "limitations": "Adherence counts only what the benchmark's checks can see in the answer text. A claim no check "
                       "tests is not measured; a draft benchmark that has not been reviewed can test the wrong thing.",
    }
