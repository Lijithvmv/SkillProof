"""Tests built from a skill's own rules, for the shapes most answer-visible rules take.

A 7B local model could not author tests: its scenarios contradicted the claim they were for (a "no requirement can be
found" case that gave a requirement), and its checks asked for sentences no answer contains. So here the test logic
comes from the rule's own words, deterministically, and the model writes only the request and its background text,
which is then checked to really trigger the rule (and redrafted once if it does not). Rules outside these shapes are
listed as not covered, never guessed.

Shapes:
- absence: "if the X cannot be located / is missing, say so / flag it as Y / say what was searched / never invent it"
  -> the background leaves X out; the answer must say X is missing (+ the flag word, + what was searched).
- always_state: "always state the X" -> the answer must name X.
- order: "the order is ...: a, b, c" -> the answer must list them in that order.
- never_write: a rule that quotes a phrase the skill never writes -> the answer must not contain it.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

from skillproof.checks import Check
from skillproof.conformance import WORD, literal_checks, testable
from skillproof.evaluation import BenchmarkTask, validate_benchmark_task

INVENT = re.compile(r"\b(?:do not|don't|never|not)\s+(?:invent|fabricate|make up|guess(?: at)?)\s+(?:a |an |the |any )?"
                    r"([a-z][a-z ,\-]{2,40}?)(?=\s+(?:merely|to|or|when|if|from|just|that|for)\b|\s*[.;:,—(]|$)", re.I)
ASK_FOR = re.compile(r"\b(?:ask (?:the user )?for (?:it|them|the missing)|ask for it|tell the user what(?:'s| is) missing)\b", re.I)
ABSENCE = re.compile(r"\b(?:missing|absent|cannot (?:locate|find)|cannot be (?:located|found|identified|read|determined)|"
                     r"no (?:such )?\w+ (?:can|could) be (?:identified|found|located|read)|(?:is|are) not "
                     r"(?:available|given|located|found|recorded)|no (?:\w+ ){0,2}(?:exists?|is available|was found|"
                     r"records?)|empty|genuinely cannot)\b", re.I)
ABSENCE_ACTION = re.compile(r"\b(?:say|says|state|states|flag|flags|mark|marks|report|list|never|do not|don't|not)\b", re.I)
NEVER_THING = re.compile(r"\bnever\s+(?:asserts?|invents?|guess(?:es)?|fills? in|makes? up)\s+(?:a|an|the)?\s*"
                         r"([a-z][a-z \-]{2,30}?)\s+(?:it|that|which)\b", re.I)
THING = re.compile(r"\b(?:if|where|when)\s+(?:the\s+|a\s+|an\s+|no\s+)?(?:such\s+)?([a-z][a-z \-]{2,40}?)\s+"
                   r"(?:cannot|can't|can|could|is|are|was|were|does|do|exists?|records?)\b", re.I)
SUBJECT = re.compile(r"^(?:the\s+)?([a-z][a-z \-]{2,30}?)\s+(?:genuinely\s+)?(?:cannot|is missing|is absent|is not)\b", re.I)
FLAG_AS = re.compile(r"\b(?:flag|mark|set|label)\b[^.;]{0,40}?\bas\s+([a-z][a-z\-]{3,20})", re.I)
FLAG_BARE = re.compile(r"\bflag\s+(?:it\s+)?as\s+([a-z][a-z\-]{3,20})", re.I)
SAY_SEARCHED = re.compile(r"\b(?:say|list|state)\s+what\s+was\s+searched\b", re.I)
ALWAYS_STATE = re.compile(r"^always\s+(?:state|say|give|list|report|name|cite|show|include)\s+(?:the\s+|a\s+|an\s+)?"
                          r"([a-z][a-z \-]{2,60})", re.I)
ORDER = re.compile(r"\border\b[^:]{0,60}:\s*([^.]+)", re.I)
ACKNOWLEDGE = (r"(?i)\b(?:not (?:yet )?(?:known|found|located|available|stated|given|provided|recorded|checked|confirmed|"
               r"determined)|unavailable|unknown|missing|cannot (?:be )?(?:found|located|determined|confirmed|identified|judged)|"
               r"could not (?:be )?(?:found|located|identified)|no [a-z]+(?: [a-z]+)? (?:was |were |is |are |could be |can be )?"
               r"(?:found|located|identified|available|given|provided|recorded))\b")
ASKS = r"(?i)\?|\b(?:please (?:send|share|provide|confirm)|could you (?:send|share|provide)|can you (?:send|share|provide)|let me know)\b"
SYNONYMS = {
    "number": [r"\d"], "numbers": [r"\d"], "figure": [r"\d"], "figures": [r"\d"], "quantity": [r"\d"],
    "citation": [r"https?://", r"\bdoi\b", r"\bet al\b", r"\[\d+\]"], "citations": [r"https?://", r"\bdoi\b", r"\bet al\b", r"\[\d+\]"],
    "source": [r"https?://", r"\bet al\b"], "sources": [r"https?://", r"\bet al\b"],
    "holiday": [r"\bholiday\w*"], "holidays": [r"\bholiday\w*"],
    "time": [r"\b\d{1,2}:\d{2}\b"], "zone": [r"\b(?:UTC|GMT|IST|PST|EST|CET)\b", r"[+-]\d{2}:\d{2}"],
    "requirement": [r"spec\w*", r"tolerance\w*", r"drawing\w*", r"clause\w*", r"standard\w*", r"callout\w*", r"\d+(?:\.\d+)?\s*(?:±|\+/-)"],
    "register": [r"dashboard\w*", r"tracker\w*"],
    "tab": [r"inventory\w*", r"on[ -]hand"],
    "price": [r"cost\w*", r"quote\w*", r"\$\s*\d"],
    "date": [r"\b\d{4}-\d{2}-\d{2}\b"],
}
STOP_NOUNS = {"the", "a", "an", "this", "that", "it", "they", "them", "source", "user", "run", "skill", "such"}


def _head(phrase: str) -> str:
    words = [w for w in re.findall(r"[a-z][a-z\-]+", phrase.lower()) if w not in STOP_NOUNS]
    return words[-1] if words else ""


def _term(word: str) -> str:
    """A regex for a word and its inflections (requirement -> requirements, assumption -> assumptions)."""
    stem = word[:-1] if len(word) > 5 and word.endswith("s") else word
    return re.escape(stem[: max(4, len(stem) - 2)]) + r"\w*"


def template_for(claim: dict[str, Any]) -> dict[str, Any] | None:
    """The test a rule's own words define, for the shapes covered; None for any other rule."""
    text, cid = claim["text"], claim["id"]

    def tag(what: str) -> str:
        return f"[{cid}] {what}"

    invent = INVENT.search(text)
    if invent:
        # "Do not invent facts, numbers or citations": the request needs that thing and the background does not give
        # it, so a skill-following answer says it is not available instead of making one up.
        thing = invent.group(1).strip(" ,")
        heads = [_head(part) for part in re.split(r",|\bor\b|\band\b", thing) if _head(part)]
        if heads:
            patterns = [p for h in heads for p in [_term(h)] + SYNONYMS.get(h, [])]
            absent = re.compile(r"(?i)\b(?:" + "|".join(patterns) + ")")
            checks = [Check(kind="regex", value=ACKNOWLEDGE, description=tag(f"says the {thing} are not available instead of inventing them"))]
            if ASK_FOR.search(text):
                checks.append(Check(kind="regex", value=ASKS, description=tag("asks for what is missing")))
            return {"shape": "do_not_invent", "thing": thing, "checks": checks,
                    "instruction": f"The request needs {thing}, but the background gives NONE of them: "
                                   f"no {', no '.join(heads)} anywhere in it. Everything else is concrete and specific.",
                    "verify": lambda context: "the background gives what should be missing" if absent.search(context) else None}

    if ABSENCE.search(text) and ABSENCE_ACTION.search(text):
        match = THING.search(text) or NEVER_THING.search(text) or SUBJECT.search(text)
        thing = match.group(1).strip() if match else ""
        head = _head(thing)
        if head:
            checks = [Check(kind="regex", value=ACKNOWLEDGE, description=tag(f"says the {thing} is missing instead of supplying one"))]
            flag = FLAG_AS.search(text) or FLAG_BARE.search(text)
            if flag:
                checks.append(Check(kind="regex", value=r"(?i)\b" + _term(flag.group(1).lower()), description=tag(f"flags it as {flag.group(1)}")))
            if SAY_SEARCHED.search(text) or re.search(r"\blist what was searched\b", text, re.I):
                checks.append(Check(kind="regex", value=r"(?i)\b(?:search|looked|checked)\w*", description=tag("says what was searched")))
            if ASK_FOR.search(text):
                checks.append(Check(kind="regex", value=ASKS, description=tag("asks for what is missing")))
            checks += literal_checks(claim)
            # A background can give the missing thing away under another name ("tolerance T12.01" is a requirement).
            absent = re.compile(r"(?i)\b(?:" + "|".join([_term(head)] + SYNONYMS.get(head, [])) + ")")
            return {"shape": "absence", "thing": thing, "checks": checks,
                    "instruction": f"The background must NOT contain any {thing}: do not use the word '{head}' at all. "
                                   "Everything else the request needs is there, concrete and specific.",
                    "verify": lambda context: f"the background mentions '{head}'" if absent.search(context) else None}
    always = ALWAYS_STATE.match(text)
    if always:
        obj = always.group(1).strip()
        head = _head(re.split(r"\b(?:behind|for|of|in|on|with)\b", obj)[0]) or _head(obj)
        if head:
            return {"shape": "always_state", "thing": obj, "checks": [
                Check(kind="regex", value=r"(?i)\b" + _term(head), description=tag(f"states the {obj}"))],
                "instruction": "The background is a normal, complete case for this request.", "verify": lambda context: None}
    order = ORDER.search(text)
    if order:
        items = [i.strip(" *`'\"") for i in order.group(1).split(",") if i.strip(" *`'\"")]
        if 3 <= len(items) <= 8:
            words = [re.sub(r"[_\-]+", " ", i).strip().lower() for i in items]
            joins = [r"[ _\-]?".join(map(re.escape, w.split())) for w in words]
            return {"shape": "order", "thing": ", ".join(words), "checks": [
                Check(kind="regex", value="(?is)" + ".*".join(r"\b" + j for j in joins),
                      description=tag(f"lists them in the order {' > '.join(words)}"))],
                "instruction": "The background must involve every one of these, each named in plain words: " + "; ".join(words) + ".",
                "verify": lambda context: next((f"the background does not mention '{w}'" for w, j in zip(words, joins)
                                                if not re.search(j, context, re.I)), None)}
    # A single common word ("shared") is used for other things in a normal answer; only specific phrases are tested.
    never = [c for c in literal_checks(claim) if c.kind == "not_contains" and (len(c.value.split()) > 1 or re.search(r"\d", c.value))]
    if never:
        return {"shape": "never_write", "thing": ", ".join(c.value for c in never), "checks": never,
                "instruction": "The background is a normal, complete case for this request.", "verify": lambda context: None}
    return None


SCENARIO_SCHEMA = {"type": "object", "properties": {"request": {"type": "string"}, "context": {"type": "string"}},
                   "required": ["request", "context"]}
SCENARIO_PROMPT = """Write one realistic test case for an AI-agent skill.

Skill: {name}. What it does: {description}

request: a message a real person would send that this skill is for, in their own words, similar to: "{trigger}".
context: the source material that request comes with (records, notes, numbers, names), 80 to 200 words.
{instruction}
Do not explain the skill or the test. Return only the JSON."""


FILLER = {"the", "this", "that", "a", "an", "is", "are", "was", "be", "it", "of", "to", "in", "on", "and", "or", "not",
          "if", "we", "our", "up", "run", "when", "with", "for", "any", "one", "can", "cannot"}


def best_trigger(claim: dict[str, Any], triggers: list[str]) -> str:
    words = set(WORD.findall(claim["text"].lower())) - FILLER
    stems = {w[:5] for w in words}
    return max(triggers, key=lambda t: len({w[:5] for w in set(WORD.findall(t.lower())) - FILLER} & stems), default="").strip(" ,.")


def coverage(claims: dict[str, Any]) -> dict[str, Any]:
    """How many of a skill's answer-visible rules a template covers, by shape."""
    shapes: dict[str, int] = {}
    testable_claims = [c for c in claims["claims"] if testable(c)]
    for claim in testable_claims:
        template = template_for(claim)
        shapes[template["shape"] if template else "not_covered"] = shapes.get(template["shape"] if template else "not_covered", 0) + 1
    return {"testable": len(testable_claims), "by_shape": shapes}


def generate_benchmark(skill_text: str, claims: dict[str, Any], ask: Callable[[str, dict], str], *, tasks: int = 8,
                       skill_name: str | None = None, retries: int = 1) -> dict[str, Any]:
    """Tests built from the skill's own rules. The model writes only the request and background; the background is
    checked to trigger the rule and redrafted up to `retries` times if it does not."""
    templated, uncovered = [], []
    for claim in claims["claims"]:
        if testable(claim):
            template = template_for(claim)
            (templated if template else uncovered).append((claim, template))
    kept, rejected = [], []
    for claim, template in templated[:tasks]:
        trigger = best_trigger(claim, claims.get("triggers", [])) or claims.get("description", "")[:120]
        prompt = SCENARIO_PROMPT.format(name=skill_name or claims.get("skill") or "", description=claims.get("description", "")[:800],
                                        trigger=trigger, instruction=template["instruction"])
        for attempt in range(retries + 1):
            try:
                scenario = json.loads(ask(prompt, SCENARIO_SCHEMA))
            except (ValueError, RuntimeError) as exc:
                rejected.append({"claim": claim["id"], "attempt": attempt + 1, "reason": f"model failed: {str(exc)[:120]}"})
                continue
            problem = template["verify"](str(scenario.get("context", ""))) or (None if str(scenario.get("request", "")).strip() else "no request")
            if problem:
                rejected.append({"claim": claim["id"], "attempt": attempt + 1, "reason": problem})
                continue
            kept.append(BenchmarkTask(task_id=f"{claim['id'].lower()}-{template['shape']}", prompt=scenario["request"].strip(),
                                      context=str(scenario["context"]).strip() or None, checks=template["checks"],
                                      target_behaviors=[claim["id"]]))
            break
    return {"tasks": kept, "rejected": rejected,
            "uncovered": [{"id": c["id"], "text": c["text"]} for c, _ in uncovered],
            "coverage": {"testable_claims": len(templated) + len(uncovered), "templated": len(templated), "tasks": len(kept)},
            "reviews": [validate_benchmark_task(skill_text, t) for t in kept]}
