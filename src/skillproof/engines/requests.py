"""Requests for a load-rate test, written from skill descriptions by a local model.

A load rate needs requests the skill is for, and requests it must not take. Hand-written ones do not scale to a
catalogue, and a generator that echoes the description makes the test trivially easy (the router then matches words,
not meaning). So the model writes requests as a user would, and every request is checked before it is used:

- it must not name the skill;
- it must not echo the description it was written from: four or more of its content words in a row (filler words
  left out), or most of its own content words taken from it (a natural phrase such as "create a pull request" alone is how people ask, and stays);
- it must be a short, distinct request;
- it must ask for what this skill is specifically for (judged against its own description only, never against
  rivals): a request a general tool in the same area would serve just as well has drifted off the skill's purpose and
  would test the wrong thing. Rivals are deliberately not consulted: a fair request that a rival also matches is
  exactly the case a load-rate test exists to catch.

What fails is dropped with the reason and kept in the result. The skill's own requests are written from its
description; the near misses (requests it must NOT take) are written from the descriptions of its closest rivals,
chosen by the caller. Every request is labelled as generated, so a reviewer can read them before trusting the rate.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable

WORD = re.compile(r"[a-z0-9]+")
STOP = {"a", "an", "the", "to", "for", "of", "in", "on", "and", "or", "with", "my", "me", "i", "you", "your", "can", "could",
        "please", "this", "that", "it", "is", "are", "be", "we", "our", "us", "want", "need", "would", "like", "do", "use",
        "when", "user", "wants", "some", "so", "at", "as", "by", "from", "up", "just", "now", "let", "s"}
MAX_SHARED = 0.6   # share of a request's content words that may come from the description
RUN = 4            # content words in a row (filler words left out) copied from the description
SCHEMA = {"type": "object", "properties": {"requests": {"type": "array", "items": {"type": "string"}}}, "required": ["requests"]}
PROMPT = """You write test messages for a tool router. Below is one tool an AI assistant can load. Write {n} different
messages that a user might send to the assistant, which this tool is meant to handle.

Rules:
- Write as the user, about their own work, in plain everyday words. One short sentence each.
- Do not mention the tool's name, and do not copy phrases from its description: say what the user wants in your own words.
- Vary the wording and the situation between messages.

Tool name: {name}
Tool description: {description}

Return JSON: {{"requests": ["...", "..."]}}"""


def _words(text: str) -> list[str]:
    return WORD.findall(text.lower())


def copies(request: str, description: str, size: int = RUN) -> str | None:
    """The first run of `size` content words (filler words left out) the request shares with the description, or None."""
    source = [w for w in _words(description) if w not in STOP]
    grams = {tuple(source[i:i + size]) for i in range(len(source) - size + 1)}
    words = [w for w in _words(request) if w not in STOP]
    for i in range(len(words) - size + 1):
        if tuple(words[i:i + size]) in grams:
            return " ".join(words[i:i + size])
    return None


def check(request: str, name: str, description: str, seen: set[str]) -> str | None:
    """Why a generated request cannot be used, or None."""
    text = request.strip()
    if not text or len(text) > 300:
        return "empty or longer than 300 characters"
    lowered = text.lower()
    name_words = _words(name)
    if name.lower() in lowered or (len(name_words) > 1 and " ".join(name_words) in " ".join(_words(text))):
        return "names the skill"
    copied = copies(text, description)
    if copied:
        return f"copies the description ('{copied}')"
    content = [w for w in _words(text) if w not in STOP]
    source = {w for w in _words(description) if w not in STOP}
    if content and sum(w in source for w in content) / len(content) >= MAX_SHARED:
        return f"mostly the description's words ({sum(w in source for w in content)} of {len(content)})"
    key = " ".join(_words(text))
    if key in seen:
        return "duplicate"
    return None


PURPOSE_SCHEMA = {"type": "object", "properties": {"verdicts": {"type": "array", "items": {
    "type": "object", "properties": {"index": {"type": "integer"}, "fits": {"type": "boolean"}, "reason": {"type": "string"}},
    "required": ["index", "fits", "reason"]}}}, "required": ["verdicts"]}
PURPOSE_PROMPT = """Below is one tool an AI assistant can load, and numbered user messages. For each message, decide whether
it asks for what THIS tool is specifically for: the thing that sets it apart in its description. A message about the
same general area that a general-purpose tool would serve just as well, without the tool's specific purpose, does not
fit. Judge each message on its own against this description only.

Tool name: {name}
Tool description: {description}

Messages:
{messages}

Return JSON: {{"verdicts": [{{"index": 1, "fits": true, "reason": "..."}}, ...]}}"""


def off_purpose(requests: list[str], name: str, description: str, ask: Callable[[str, dict], str]) -> dict[int, str]:
    """Indexes of requests that do not ask for the skill's specific purpose, with the judge's reason. A request the
    judge gave no verdict for is treated as off purpose (it was not confirmed)."""
    if not requests:
        return {}
    listing = "\n".join(f"{i}. {r}" for i, r in enumerate(requests, 1))
    raw = ask(PURPOSE_PROMPT.format(name=name, description=description, messages=listing), PURPOSE_SCHEMA)
    try:
        verdicts = json.loads(raw).get("verdicts") or []
    except (json.JSONDecodeError, AttributeError) as exc:
        raise RuntimeError(f"the purpose check returned no verdicts for {name}: {raw[:120]!r}") from exc
    fits = {int(v["index"]): (bool(v.get("fits")), str(v.get("reason", ""))[:200]) for v in verdicts
            if isinstance(v, dict) and isinstance(v.get("index"), int)}
    return {i - 1: (fits.get(i, (False, "no verdict"))[1] or "not its specific purpose")
            for i in range(1, len(requests) + 1) if not fits.get(i, (False, ""))[0]}


def off_purpose_by_majority(requests: list[str], name: str, description: str,
                            judges: list[Callable[[str, dict], str]]) -> dict[int, str]:
    """Requests a majority of independent judgements (sampled judges) find off the skill's purpose. One judgement
    wrongly dropped a fair security request on real data (and one sample flagged every request); three samples with a
    majority kept every fair request and still dropped the off-purpose one."""
    votes: dict[int, list[str]] = {}
    for judge in judges:
        for index, reason in off_purpose(requests, name, description, judge).items():
            votes.setdefault(index, []).append(reason)
    needed = len(judges) // 2 + 1
    return {index: f"{len(reasons)} of {len(judges)} judgements: {reasons[0]}" for index, reasons in votes.items() if len(reasons) >= needed}


FEEDBACK = """

These earlier messages were rejected; write different ones that avoid the same problem:
{rejected}"""


def write_requests(name: str, description: str, ask: Callable[[str, dict], str], n: int,
                   rounds: int = 3, judge: Callable[[str, dict], str] | list[Callable[[str, dict], str]] | None = None,
                   ) -> tuple[list[str], list[dict[str, str]]]:
    """Up to n usable requests for one skill, and the dropped ones with reasons. With `judge`, each round's candidates
    are also checked for the skill's specific purpose (off_purpose). Rejected requests are shown back to the model with
    their reasons, for up to `rounds` rounds."""
    kept: list[str] = []
    dropped: list[dict[str, str]] = []
    seen: set[str] = set()
    for _ in range(rounds):
        prompt = PROMPT.format(n=n - len(kept), name=name, description=description)
        if dropped:
            rejected = [f"- {d['request']} (rejected: {d['reason']})" for d in dropped[-8:]]
            prompt += FEEDBACK.format(rejected="\n".join(rejected))
        raw = ask(prompt, SCHEMA)
        try:
            items = json.loads(raw).get("requests") or []
        except (json.JSONDecodeError, AttributeError) as exc:
            raise RuntimeError(f"the model returned no request list for {name}: {raw[:120]!r}") from exc
        candidates = []
        for item in items:
            text = str(item).strip()
            reason = check(text, name, description, seen | {" ".join(_words(c)) for c in candidates})
            if reason:
                dropped.append({"skill": name, "request": text[:300], "reason": reason})
            else:
                candidates.append(text)
        if not judge:
            drift: dict[int, str] = {}
        elif isinstance(judge, list):
            drift = off_purpose_by_majority(candidates, name, description, judge)
        else:
            drift = off_purpose(candidates, name, description, judge)
        for index, text in enumerate(candidates):
            if index in drift:
                dropped.append({"skill": name, "request": text[:300], "reason": f"off the skill's purpose ({drift[index]})"})
            elif len(kept) < n:
                kept.append(text)
                seen.add(" ".join(_words(text)))
        if len(kept) >= n:
            break
    return kept, dropped


def generate(target: tuple[str, str], rivals: list[tuple[str, str]], ask: Callable[[str, dict], str], *,
             own: int = 6, per_rival: int = 2, model: str = "") -> dict[str, Any]:
    """The skill's own requests, near misses written for each rival (requests it must not take), and what was dropped."""
    relevant, dropped = write_requests(target[0], target[1], ask, own)
    near_misses = []
    for rival_name, rival_description in rivals:
        kept, lost = write_requests(rival_name, rival_description, ask, per_rival)
        near_misses.extend({"rival": rival_name, "request": text} for text in kept)
        dropped.extend(lost)
    return {"source": "generated_from_descriptions", "model": model, "relevant": relevant, "near_misses": near_misses,
            "dropped": dropped,
            "limitations": "Written by a local model from the descriptions alone and checked only for naming the skill, "
                           "copying its description and duplicates. A near miss written for a rival can still be a fair "
                           "request for this skill when the two overlap; read them before trusting the rate."}
