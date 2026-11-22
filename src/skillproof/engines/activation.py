"""Load-rate measurement: does a model pick the skill from its description when the skill is not forced?

A with/without-skill experiment pastes the skill in, so it measures the gain *when the skill is used*. In real
agents a skill is chosen from its name and description among the other installed skills, and an unclear
description means it is often not used at all. This module measures that choice separately:

- activation rate: on tasks the skill is meant for, how often the model picks it;
- false activation rate: on unrelated tasks, how often the model picks it anyway;
- expected lift: activation rate × the forced lift from the paired experiment.

The probe is a proxy: a local model choosing from a list is not the same as a specific agent product's
loader. Treat the numbers as a comparison between descriptions and versions, not as a prediction for one agent.
"""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import yaml

NONE = "none"

ROUTER_INSTRUCTIONS = (
    "You are an agent deciding whether to load a skill before answering. Each available skill is listed with its "
    "name and description. Choose the one skill that applies to the user's request, or 'none' if no skill applies. "
    "Do not answer the request itself. Return only the required structured result."
)


@dataclass(frozen=True)
class SkillCard:
    name: str
    description: str


class ActivationProbe(Protocol):
    def choose(self, *, request: str, cards: list[SkillCard]) -> str:
        """Return the chosen skill name, or 'none'."""
        ...


def read_skill_card(skill_file: str | Path) -> SkillCard:
    text = Path(skill_file).read_text(encoding="utf-8")
    match = re.match(r"^---\s*\n(.*?)\n---\s*(?:\n|$)", text, re.S)
    data = yaml.safe_load(match.group(1)) if match else None
    if not isinstance(data, dict) or not str(data.get("name") or "").strip() or not str(data.get("description") or "").strip():
        raise ValueError("Skill file needs YAML frontmatter with a name and a description to measure load rate")
    return SkillCard(name=str(data["name"]).strip(), description=str(data["description"]).strip())


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"Expected a JSON object at {path}:{number}")
            rows.append(row)
    return rows


def read_distractors(path: str | Path) -> list[SkillCard]:
    cards = []
    for row in read_jsonl(path):
        name, description = str(row.get("name") or "").strip(), str(row.get("description") or "").strip()
        if not name or not description:
            raise ValueError("Each distractor skill needs a name and a description")
        cards.append(SkillCard(name=name, description=description))
    return cards


def read_requests(path: str | Path) -> list[str]:
    requests = [str(row.get("prompt") or "").strip() for row in read_jsonl(path)]
    if not requests or any(not request for request in requests):
        raise ValueError("Each unrelated task needs a non-empty prompt")
    return requests


def _rate(hits: int, total: int) -> float | None:
    return round(hits / total, 4) if total else None


def measure_activation(
    *, target: SkillCard, distractors: list[SkillCard], relevant_requests: list[str],
    unrelated_requests: list[str], probe: ActivationProbe, repeats: int = 1, seed: int = 0,
    forced_lift_percentage_points: float | None = None,
) -> dict[str, Any]:
    if not relevant_requests:
        raise ValueError("At least one relevant request is required")
    if not 1 <= repeats <= 20:
        raise ValueError("repeats must be from 1 to 20")
    names = [target.name, *(card.name for card in distractors)]
    if len(names) != len(set(names)) or NONE in names:
        raise ValueError("Skill names must be unique and must not be 'none'")
    rng = random.Random(seed)
    records: list[dict[str, Any]] = []
    for kind, requests in (("relevant", relevant_requests), ("unrelated", unrelated_requests)):
        for index, request in enumerate(requests):
            for repeat in range(repeats):
                cards = [target, *distractors]
                rng.shuffle(cards)  # the target's list position changes, so position bias averages out
                record = {"kind": kind, "request_index": index, "repeat": repeat + 1,
                          "target_position": [card.name for card in cards].index(target.name) + 1}
                try:
                    chosen = probe.choose(request=request, cards=cards)
                    if chosen not in names and chosen != NONE:
                        raise ValueError(f"probe returned an unknown skill name: {chosen!r}")
                    record.update(chosen=chosen, error=None)
                except Exception as exc:  # keep failures visible; they are not counted as choices
                    record.update(chosen=None, error=f"{type(exc).__name__}: {exc}")
                records.append(record)

    def counted(kind: str) -> list[dict[str, Any]]:
        return [r for r in records if r["kind"] == kind and r["error"] is None]

    relevant, unrelated = counted("relevant"), counted("unrelated")
    picked = sum(r["chosen"] == target.name for r in relevant)
    wrong = sum(r["chosen"] not in {target.name, NONE} for r in relevant)
    activation_rate = _rate(picked, len(relevant))
    expected_lift = (
        round(activation_rate * forced_lift_percentage_points, 2)
        if activation_rate is not None and forced_lift_percentage_points is not None else None
    )
    by_request = []
    for kind, requests in (("relevant", relevant_requests), ("unrelated", unrelated_requests)):
        for index, request in enumerate(requests):
            rows = [r for r in records if r["kind"] == kind and r["request_index"] == index and r["error"] is None]
            choices: dict[str, int] = {}
            for row in rows:
                choices[row["chosen"]] = choices.get(row["chosen"], 0) + 1
            by_request.append({
                "kind": kind, "request_index": index, "request": request[:160], "trials": len(rows),
                "target_rate": _rate(sum(r["chosen"] == target.name for r in rows), len(rows)), "choices": choices,
            })
    return {
        "method": "model_routing_proxy",
        "target_skill": target.name,
        "candidate_skills": len(names),
        "repeats": repeats,
        "relevant": {
            "trials": len(relevant),
            "activation_rate": activation_rate,
            "picked_other_skill": wrong,
            "picked_none": sum(r["chosen"] == NONE for r in relevant),
        },
        "unrelated": {
            "trials": len(unrelated),
            "false_activation_rate": _rate(sum(r["chosen"] == target.name for r in unrelated), len(unrelated)),
        },
        "failures": sum(r["error"] is not None for r in records),
        # An average can hide a task where the skill is never picked; read this before the overall rate.
        "by_request": by_request,
        "forced_lift_percentage_points": forced_lift_percentage_points,
        "expected_lift_percentage_points": expected_lift,
        "records": records,
        "limitations": (
            "A model choosing from a list of names and descriptions is a proxy for an agent's skill loader, not a "
            "measurement of any specific product. Seeds reduce but do not remove run-to-run variation in local models. Expected lift assumes the forced lift holds whenever the skill "
            "loads, and ignores any harm from false activation. Small request sets give unstable rates."
        ),
    }
