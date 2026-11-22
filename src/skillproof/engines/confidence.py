"""How often is a flag like this one a real capability? Measured, not assumed.

The extractor finds what an update adds with high recall, but on repositories it has never seen, some kinds of flag are
mostly mentions (persistence named in prose, agent commands in text, test code) while others are almost always real
(installs, hooks, deletions, hosts in a shell step). Hand rules tuned on seen examples did not carry to new
repositories, and neither did a learned per-line model (both measured on eight held-out tests). What did hold is the
simplest calibrated quantity: the share of real flags per CATEGORY and BLOCK KIND, measured on labelled public skill
updates and updated with each tenant's own reviewer decisions.

- block kind: "step" when any location is a shell step in a document or a script file; "test" when every location is
  test code; otherwise "text" (prose, inline spans, tables, other code blocks).
- confidence: the posterior mean of a Beta distribution whose counts are the public labels (data/category_confidence.json)
  plus the tenant's own: items it approved (real) and items its reviewers marked "Not real" (false).
- an item whose confidence is below the cut for its level (LOWER_BELOW) is lowered one level with the numbers shown;
  nothing is hidden.

The skill's stated purpose (from its own SKILL.md description) also marks attack toolkits and audit/rules libraries,
whose text blocks are where line-by-line judgement fails most; triage groups those flags for one review.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib import resources
from pathlib import PurePosixPath
from typing import Any

# Lower an item when P(real) is below the cost-weighted cut for its level (Bayes decision: lower when
# P(real) < cost_false_alarm / (cost_false_alarm + cost_miss)). Missing a real block-level fact is taken as nine times
# worse than one false alarm; for ask-level facts the two costs are taken as equal. Measured with each held-out scored
# by a table built without it: 16 of 737 real items lowered (2.2%), none of them block-level.
LOWER_BELOW = {"block": 0.1, "ask": 0.5}
EXCLUDED = {"declared_tools", "bundled_binaries"}
SCRIPT = re.compile(r"\.(py|sh|bash|zsh|js|mjs|cjs|ts|ps1|rb|go|rs|php|pl|lua)$", re.I)
TEST = re.compile(r"(^|/)(tests?|spec|__tests__|testdata|fixtures?)/|(^|/)test_[^/]*$|_test\.\w+$|\.(test|spec)\.\w+$|(^|/)conftest\.py$", re.I)
SHELL_LANGS = {"bash", "sh", "zsh", "shell", "console", "powershell", "pwsh", "ps1", "cmd", "bat", "terminal", "fish"}
FENCE = re.compile(r"^\s*(```+|~~~+)\s*([\w+-]*)")
DESCRIPTION = re.compile(r"^description:\s*(.+?)(?:\n[A-Za-z_-]+:|\n---)", re.S | re.M)
OFFENSIVE = re.compile(r"pentest|penetration test|exploit|red[- ]?team|offensive|attack|payload|vulnerab|bug bounty|\bctf\b|"
                       r"\bxss\b|\bssrf\b|injection|post-exploitation|privilege escalation", re.I)
AUDIT = re.compile(r"\baudit|code review|security review|checklist|best practices|guidelines?\b|compliance|hardening|\blint", re.I)


def _shell_fence_lines(raw: bytes) -> set[int]:
    lines, inside, lang = set(), False, ""
    for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        fence = FENCE.match(line)
        if fence:
            inside, lang = (not inside), (fence.group(2).lower() if not inside else "")
            continue
        if inside and lang in SHELL_LANGS:
            lines.add(number)
    return lines


def block_of(files: dict[str, bytes], locations: list[str], fence_cache: dict[str, set[int]] | None = None) -> str:
    fence_cache = {} if fence_cache is None else fence_cache
    kinds = []
    for location in locations[:5]:
        path, _, number = location.rpartition(":")
        if not number.isdigit():
            path, number = location, ""
        if TEST.search(path):
            kinds.append("test")
        elif SCRIPT.search(path):
            kinds.append("step")
        elif number and path in files:
            if path not in fence_cache:
                fence_cache[path] = _shell_fence_lines(files[path])
            kinds.append("step" if int(number) in fence_cache[path] else "text")
        else:
            kinds.append("text")
    if "step" in kinds:
        return "step"
    return "test" if kinds and all(k == "test" for k in kinds) else "text"


def purpose_of(files: dict[str, bytes]) -> dict[str, bool]:
    """What the skill says it is for, from its own SKILL.md (shortest SKILL.md path in the package)."""
    skill_md = min((p for p in files if PurePosixPath(p).name == "SKILL.md"), key=len, default=None)
    text = files.get(skill_md, b"")[:6000].decode("utf-8", "replace") if skill_md else ""
    match = DESCRIPTION.search(text)
    said = (match.group(1) if match else "") + " " + " ".join(re.findall(r"^name:\s*(.+)$", text, re.M))
    return {"offensive": bool(OFFENSIVE.search(said)), "audit": bool(AUDIT.search(said))}


def add_blocks(manifest: dict[str, Any], files: dict[str, bytes]) -> None:
    """Record each risk value's block kind and the skill's stated purpose in the manifest (read by triage)."""
    cache: dict[str, set[int]] = {}
    manifest["blocks"] = {f"{category}|{value}": block_of(files, locations, cache)
                          for category, values in (manifest.get("capabilities") or {}).items() if category not in EXCLUDED
                          for value, locations in values.items()}
    manifest["purpose"] = purpose_of(files)


@lru_cache(maxsize=1)
def load_table() -> dict[str, Any]:
    try:
        return json.loads(resources.files("skillproof").joinpath("data/category_confidence.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {"counts": {}}


def confidence(category: str, block: str, table: dict[str, Any] | None = None,
               tenant_counts: dict[str, list[int]] | None = None) -> dict[str, Any] | None:
    """Posterior mean share of real flags for this category and block kind, with the counts behind it. None when
    neither the public labels nor the tenant have seen this kind of flag."""
    table = table if table is not None else load_table()
    key = f"{category}|{block}"
    real, false = (table.get("counts") or {}).get(key, [0, 0])
    t_real, t_false = (tenant_counts or {}).get(key, [0, 0])
    seen = real + false + t_real + t_false
    if not seen:
        return None
    p = (real + t_real + 1) / (seen + 2)  # Beta(1, 1) prior
    return {"p": round(p, 3), "real": real + t_real, "seen": seen, "block": block, "tenant_real": t_real, "tenant_false": t_false}
