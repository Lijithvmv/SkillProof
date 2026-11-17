"""Rank what an update adds, so a reviewer reads the dangerous lines first.

The capability diff answers "what can the new version do that the old one could not?". A real update can add
twenty facts at once (packages, hosts, tools), and most are routine. Triage turns that list into a decision aid:

1. **Level per fact.** Each added fact gets a level from what it lets the skill do, not from its category name:
   piping a download into a shell, a permission-bypass flag, reading SSH keys or the whole environment, startup
   persistence and hiding techniques are ``block``; a new hook, a write to agent configuration, a new external
   host, a secret read or a broad tool grant is ``ask``; an ordinary pinned package or a read-only tool is ``note``.
2. **Combinations.** Facts that are routine alone are dangerous together in one file: a secret read plus an
   outbound call is the exfiltration shape, a download plus a shell is fetch-and-execute, a hook plus network is
   a call made on every session without anyone asking. Combinations raise the level.
3. **Rarity.** How often the same fact was added across real public skill updates (base rates shipped with the
   package). Something added in 1 of 10,000 updates is worth a closer look than something added in 800.
4. **Place.** A fact found only in test files is capped at ``note``.

Nothing here is a verdict on intent; ``block`` means "do not apply this update without reading these lines".
"""
from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from skillproof.capabilities import source_kind

LEVELS = {"block": 3, "ask": 2, "note": 1}
BASE_RATES = Path(__file__).with_name("data") / "base_rates.json"

BLOCK_VALUES = {
    "process_execution": {"pipe-to-shell"},
    "agent_spawning": {"permission bypass"},
    "credential_access": {"ssh keys", "aws credentials", "browser data", "keychain", "netrc", "npmrc/pypirc", "gh token", "env:<all>"},
    "persistence": {"shell rc", "cron", "systemd", "launchd", "windows run key", "scheduled task", "startup folder"},
    "destructive_operations": {"format/mkfs", "dd"},
}
ASK_CATEGORIES = {"hooks", "agent_config_writes", "agent_spawning", "network_hosts", "network_clients", "process_execution",
                  "credential_access", "persistence", "destructive_operations", "bundled_binaries"}
BROAD_TOOLS = re.compile(r"^(?:Bash|Write|Edit|MultiEdit|WebFetch|NotebookEdit|Task|Agent|\*)(?:\(\*?\))?$|^Bash\((?:[^)]*(?:curl|wget|rm|sudo|sh|bash|python|node|npx|\*))", re.I)
EVERY_TURN_EVENTS = re.compile(r"^(?:UserPromptSubmit|PreToolUse|PostToolUse|postToolUse|preToolUse|beforeShellExecution|afterMCPExecution|userPromptSubmitted)\b")
UNPINNED_RUNNER = re.compile(r"^(?:npx|bunx|pnpm dlx|uvx):(?:.*@latest|[^@]+)$")
SOURCE_INSTALL = re.compile(r"^[\w ]+:(?:https?://|git\+|github:)")
NETWORK = ("network_hosts", "network_clients")
EXECUTION_SHAPES = {"pipe-to-shell", "shell -c", "eval", "exec", "powershell", "cmd /c"}


@lru_cache(maxsize=1)
def load_base_rates(path: str | None = None) -> dict[str, Any]:
    target = Path(path) if path else BASE_RATES
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"updates": 0, "values": {}, "categories": {}}


def _base_level(category: str, value: str) -> tuple[str, str]:
    if value in BLOCK_VALUES.get(category, set()) or category == "hiding_techniques":
        return "block", {
            "pipe-to-shell": "runs downloaded or generated text as code",
            "permission bypass": "starts an agent with the approval step switched off",
            "env:<all>": "reads the whole environment, including every secret in it",
        }.get(value, f"{category.replace('_', ' ')}: {value}")
    if category == "hooks":
        if EVERY_TURN_EVENTS.match(value):
            return "ask", "runs by itself on every prompt or tool call, without the skill being used"
        return "ask", "runs by itself on an agent event, without the skill being used"
    if category == "declared_tools":
        if BROAD_TOOLS.search(value):
            return "ask", "pre-approves a tool that can change files, run commands or reach the network"
        return "note", "pre-approves a read-only tool"
    if category == "package_installs":
        if value.startswith("vendored:"):
            return "ask", "ships third-party code inside the skill"
        if SOURCE_INSTALL.match(value):
            return "ask", "installs from a URL or repository, not a registry release"
        if UNPINNED_RUNNER.match(value):
            return "ask", "downloads and runs the newest release each time (unpinned)"
        return "note", "installs a package"
    if category == "credential_access":
        return "ask", "reads a secret" if value.startswith("env:") else f"touches {value}"
    if category == "network_hosts":
        return "ask", "contacts a new external host"
    if category in ASK_CATEGORIES:
        return "ask", category.replace("_", " ")
    return "note", category.replace("_", " ")


def _file(location: str) -> str:
    return re.sub(r":(?:\d+|decoded)$", "", location)


GENERIC_SECRET_WORDS = {"API", "KEY", "KEYS", "TOKEN", "SECRET", "ACCESS", "AUTH", "PASSWORD", "PAT", "ENV", "CLIENT", "PRIVATE"}


def _own_service(secret: str, hosts: set[str]) -> bool:
    """OPENROUTER_API_KEY going to openrouter.ai is the key doing its job; going to collect.zz-metrics.io is not."""
    words = {w.lower() for w in re.split(r"[_\W]+", secret.removeprefix("env:")) if len(w) > 2 and w.upper() not in GENERIC_SECRET_WORDS}
    return bool(words) and any(any(word in host.lower() for word in words) for host in hosts)


def _combinations(added: dict[str, dict[str, list[str]]]) -> list[dict[str, Any]]:
    """Dangerous pairs inside one file: the shape that matters is the pair, not either fact alone."""
    by_file: dict[str, dict[str, set[str]]] = {}
    for category, values in added.items():
        for value, locations in values.items():
            for location in locations:
                path = _file(location)
                # Pairs count in code the skill ships and runs, and in hook definitions. In Markdown, "read
                # DATABASE_URL, then connect" is an SDK example being taught; on held-out data 8 of 11 block items
                # from doc-file pairs were such examples. A dangerous fact in a doc keeps its own level.
                if source_kind(location) != "shipped":
                    continue
                by_file.setdefault(path, {}).setdefault(category, set()).add(value)

    def tagged(facts: dict[str, set[str]], *categories: str, only: set[str] | None = None) -> list[str]:
        return sorted(f"{c}|{v}" for c in categories for v in facts.get(c, set()) if only is None or v in only)

    found = []
    for path, facts in sorted(by_file.items()):
        network = tagged(facts, *NETWORK)
        secrets = tagged(facts, "credential_access")
        execution = tagged(facts, "process_execution", only=EXECUTION_SHAPES)
        if secrets and network:
            hosts = facts.get("network_hosts", set())
            if hosts and all(_own_service(secret.split("|", 1)[1], hosts) for secret in secrets):
                found.append({"file": path, "shape": "secret to its own service", "level": "ask", "facts": secrets + network,
                              "why": "reads a key and calls the service the key is named after (" + ", ".join(sorted(hosts)) + ")"})
            else:
                found.append({"file": path, "shape": "exfiltration", "level": "block", "facts": secrets + network,
                              "why": "reads a secret and sends data out from the same file"})
        if network and execution:
            found.append({"file": path, "shape": "fetch-and-execute", "level": "block", "facts": network + execution,
                          "why": "downloads and runs code from the same file"})
        if facts.get("hooks") and (network or facts.get("package_installs")):
            found.append({"file": path, "shape": "unattended network", "level": "block",
                          "facts": tagged(facts, "hooks") + network + tagged(facts, "package_installs"),
                          "why": "a hook reaches the network or installs a package on every trigger, with no one asking"})
        if facts.get("agent_config_writes") and network:
            found.append({"file": path, "shape": "remote instructions", "level": "block",
                          "facts": tagged(facts, "agent_config_writes") + network,
                          "why": "writes agent instructions in a file that also fetches remote content"})
    return found


def triage(diff: dict[str, Any], base_rates: dict[str, Any] | None = None) -> dict[str, Any]:
    """Rank the additions in a diff_manifests() result. Returns the decision (highest level), the ranked items,
    and the dangerous combinations found."""
    rates = base_rates if base_rates is not None else load_base_rates()
    total = max(int(rates.get("updates", 0)), 0)
    added: dict[str, dict[str, list[str]]] = diff.get("added", {})
    sources: dict[str, dict[str, list[str]]] = diff.get("added_sources", {})
    combos = _combinations(added)
    combo_level: dict[tuple[str, ...], str] = {}
    for combo in combos:
        for fact in combo["facts"]:
            key = tuple(fact.split("|", 1))
            if LEVELS[combo["level"]] > LEVELS[combo_level.get(key, "note")]:
                combo_level[key] = combo["level"]
    items = []
    for category, values in added.items():
        for value, locations in values.items():
            level, reason = _base_level(category, value)
            reasons = [reason]
            paired = combo_level.get((category, value))
            if paired and LEVELS[paired] > LEVELS[level]:
                level = paired
                reasons.append("part of a dangerous combination (see combinations)")
            kinds = sources.get(category, {}).get(value, [])
            if kinds == ["test"]:
                level = "note"
                reasons.append("only in test files")
            seen = rates.get("values", {}).get(f"{category}|{value}")
            rarity_bits = None
            if total:
                count = int(seen or 0)
                rarity_bits = round(-math.log2((count + 1) / (total + 2)), 1)
                reasons.append(f"added in {count} of {total:,} real public skill updates" if count else f"never added in {total:,} real public skill updates")
            score = LEVELS[level] * 100 + (rarity_bits or 0)
            items.append({"category": category, "value": value, "level": level, "score": round(score, 1),
                          "rarity_bits": rarity_bits, "reasons": reasons, "locations": locations[:5]})
    items.sort(key=lambda item: (-item["score"], item["category"], item["value"]))
    decision = max((item["level"] for item in items), key=LEVELS.get, default="none")
    counts = {level: sum(item["level"] == level for item in items) for level in LEVELS}
    return {
        "decision": decision,
        "counts": counts,
        "items": items,
        "combinations": combos,
        "base_rates": {"updates": total, "source": rates.get("source", "")},
        "meaning": "block = do not apply without reading these lines; ask = confirm this is expected; note = routine. "
                   "Levels come from what a fact lets the skill do and from dangerous pairs in one file, not from intent.",
    }
