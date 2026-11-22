"""What a new version adds over an old one: added facts by source (instructions, shipped code, tests), widened
reach, re-pointed hooks."""
from __future__ import annotations

import re

from pathlib import PurePosixPath
from typing import Any

from skillproof.engines.capabilities.positions import CATEGORIES, DOC_SUFFIXES, SCOPE_RANK, TEST_NAME, TEST_PATH




def source_kind(location: str, invoked: set[str] | frozenset[str] = frozenset()) -> str:
    """Where a capability lives: 'instructions' (Markdown the agent reads and follows), 'shipped' (scripts and
    files that ship and can run), or 'test' (test files only). Instructions are not lower risk than code: for a
    skill they are what the agent is told to do. ``invoked`` lists test-named files the package itself runs."""
    path = location.rsplit(":", 1)[0] if re.search(r":(?:\d+|decoded)$", location) else location
    name = PurePosixPath(path).name
    if (TEST_PATH.search(path) or TEST_NAME.match(name)) and path not in invoked:
        return "test"
    if PurePosixPath(name).suffix.lower() in DOC_SUFFIXES:
        return "instructions"
    return "shipped"


def _hook_additions(before: dict[str, list[str]], after: dict[str, list[str]], gained: dict[str, list[str]]) -> tuple[dict[str, list[str]], list[str]]:
    """Split new hook values into real additions and re-pointings. A hook is added when an event gains a handler
    (a new event, a new client's event name, or one more handler on an event); a handler that only switches to
    another script on an event that already had as many handlers is a change, not a new capability (real plugin
    histories: 42 of 65 new hook values were .sh <-> .js ports or wrapper swaps). What the new script does is still
    read, because the script itself is scanned like any other file."""
    def count(values) -> dict[str, int]:
        counts: dict[str, int] = {}
        for value in values:
            key = value.split(":", 1)[0]  # "SessionStart command"
            counts[key] = counts.get(key, 0) + 1
        return counts
    old_counts = count(before)
    new_counts = count(after)
    kept, repointed = {}, []
    for value, locations in gained.items():
        key = value.split(":", 1)[0]
        if value.startswith("unreadable hooks file") or new_counts[key] > old_counts.get(key, 0):
            kept[value] = locations
        else:
            repointed.append(value)
    return kept, sorted(repointed)


def _widest(scopes: list[str]) -> str:
    return max(scopes, key=lambda scope: SCOPE_RANK.get(scope, 0))


def _widenings(old: dict[str, Any], new: dict[str, Any], added: dict[str, dict[str, list[str]]]) -> list[dict[str, Any]]:
    """Facts both versions have whose reach grew: rm -rf from a temp folder to the home folder, a hook from named
    tools to every tool, an allowed tool from `Bash(git:*)` to `Bash`. A manifest written before scopes were
    recorded has no "scopes" key; then reach is unknown, not narrow, and nothing is reported."""
    found = []
    old_scopes, new_scopes = old.get("scopes"), new.get("scopes") or {}
    if old_scopes is not None:
        for key, scopes in sorted(new_scopes.items()):
            before = old_scopes.get(key)
            category, value = key.split("|", 1)
            if not before or value in added.get(category, {}):
                continue
            wide, was = _widest(scopes), _widest(before)
            if SCOPE_RANK.get(wide, 0) > SCOPE_RANK.get(was, 0):
                found.append({"category": category, "value": value, "before": was, "after": wide,
                              "locations": new["capabilities"].get(category, {}).get(value, [])[:5]})
    before_tools = old["capabilities"].get("declared_tools", {})
    after_tools = new["capabilities"].get("declared_tools", {})
    for tool, locations in sorted(added.get("declared_tools", {}).items()):
        narrower = sorted(t for t in before_tools if t.startswith(tool + "(") and t not in after_tools)
        if "(" not in tool and narrower:
            found.append({"category": "declared_tools", "value": tool, "before": ", ".join(narrower), "after": "all uses",
                          "locations": locations[:5]})
    return found


def diff_manifests(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Capabilities the new version has that the old one did not (and the reverse)."""
    invoked = frozenset(new.get("invoked_test_named") or ())
    added: dict[str, dict[str, list[str]]] = {}
    removed: dict[str, list[str]] = {}
    repointed: list[str] = []
    for category in CATEGORIES:
        before, after = old["capabilities"].get(category, {}), new["capabilities"].get(category, {})
        gained = {value: locations for value, locations in after.items() if value not in before}
        lost = sorted(value for value in before if value not in after)
        if category == "hooks":
            gained, repointed[:] = _hook_additions(before, after, gained)
        if gained:
            added[category] = gained
        if lost:
            removed[category] = lost
    widened = _widenings(old, new, added)
    sources: dict[str, dict[str, list[str]]] = {}
    by_source = {"instructions": 0, "shipped": 0, "test": 0}
    for category, values in added.items():
        for value, locations in values.items():
            kinds = sorted({source_kind(location, invoked) for location in locations})
            sources.setdefault(category, {})[value] = kinds
            # An item counts once, under the riskiest place it appears: shipped code, then instructions, then tests.
            by_source[next(k for k in ("shipped", "instructions", "test") if k in kinds)] += 1
    return {
        "method": "capability_manifest_diff",
        "status": "new_capabilities" if added or widened else "no_new_capabilities",
        "added": added,
        "added_sources": sources,
        "added_by_source": by_source,
        "removed": removed,
        "hooks_repointed": repointed,
        "widened": widened,
        "added_scopes": {key: _widest(values) for key, values in (new.get("scopes") or {}).items()
                         if key.split("|", 1)[1] in added.get(key.split("|", 1)[0], {})},
        "new_categories": sorted(c for c in added if not old["capabilities"].get(c)),
        "limitations": "Compares extracted facts, not code. A capability that both versions mention is not reported even if how it is used changed.",
    }
