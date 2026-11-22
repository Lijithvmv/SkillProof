"""The capability manifest: facts per category with their locations, decode trail, reasons and scopes."""
from __future__ import annotations


from dataclasses import dataclass, field
from typing import Any

from skillproof.engines.capabilities.positions import CATEGORIES, MANIFEST_VERSION


@dataclass
class Manifest:
    capabilities: dict[str, dict[str, list[str]]] = field(default_factory=lambda: {c: {} for c in CATEGORIES})
    decode_trail: list[dict[str, str]] = field(default_factory=list)
    files: int = 0
    scopes: dict[str, set[str]] = field(default_factory=dict)  # "category|value" -> reach seen (see SCOPE_RANK)
    mentions: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # named but not contacted / read
    reasons: dict[str, str] = field(default_factory=dict)  # "category|value" -> why it counts (first seen)

    def mention(self, category: str, value: str, location: str) -> None:
        locations = self.mentions.setdefault(category, {}).setdefault(value, [])
        if location not in locations and len(locations) < 5:
            locations.append(location)

    def add(self, category: str, value: str, location: str) -> None:
        locations = self.capabilities[category].setdefault(value, [])
        if location not in locations and len(locations) < 20:
            locations.append(location)

    def scope(self, category: str, value: str, scope: str | None) -> None:
        if scope and value in self.capabilities[category]:
            self.scopes.setdefault(f"{category}|{value}", set()).add(scope)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "method": "decode_then_extract_facts",
            "files": self.files,
            "capabilities": {c: {v: sorted(locs) for v, locs in sorted(values.items())} for c, values in self.capabilities.items()},
            "scopes": {key: sorted(values) for key, values in sorted(self.scopes.items())},
            "reasons": dict(sorted(self.reasons.items())),
            "mentions": {c: {v: sorted(l) for v, l in sorted(values.items()) if v not in self.capabilities.get(c, {})}
                         for c, values in sorted(self.mentions.items())},
            "decode_trail": self.decode_trail[:200],
            "limitations": (
                "Facts from static text after reversing common hiding techniques. Content that is fetched at run time, "
                "generated, or hidden by a technique not reversed here is not seen. Nothing was executed. A listed "
                "capability is not a verdict, and an empty category is not proof of absence."
            ),
        }
