"""Who wrote a skill version, and what that means for its review.

Skills are increasingly written and rewritten by agents (self-improving agents, an agent asked to "fix the skill",
skills edited in place on disk). A version's provenance records what SkillProof can establish about its author:

- `human`    a person registered it and attests they wrote it (an upload by a human identity). With OIDC, only from a
             token whose interactive sign-in (auth_time) is recent: an agent running unattended on a person's token
             carries an old sign-in, so its "human" attestation is recorded as `unknown`;
- `agent`    an agent identity registered it, or whoever registered it says an agent wrote it;
- `unknown`  nobody can attest (an installed folder that changed on disk: the importer saw the files, not the author).

Two rules follow, and neither can be argued down by a declaration:

1. Only a version attested as human-written is reviewed as a change over the version before it. An agent-written or
   unknown update is held to the bar of a new skill: everything it can do is raised for review, because an agent can
   introduce a capability in a rewrite that a diff against its own previous output would hide.
2. No author of a version approves it: not the identity that registered it, not the agent that wrote it, not the
   person the agent acted for. Agent identities never approve, promote, dismiss raised items or change policy.

Declarations only ever raise the bar: an agent identity cannot declare a version human-written, and an importer
cannot attest anything about files it found on disk.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, TypedDict

if TYPE_CHECKING:
    from skillproof.authorization import Principal

AuthorKind = Literal["human", "agent", "unknown"]
Source = Literal["upload", "installed_import", "api"]
DECLARED_FIELDS = {"author_kind": 16, "agent": 200, "model": 200, "session": 200, "derived_from": 128, "note": 500}


class ProvenanceError(ValueError):
    """A provenance declaration that cannot be accepted."""


class Provenance(TypedDict, total=False):
    author_kind: AuthorKind
    registered_by: str          # the identity that registered the version
    registered_as: str          # 'human' or 'agent': what that identity is
    on_behalf_of: str | None    # the person an agent identity acted for (token delegation)
    agent: str | None           # the agent that wrote it, when known
    model: str | None
    session: str | None
    derived_from: str | None    # the version or fingerprint it was rewritten from, when declared
    note: str | None
    source: Source
    basis: list[str]            # how the author kind was established, in words
    review_bar: Literal["change_over_previous", "new_skill"]
    recorded_at: str


def _declared(declared: dict[str, Any] | None) -> dict[str, str]:
    if declared is None:
        return {}
    if not isinstance(declared, dict):
        raise ProvenanceError("provenance must be a JSON object")
    unknown = set(declared) - set(DECLARED_FIELDS)
    if unknown:
        raise ProvenanceError(f"unknown provenance fields: {sorted(unknown)}")
    out = {}
    for key, value in declared.items():
        if value is None:
            continue
        if not isinstance(value, str) or len(value) > DECLARED_FIELDS[key] or "\x00" in value:
            raise ProvenanceError(f"provenance field '{key}' must be text of at most {DECLARED_FIELDS[key]} characters")
        out[key] = value.strip()
    if out.get("author_kind", "human") not in {"human", "agent", "unknown"}:
        raise ProvenanceError("author_kind must be 'human', 'agent' or 'unknown'")
    return out


def resolve(principal: Principal, declared: dict[str, Any] | None = None, *, source: Source = "upload") -> Provenance:
    """The provenance of a version registered by this principal, with this declaration, from this source."""
    claim = _declared(declared)
    basis: list[str] = []
    if principal.actor_kind == "agent":
        kind: AuthorKind = "agent"
        basis.append(f"registered by agent identity {principal.user_id}"
                     + (f" acting for {principal.on_behalf_of}" if principal.on_behalf_of else ""))
        if claim.get("author_kind") in {"human", "unknown"}:
            basis.append(f"declared {claim['author_kind']}, ignored: an agent identity cannot lower the bar")
    elif source == "installed_import":
        kind = "agent" if claim.get("author_kind") == "agent" else "unknown"
        basis.append("found on disk by the importer, which cannot attest who wrote the files")
        if kind == "agent":
            basis.append("declared agent-written")
    else:
        kind = claim.get("author_kind", "human")  # type: ignore[assignment]
        basis.append(f"registered by {principal.user_id}, who " + ("attests a person wrote it" if kind == "human" else f"declares it {kind}"))
        if kind == "human" and principal.identity_source == "oidc":
            # An agent running unattended on a person's token is indistinguishable by identity; the sign-in time is not.
            from skillproof.config import settings

            limit = settings().human_attestation_max_age_seconds
            age = None if principal.signed_in_at is None else int(datetime.now(timezone.utc).timestamp()) - principal.signed_in_at
            if age is None or age > limit or age < -300:
                kind = "unknown"
                basis.append("not accepted as human-written: the token " + ("has no interactive sign-in time (auth_time)"
                             if age is None else f"was signed in {age // 60} minute(s) ago (limit {limit // 60})")
                             + ", so an agent using the person's token cannot be ruled out")
    return Provenance(
        author_kind=kind, registered_by=principal.user_id, registered_as=principal.actor_kind,
        on_behalf_of=principal.on_behalf_of, agent=claim.get("agent") or (principal.user_id if principal.actor_kind == "agent" else None),
        model=claim.get("model"), session=claim.get("session"), derived_from=claim.get("derived_from"), note=claim.get("note"),
        source=source, basis=basis, review_bar="change_over_previous" if kind == "human" else "new_skill",
        recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def full_review(provenance: Provenance | dict[str, Any] | None) -> bool:
    """Whether the version is held to the bar of a new skill. A version without provenance (registered before it was
    recorded) keeps the comparison it was registered with."""
    return bool(provenance) and (provenance or {}).get("author_kind") != "human"


def authors(provenance: Provenance | dict[str, Any] | None, registered_by: str) -> set[str]:
    """Every identity that counts as an author of the version and so may not approve it."""
    found = {registered_by}
    for key in ("registered_by", "on_behalf_of", "agent"):
        value = (provenance or {}).get(key)
        if isinstance(value, str) and value.strip():
            found.add(value.strip())
    return found
