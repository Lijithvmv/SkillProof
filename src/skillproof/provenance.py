"""Who wrote a skill version, and what that means for its review.

Skills are increasingly written and rewritten by agents (self-improving agents, an agent asked to "fix the skill",
skills edited in place on disk). A version's provenance records what SkillProof can establish about its author:

- `human`    a person registered it and attests they wrote it (an upload by a human identity). With OIDC, only from a
             token whose interactive sign-in (auth_time) is recent: an agent running unattended on a person's token
             carries an old sign-in, so its "human" attestation is recorded as `unknown`. A server can also require a
             strong sign-in method (amr), a scope only a person's own sign-in requests, and one attestation per
             sign-in, so a token reused after the person attested cannot attest again;
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
    attested_sign_in: str       # with one attestation per sign-in: the (hashed) sign-in this attestation used


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


def sign_in_key(principal: Principal) -> str | None:
    """Which interactive sign-in a token comes from (tenant, subject, session id, sign-in time), hashed; None for a
    token with no sign-in time or a development sign-in."""
    if principal.identity_source != "oidc" or principal.signed_in_at is None:
        return None
    import hashlib

    raw = "|".join([principal.tenant_id, principal.on_behalf_of or principal.user_id, principal.sign_in_session or "",
                    str(principal.signed_in_at)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:40]


def resolve(principal: Principal, declared: dict[str, Any] | None = None, *, source: Source = "upload",
            sign_in_used_by: str | None = None) -> Provenance:
    """The provenance of a version registered by this principal, with this declaration, from this source.
    `sign_in_used_by` names the version this token's sign-in already attested, when the server allows one attestation
    per sign-in (the caller looks it up with sign_in_key)."""
    claim = _declared(declared)
    basis: list[str] = []
    attested: str | None = None
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
            required = settings().human_attestation_methods
            age = None if principal.signed_in_at is None else int(datetime.now(timezone.utc).timestamp()) - principal.signed_in_at
            if age is None or age > limit or age < -300:
                kind = "unknown"
                basis.append("not accepted as human-written: the token " + ("has no interactive sign-in time (auth_time)"
                             if age is None else f"was signed in {age // 60} minute(s) ago (limit {limit // 60})")
                             + ", so an agent using the person's token cannot be ruled out")
            elif required and not set(required) & set(principal.sign_in_methods):
                kind = "unknown"
                basis.append(f"not accepted as human-written: the sign-in used {list(principal.sign_in_methods) or 'no stated method'}, "
                             f"and this server requires one of {list(required)} (amr)")
            elif settings().human_attestation_scope and settings().human_attestation_scope not in principal.scopes:
                kind = "unknown"
                basis.append(f"not accepted as human-written: the token lacks the scope {settings().human_attestation_scope!r}, "
                             "which only a person's own sign-in for attesting requests")
            elif settings().human_attestation_once_per_sign_in and sign_in_used_by:
                kind = "unknown"
                basis.append(f"not accepted as human-written: this sign-in already attested version {sign_in_used_by}; each "
                             "sign-in attests one version, so a reused token cannot attest again (sign in again to attest)")
            elif settings().human_attestation_once_per_sign_in:
                attested = sign_in_key(principal)
    record = Provenance(
        author_kind=kind, registered_by=principal.user_id, registered_as=principal.actor_kind,
        on_behalf_of=principal.on_behalf_of, agent=claim.get("agent") or (principal.user_id if principal.actor_kind == "agent" else None),
        model=claim.get("model"), session=claim.get("session"), derived_from=claim.get("derived_from"), note=claim.get("note"),
        source=source, basis=basis, review_bar="change_over_previous" if kind == "human" else "new_skill",
        recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    if attested:
        record["attested_sign_in"] = attested
    return record


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
