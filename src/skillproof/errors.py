"""Typed errors shared by every layer. The API maps them to HTTP status in one place (api/main.py `_guarded`):
NotFound -> 404, Conflict (and any other SkillProofError) -> 409; AuthorizationError -> 403 is defined with the roles.
Callers decide by type, never by message text."""
from __future__ import annotations


class SkillProofError(ValueError):
    """A request SkillProof refuses: the message says why, in words a reviewer can act on."""


class NotFound(SkillProofError):
    """The thing asked for does not exist in this tenant (or the caller may not see it)."""


class Conflict(SkillProofError):
    """The request is valid but conflicts with the current state (wrong state, already decided, changed meanwhile)."""
