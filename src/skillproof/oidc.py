"""OIDC JWT access-token verification and RBAC principal mapping."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError, PyJWTError

from skillproof.authorization import Principal


class AuthenticationError(ValueError):
    """Access token could not be verified or mapped to an authorized principal."""


class SigningKeyClient(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    jwks_url: str
    role_claim: str = "skillproof_role"
    tenant_claim: str = "tenant_id"
    algorithms: tuple[str, ...] = ("RS256",)
    accepted_types: tuple[str, ...] = ("at+jwt", "application/at+jwt")
    leeway_seconds: int = 30
    jwks_timeout_seconds: float = 5

    def __post_init__(self) -> None:
        for label, value in (("issuer", self.issuer), ("JWKS URL", self.jwks_url)):
            parsed = urlparse(value)
            # Plain HTTP only to this machine's loopback outside production (a local development provider).
            loopback_http = (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                             and os.getenv("SKILLPROOF_ENV", "").lower() != "production")
            if (parsed.scheme != "https" and not loopback_http) or not parsed.netloc or parsed.username or parsed.password:
                raise ValueError(f"{label} must be an HTTPS URL without embedded credentials")
        if not self.audience.strip():
            raise ValueError("audience is required")
        if not self.algorithms or any(alg not in {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"} for alg in self.algorithms):
            raise ValueError("algorithms must be an explicit asymmetric JWT allowlist")
        if self.leeway_seconds < 0 or self.jwks_timeout_seconds <= 0:
            raise ValueError("token leeway and JWKS timeout are outside supported ranges")

    @classmethod
    def from_env(cls) -> "OIDCSettings | None":
        issuer = os.getenv("SKILLPROOF_OIDC_ISSUER")
        audience = os.getenv("SKILLPROOF_OIDC_AUDIENCE")
        jwks_url = os.getenv("SKILLPROOF_OIDC_JWKS_URL")
        if not any((issuer, audience, jwks_url)):
            return None
        if not all((issuer, audience, jwks_url)):
            raise ValueError("OIDC issuer, audience, and JWKS URL must be configured together")
        return cls(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            role_claim=os.getenv("SKILLPROOF_OIDC_ROLE_CLAIM", "skillproof_role"),
            tenant_claim=os.getenv("SKILLPROOF_OIDC_TENANT_CLAIM", "tenant_id"),
            leeway_seconds=int(os.getenv("SKILLPROOF_OIDC_LEEWAY_SECONDS", "30")),
            jwks_timeout_seconds=float(os.getenv("SKILLPROOF_OIDC_JWKS_TIMEOUT_SECONDS", "5")),
        )


class OIDCAccessTokenVerifier:
    REQUIRED_CLAIMS = ["iss", "aud", "exp", "sub", "iat", "jti", "client_id"]

    def __init__(self, settings: OIDCSettings, signing_keys: SigningKeyClient | None = None):
        self.settings = settings
        self.signing_keys = signing_keys or PyJWKClient(
            settings.jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=settings.jwks_timeout_seconds,
        )

    def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
            if str(header.get("typ", "")).lower() not in {value.lower() for value in self.settings.accepted_types}:
                raise AuthenticationError("token is not a supported access-token type")
            if header.get("alg") not in self.settings.algorithms or not isinstance(header.get("kid"), str):
                raise AuthenticationError("token signing algorithm or key identifier is not accepted")
            key = self.signing_keys.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self.settings.algorithms),
                audience=self.settings.audience,
                issuer=self.settings.issuer,
                leeway=self.settings.leeway_seconds,
                options={"require": self.REQUIRED_CLAIMS},
            )
        except AuthenticationError:
            raise
        except (PyJWTError, PyJWKClientError, TypeError, ValueError) as exc:
            raise AuthenticationError("access token validation failed") from exc

        role_value = claims.get(self.settings.role_claim)
        tenant_id = claims.get(self.settings.tenant_claim)
        subject = claims.get("sub")
        if not isinstance(role_value, str) or role_value not in {"tenant_admin", "evaluator", "approver", "viewer", "reporter"}:
            raise AuthenticationError("access token has no single recognized SkillProof role")
        if not isinstance(tenant_id, str) or not tenant_id.strip() or not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("access token lacks a valid subject or tenant claim")
        try:
            return Principal(user_id=subject, tenant_id=tenant_id, role=role_value)  # type: ignore[arg-type]
        except ValueError as exc:
            raise AuthenticationError("access token principal claims are invalid") from exc


def verifier_from_environment() -> OIDCAccessTokenVerifier | None:
    settings = OIDCSettings.from_env()
    auth_mode = os.getenv("SKILLPROOF_AUTH_MODE", "local").lower()
    deployment = os.getenv("SKILLPROOF_ENV", "development").lower()
    if auth_mode not in {"local", "oidc"}:
        raise ValueError("SKILLPROOF_AUTH_MODE must be 'local' or 'oidc'")
    if deployment == "production" and auth_mode != "oidc":
        raise RuntimeError("production mode requires SKILLPROOF_AUTH_MODE=oidc")
    if auth_mode == "oidc" and settings is None:
        raise RuntimeError("OIDC mode requires issuer, audience, and JWKS URL settings")
    if auth_mode == "local" and settings is not None:
        raise RuntimeError("OIDC settings are present while auth mode is local; set SKILLPROOF_AUTH_MODE=oidc")
    return OIDCAccessTokenVerifier(settings) if settings is not None else None


_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


def browser_login_config() -> dict[str, Any]:
    """What the catalogue page needs to sign a person in with the authorization code flow and PKCE (public client).

    The page never holds a client secret: SKILLPROOF_OIDC_CLIENT_ID names a public client registered at the identity
    provider with the page's address as its redirect URI. Endpoints come from the issuer's discovery document unless
    SKILLPROOF_OIDC_AUTHORIZATION_URL / SKILLPROOF_OIDC_TOKEN_URL set them."""
    settings = OIDCSettings.from_env()
    client_id = os.getenv("SKILLPROOF_OIDC_CLIENT_ID", "").strip()
    if settings is None:
        return {"mode": "local"}
    config: dict[str, Any] = {"mode": "oidc", "issuer": settings.issuer, "client_id": client_id or None,
                              "scope": os.getenv("SKILLPROOF_OIDC_SCOPE", "openid profile"),
                              "audience": settings.audience}
    authorization = os.getenv("SKILLPROOF_OIDC_AUTHORIZATION_URL", "").strip()
    token = os.getenv("SKILLPROOF_OIDC_TOKEN_URL", "").strip()
    end_session = os.getenv("SKILLPROOF_OIDC_END_SESSION_URL", "").strip()
    if not (authorization and token):
        discovered = _discover(settings.issuer)
        authorization = authorization or discovered.get("authorization_endpoint", "")
        token = token or discovered.get("token_endpoint", "")
        end_session = end_session or discovered.get("end_session_endpoint", "")
    for name, url in (("authorization_endpoint", authorization), ("token_endpoint", token), ("end_session_endpoint", end_session)):
        if url and urlparse(url).scheme not in {"https", "http"}:
            url = ""
        config[name] = url or None
    config["sign_in"] = bool(client_id and config["authorization_endpoint"] and config["token_endpoint"])
    return config


def _discover(issuer: str) -> dict[str, Any]:
    if issuer in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[issuer]
    import json
    import urllib.request

    try:
        with urllib.request.urlopen(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=5) as response:
            document = json.loads(response.read(1_000_000).decode("utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(document, dict) or document.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        return {}
    _DISCOVERY_CACHE[issuer] = document
    return document
