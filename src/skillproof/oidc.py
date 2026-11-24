"""OIDC JWT access-token verification and RBAC principal mapping."""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError, PyJWTError

from skillproof.authorization import Principal
from skillproof.config import settings


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
    agent_clients: tuple[str, ...] = ()
    client_id: str = ""   # the page's client: the audience of its ID tokens (attestation binding)

    def __post_init__(self) -> None:
        for label, value in (("issuer", self.issuer), ("JWKS URL", self.jwks_url)):
            parsed = urlparse(value)
            # Plain HTTP only to this machine's loopback outside production (a local development provider).
            loopback_http = (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                             and not settings().production)
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
        oidc = settings().oidc
        if not oidc.configured:
            return None
        if not all((oidc.issuer, oidc.audience, oidc.jwks_url)):
            raise ValueError("OIDC issuer, audience, and JWKS URL must be configured together")
        return cls(issuer=oidc.issuer, audience=oidc.audience, jwks_url=oidc.jwks_url, role_claim=oidc.role_claim,
                   accepted_types=oidc.accepted_types,
                   tenant_claim=oidc.tenant_claim, leeway_seconds=oidc.leeway_seconds, jwks_timeout_seconds=oidc.jwks_timeout_seconds,
                   agent_clients=oidc.agent_clients, client_id=oidc.client_id)


class OIDCAccessTokenVerifier:
    # client_id (RFC 9068) or azp: Keycloak puts the client in azp and adds client_id only for service accounts.
    REQUIRED_CLAIMS = ["iss", "aud", "exp", "sub", "iat", "jti"]

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
            header_type = str(header.get("typ", "")).lower()
            if header_type not in {value.lower() for value in self.settings.accepted_types}:
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
        if header_type == "jwt" and str(claims.get("typ", "")).lower() != "bearer":
            # A generic JWT header (Keycloak) is accepted only for a token that says it is an access token, so an ID
            # token from the same provider can never be used as one.
            raise AuthenticationError("token is not an access token (typ claim is not Bearer)")
        client = claims.get("client_id") or claims.get("azp")
        if not isinstance(client, str) or not client.strip():
            raise AuthenticationError("access token names no client (client_id or azp)")
        claims["client_id"] = client

        role_value = claims.get(self.settings.role_claim)
        tenant_id = claims.get(self.settings.tenant_claim)
        subject = claims.get("sub")
        if not isinstance(role_value, str) or role_value not in {"tenant_admin", "evaluator", "approver", "viewer", "reporter"}:
            raise AuthenticationError("access token has no single recognized SkillProof role")
        if not isinstance(tenant_id, str) or not tenant_id.strip() or not isinstance(subject, str) or not subject.strip():
            raise AuthenticationError("access token lacks a valid subject or tenant claim")
        # Agent identities. Delegation (RFC 8693 `act` claim): the token was issued to an agent acting for `sub`; the
        # agent is the identity that acts and the person it acts for is kept, so neither can approve what it wrote. A
        # token from an OAuth client the tenant issued to an agent (SKILLPROOF_OIDC_AGENT_CLIENTS) is an agent too.
        signed_in = claims.get("auth_time")
        signed_in_at = signed_in if isinstance(signed_in, int) and not isinstance(signed_in, bool) else None
        amr = claims.get("amr")
        methods = tuple(str(m) for m in amr if isinstance(m, str))[:20] if isinstance(amr, list) else ()
        sid = claims.get("sid")
        session = sid[:200] if isinstance(sid, str) and sid.strip() else None
        granted = claims.get("scope", claims.get("scp"))
        scopes = tuple((granted.split() if isinstance(granted, str) else [s for s in granted if isinstance(s, str)]
                        if isinstance(granted, list) else [])[:50])
        signed = {"signed_in_at": signed_in_at, "sign_in_methods": methods, "sign_in_session": session, "scopes": scopes}
        actor = claims.get("act")
        if actor is not None and (not isinstance(actor, dict) or not isinstance(actor.get("sub"), str) or not actor["sub"].strip()):
            raise AuthenticationError("access token has a malformed act (delegation) claim")
        try:
            if actor is not None:
                return Principal(user_id=actor["sub"], tenant_id=tenant_id, role=role_value,  # type: ignore[arg-type]
                                 actor_kind="agent", on_behalf_of=subject, identity_source="oidc", **signed)
            if claims.get("client_id") in self.settings.agent_clients:
                return Principal(user_id=subject, tenant_id=tenant_id, role=role_value, actor_kind="agent",  # type: ignore[arg-type]
                                 identity_source="oidc", **signed)
            return Principal(user_id=subject, tenant_id=tenant_id, role=role_value,  # type: ignore[arg-type]
                             identity_source="oidc", **signed)
        except ValueError as exc:
            raise AuthenticationError("access token principal claims are invalid") from exc


def verify_binding(verifier: OIDCAccessTokenVerifier, id_token: str, *, principal: Principal, nonce: str) -> None:
    """Check that an ID token comes from a sign-in made for this package by this person: signed by the provider,
    issued to the page's client, its nonce equal to the package's, its subject the access token's, and from the same
    sign-in (session id and sign-in time). Raises AuthenticationError with the reason otherwise."""
    settings_ = verifier.settings
    if not settings_.client_id:
        raise AuthenticationError("binding needs the page's client id (SKILLPROOF_OIDC_CLIENT_ID)")
    try:
        header = jwt.get_unverified_header(id_token)
        if header.get("alg") not in settings_.algorithms or not isinstance(header.get("kid"), str):
            raise AuthenticationError("ID token signing algorithm or key identifier is not accepted")
        key = verifier.signing_keys.get_signing_key_from_jwt(id_token).key
        claims = jwt.decode(id_token, key=key, algorithms=list(settings_.algorithms), audience=settings_.client_id,
                            issuer=settings_.issuer, leeway=settings_.leeway_seconds,
                            options={"require": ["iss", "aud", "exp", "iat", "sub", "nonce"]})
    except AuthenticationError:
        raise
    except (PyJWTError, PyJWKClientError, TypeError, ValueError) as exc:
        raise AuthenticationError("ID token validation failed") from exc
    if claims.get("typ") is not None and str(claims["typ"]).lower() != "id":
        raise AuthenticationError("the binding token is not an ID token")
    if principal.actor_kind != "human" or claims.get("sub") != principal.user_id:
        raise AuthenticationError("the ID token is for a different person than the access token")
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise AuthenticationError("the sign-in was made for a different package (nonce does not match these bytes)")
    sid, auth_time = claims.get("sid"), claims.get("auth_time")
    same_session = sid is not None and principal.sign_in_session is not None and sid == principal.sign_in_session
    same_time = auth_time is not None and principal.signed_in_at is not None and auth_time == principal.signed_in_at
    if not (same_session or same_time) or (sid is not None and principal.sign_in_session not in {None, sid}) or (
            auth_time is not None and principal.signed_in_at not in {None, auth_time}):
        raise AuthenticationError("the ID token and the access token come from different sign-ins")


def verifier_from_environment() -> OIDCAccessTokenVerifier | None:
    oidc_settings = OIDCSettings.from_env()
    current = settings()
    if current.auth_mode not in {"local", "oidc"}:
        raise ValueError("SKILLPROOF_AUTH_MODE must be 'local' or 'oidc'")
    if current.production and current.auth_mode != "oidc":
        raise RuntimeError("production mode requires SKILLPROOF_AUTH_MODE=oidc")
    if current.auth_mode == "oidc" and oidc_settings is None:
        raise RuntimeError("OIDC mode requires issuer, audience, and JWKS URL settings")
    if current.auth_mode == "local" and oidc_settings is not None:
        raise RuntimeError("OIDC settings are present while auth mode is local; set SKILLPROOF_AUTH_MODE=oidc")
    return OIDCAccessTokenVerifier(oidc_settings) if oidc_settings is not None else None


_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


def browser_login_config() -> dict[str, Any]:
    """What the catalogue page needs to sign a person in with the authorization code flow and PKCE (public client).

    The page never holds a client secret: SKILLPROOF_OIDC_CLIENT_ID names a public client registered at the identity
    provider with the page's address as its redirect URI. Endpoints come from the issuer's discovery document unless
    SKILLPROOF_OIDC_AUTHORIZATION_URL / SKILLPROOF_OIDC_TOKEN_URL set them."""
    verifier_settings = OIDCSettings.from_env()
    if verifier_settings is None:
        return {"mode": "local"}
    current = settings()
    oidc = current.oidc
    client_id = oidc.client_id
    config: dict[str, Any] = {"mode": "oidc", "issuer": verifier_settings.issuer, "client_id": client_id or None,
                              "scope": oidc.scope,
                              "audience": verifier_settings.audience}
    authorization, token, end_session = oidc.authorization_url, oidc.token_url, oidc.end_session_url
    if not (authorization and token):
        discovered = _discover(verifier_settings.issuer)
        authorization = authorization or discovered.get("authorization_endpoint", "")
        token = token or discovered.get("token_endpoint", "")
        end_session = end_session or discovered.get("end_session_endpoint", "")
    for name, url in (("authorization_endpoint", authorization), ("token_endpoint", token), ("end_session_endpoint", end_session)):
        if url and urlparse(url).scheme not in {"https", "http"}:
            url = ""
        config[name] = url or None
    config["sign_in"] = bool(client_id and config["authorization_endpoint"] and config["token_endpoint"])
    # A person attests they wrote a version from a sign-in made for that: the page then adds this scope and asks the
    # provider for a fresh login (prompt=login), so the attestation comes from a new interactive sign-in.
    config["attest_scope"] = current.human_attestation_scope or None
    config["attest_once"] = current.human_attestation_once_per_sign_in
    config["attest_bound"] = current.human_attestation_bound
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
