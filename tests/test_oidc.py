import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from skillproof.api.main import app
from skillproof.oidc import AuthenticationError, OIDCAccessTokenVerifier, OIDCSettings, verifier_from_environment


PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeKeys:
    def get_signing_key_from_jwt(self, token):
        return SimpleNamespace(key=PRIVATE_KEY.public_key())


def verifier():
    return OIDCAccessTokenVerifier(
        OIDCSettings(
            issuer="https://login.example.test/",
            audience="skillproof-api",
            jwks_url="https://login.example.test/.well-known/jwks.json",
            leeway_seconds=0,
        ),
        signing_keys=FakeKeys(),
    )


def make_token(**changes):
    now = int(time.time())
    claims = {
        "iss": "https://login.example.test/",
        "aud": "skillproof-api",
        "exp": now + 120,
        "iat": now,
        "sub": "user-123",
        "jti": "token-123",
        "client_id": "skillproof-web",
        "tenant_id": "tenant-abc",
        "skillproof_role": "evaluator",
    }
    claims.update(changes)
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"typ": "at+jwt", "kid": "key-1"})


def test_verifier_checks_signature_and_maps_tenant_role():
    principal = verifier().verify(make_token())
    assert principal.user_id == "user-123"
    assert principal.tenant_id == "tenant-abc"
    assert principal.role == "evaluator"


@pytest.mark.parametrize("changes", [
    {"iss": "https://other.example.test/"},
    {"aud": "different-api"},
    {"exp": int(time.time()) - 60},
    {"skillproof_role": "superuser"},
    {"tenant_id": ""},
    {"jti": None},
])
def test_verifier_rejects_invalid_claims(changes):
    with pytest.raises(AuthenticationError):
        verifier().verify(make_token(**changes))


def test_verifier_rejects_id_token_type_and_bad_signature():
    id_token = jwt.encode(
        {"iss": "https://login.example.test/", "aud": "skillproof-api", "exp": int(time.time()) + 60, "iat": int(time.time()), "sub": "u", "jti": "j", "client_id": "c", "tenant_id": "t", "skillproof_role": "viewer"},
        PRIVATE_KEY, algorithm="RS256", headers={"typ": "JWT", "kid": "key-1"},
    )
    with pytest.raises(AuthenticationError, match="access-token type"):
        verifier().verify(id_token)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad_sig = jwt.encode({"iss": "https://login.example.test/"}, other_key, algorithm="RS256", headers={"typ": "at+jwt", "kid": "key-1"})
    with pytest.raises(AuthenticationError):
        verifier().verify(bad_sig)


def test_oidc_settings_require_https_and_production_requires_oidc(monkeypatch):
    with pytest.raises(ValueError, match="HTTPS"):
        OIDCSettings(issuer="http://login.example.test", audience="api", jwks_url="https://login.example.test/keys")
    monkeypatch.setenv("SKILLPROOF_ENV", "production")
    monkeypatch.setenv("SKILLPROOF_AUTH_MODE", "local")
    monkeypatch.delenv("SKILLPROOF_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("SKILLPROOF_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("SKILLPROOF_OIDC_JWKS_URL", raising=False)
    with pytest.raises(RuntimeError, match="production mode requires"):
        verifier_from_environment()


def test_api_requires_bearer_and_evaluator_role_when_oidc_enabled(monkeypatch):
    monkeypatch.setattr(app.state, "oidc_verifier", verifier())
    client = TestClient(app)
    payload = {"files": {"demo/SKILL.md": "---\nname: demo\ndescription: demo skill\n---\nCreate a demo.\n"}}
    assert client.post("/api/v1/skills/analyze", json=payload).status_code == 401
    assert client.get("/health").status_code == 200

    viewer = make_token(skillproof_role="viewer")
    assert client.post("/api/v1/skills/analyze", json=payload, headers={"Authorization": f"Bearer {viewer}"}).status_code == 403

    evaluator = make_token(skillproof_role="evaluator")
    response = client.post("/api/v1/skills/analyze", json=payload, headers={"Authorization": f"Bearer {evaluator}"})
    assert response.status_code == 200
    monkeypatch.setattr(app.state, "oidc_verifier", None)

