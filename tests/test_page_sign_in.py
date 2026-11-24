"""Page sign-in: authorization code + PKCE against a local provider, and the API's verifier accepting the result."""
import base64
import hashlib
import importlib.util
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import jwt
from fastapi.testclient import TestClient

from skillproof.api.main import app as api_app
from skillproof.oidc import OIDCAccessTokenVerifier, OIDCSettings

ISSUER, REDIRECT = "http://127.0.0.1:8046", "http://127.0.0.1:8045/catalogue"
spec = importlib.util.spec_from_file_location("dev_oidc_provider", Path(__file__).parents[1] / "scripts" / "dev_oidc_provider.py")
provider_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider_module)


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def sign_in(provider, challenge, user="bob", role="approver", tenant="acme"):
    form = {"client_id": "skillproof-catalogue", "redirect_uri": REDIRECT, "state": "s1", "code_challenge": challenge,
            "user": user, "role": role, "tenant": tenant}
    response = provider.post("/authorize", data=form, follow_redirects=False)
    assert response.status_code == 303
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["s1"]
    return query["code"][0]


def exchange(provider, code, verifier):
    return provider.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                         "client_id": "skillproof-catalogue", "code_verifier": verifier})


class Keys:
    def __init__(self, jwks):
        self.keys = {k["kid"]: jwt.algorithms.RSAAlgorithm.from_jwk(k) for k in jwks["keys"]}

    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": self.keys[jwt.get_unverified_header(token)["kid"]]})()


def test_pkce_sign_in_gives_a_token_the_api_accepts():
    provider = TestClient(provider_module.create_app(ISSUER, [REDIRECT]))
    form = provider.get("/authorize", params={"client_id": "skillproof-catalogue", "redirect_uri": REDIRECT, "response_type": "code",
                                              "code_challenge": "x", "code_challenge_method": "S256", "state": "s1"})
    assert form.status_code == 200 and "Development sign-in" in form.text
    verifier, challenge = pkce()
    code = sign_in(provider, challenge)
    tokens = exchange(provider, code, verifier).json()
    settings = OIDCSettings(issuer=ISSUER, audience="skillproof-api", jwks_url=ISSUER + "/jwks")
    principal = OIDCAccessTokenVerifier(settings, signing_keys=Keys(provider.get("/jwks").json())).verify(tokens["access_token"])
    assert (principal.user_id, principal.role, principal.tenant_id) == ("bob", "approver", "acme")


def test_wrong_verifier_reused_code_and_foreign_redirect_are_refused():
    provider = TestClient(provider_module.create_app(ISSUER, [REDIRECT]))
    verifier, challenge = pkce()
    code = sign_in(provider, challenge)
    assert exchange(provider, code, "not-the-verifier").status_code == 400  # PKCE mismatch (and the code is spent)
    code = sign_in(provider, challenge)
    assert exchange(provider, code, verifier).status_code == 200
    assert exchange(provider, code, verifier).status_code == 400  # single use
    bad = provider.post("/authorize", data={"client_id": "skillproof-catalogue", "redirect_uri": "http://evil.test/cb", "state": "s",
                                            "code_challenge": challenge, "user": "x", "role": "viewer", "tenant": "t"}, follow_redirects=False)
    assert bad.status_code == 400


def test_login_config_is_public_and_local_without_oidc():
    client = TestClient(api_app)
    assert client.get("/api/v1/auth/config").json() == {"mode": "local"}


def test_plain_http_issuer_only_on_loopback_and_never_in_production(monkeypatch):
    import pytest

    OIDCSettings(issuer="http://127.0.0.1:8046", audience="a", jwks_url="http://127.0.0.1:8046/jwks")
    with pytest.raises(ValueError, match="HTTPS"):
        OIDCSettings(issuer="http://idp.example.org", audience="a", jwks_url="http://idp.example.org/jwks")
    monkeypatch.setenv("SKILLPROOF_ENV", "production")
    with pytest.raises(ValueError, match="HTTPS"):
        OIDCSettings(issuer="http://127.0.0.1:8046", audience="a", jwks_url="http://127.0.0.1:8046/jwks")


# Decision: when the server requires a scope (or one attestation per sign-in) for "human-written", the page learns it
# (this call crashed whenever OIDC was on before: a local variable hid the settings function),
# from the public login config and offers a separate sign-in for attesting; without those rules it offers nothing.
def test_login_config_tells_the_page_how_to_attest(monkeypatch):
    from skillproof.oidc import browser_login_config

    monkeypatch.setenv("SKILLPROOF_OIDC_ISSUER", "https://login.example.test/")
    monkeypatch.setenv("SKILLPROOF_OIDC_AUDIENCE", "skillproof-api")
    monkeypatch.setenv("SKILLPROOF_OIDC_JWKS_URL", "https://login.example.test/jwks")
    monkeypatch.setenv("SKILLPROOF_OIDC_CLIENT_ID", "skillproof-catalogue")
    monkeypatch.setenv("SKILLPROOF_OIDC_AUTHORIZATION_URL", "https://login.example.test/authorize")
    monkeypatch.setenv("SKILLPROOF_OIDC_TOKEN_URL", "https://login.example.test/token")
    plain = browser_login_config()
    assert plain["attest_scope"] is None and plain["attest_once"] is False
    monkeypatch.setenv("SKILLPROOF_HUMAN_ATTESTATION_SCOPE", "skillproof:attest")
    monkeypatch.setenv("SKILLPROOF_HUMAN_ATTESTATION_ONCE", "true")
    strict = browser_login_config()
    assert strict["attest_scope"] == "skillproof:attest" and strict["attest_once"] is True
    page = (Path(__file__).parents[1] / "src" / "skillproof" / "web" / "catalogue.html").read_text(encoding="utf-8")
    assert 'url.searchParams.set("prompt", "login")' in page and "a.attest_scope" in page
