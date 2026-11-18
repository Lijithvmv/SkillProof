"""A local OpenID Connect provider for trying and testing the catalogue's sign-in. Development only.

    python scripts/dev_oidc_provider.py --port 8046 --redirect http://127.0.0.1:8045/catalogue

Signs access tokens with a key generated at start (RS256, typ at+jwt), serves discovery and JWKS, shows a form to pick
user / role / tenant (so the two-person rule can be exercised with real tokens), and checks PKCE (S256) when a code is
exchanged. Codes are single-use and expire after 60 seconds. It listens on 127.0.0.1 and accepts only the redirect
addresses it is given. Point the API at it with:

    SKILLPROOF_AUTH_MODE=oidc SKILLPROOF_OIDC_ISSUER=http://127.0.0.1:8046 SKILLPROOF_OIDC_AUDIENCE=skillproof-api
    SKILLPROOF_OIDC_JWKS_URL=http://127.0.0.1:8046/jwks SKILLPROOF_OIDC_CLIENT_ID=skillproof-catalogue
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import secrets
import time
import uuid
from urllib.parse import urlencode, urlparse

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

ROLES = ("tenant_admin", "evaluator", "approver", "viewer")


def create_app(issuer: str, redirects: list[str], *, audience: str = "skillproof-api", client_id: str = "skillproof-catalogue") -> FastAPI:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "dev-" + secrets.token_hex(4)
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True) | {"kid": kid, "use": "sig", "alg": "RS256"}
    codes: dict[str, dict] = {}
    app = FastAPI(title="SkillProof development OIDC provider")
    origins = sorted({f"{urlparse(r).scheme}://{urlparse(r).netloc}" for r in redirects})
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["POST"], allow_headers=["Content-Type"])

    @app.get("/.well-known/openid-configuration")
    def discovery() -> dict:
        return {"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
                "jwks_uri": issuer + "/jwks", "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code"], "token_endpoint_auth_methods_supported": ["none"]}

    @app.get("/jwks")
    def jwks() -> dict:
        return {"keys": [public_jwk]}

    def check_request(request_client: str, redirect_uri: str) -> None:
        if request_client != client_id:
            raise HTTPException(400, "unknown client_id")
        if redirect_uri not in redirects:
            raise HTTPException(400, "redirect_uri is not registered for this client")

    @app.get("/authorize", response_class=HTMLResponse)
    def authorize_form(request: Request) -> str:
        q = request.query_params
        check_request(q.get("client_id", ""), q.get("redirect_uri", ""))
        if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            raise HTTPException(400, "only response_type=code with PKCE S256 is supported")
        hidden = "".join(f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">' for k, v in q.items())
        options = "".join(f"<option>{r}</option>" for r in ROLES)
        return (f"<!doctype html><meta charset=utf-8><title>Development sign-in</title><body style='font:14px system-ui;margin:2em'>"
                f"<h1>Development sign-in</h1><p>Local provider for testing. Pick who you are.</p><form method=post action=/authorize>{hidden}"
                f"<p><label>User <input name=user value=alice></label></p><p><label>Role <select name=role>{options}</select></label></p>"
                f"<p><label>Tenant <input name=tenant value=acme></label></p><button>Sign in</button></form>")

    @app.post("/authorize")
    def authorize(client_id_: str = Form(alias="client_id"), redirect_uri: str = Form(), state: str = Form(""),
                  code_challenge: str = Form(), user: str = Form(), role: str = Form(), tenant: str = Form(),
                  nonce: str = Form("")) -> RedirectResponse:
        check_request(client_id_, redirect_uri)
        if role not in ROLES or not user.strip() or not tenant.strip():
            raise HTTPException(400, "user, role and tenant are required")
        code = secrets.token_urlsafe(32)
        codes[code] = {"client_id": client_id_, "redirect_uri": redirect_uri, "challenge": code_challenge, "sub": user.strip(),
                       "role": role, "tenant": tenant.strip(), "nonce": nonce, "expires": time.time() + 60}
        return RedirectResponse(redirect_uri + "?" + urlencode({"code": code, "state": state}), status_code=303)

    @app.post("/token")
    def token(grant_type: str = Form(), code: str = Form(), redirect_uri: str = Form(), client_id_: str = Form(alias="client_id"),
              code_verifier: str = Form()) -> JSONResponse:
        grant = codes.pop(code, None)  # single use
        error = None
        if grant_type != "authorization_code" or grant is None or grant["expires"] < time.time():
            error = "invalid_grant"
        elif grant["client_id"] != client_id_ or grant["redirect_uri"] != redirect_uri:
            error = "invalid_grant"
        else:
            digest = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
            if not secrets.compare_digest(digest, grant["challenge"]):
                error = "invalid_grant"
        if error:
            return JSONResponse({"error": error, "error_description": "code, client, redirect or PKCE verifier does not match"}, status_code=400)
        now = int(time.time())
        claims = {"iss": issuer, "aud": audience, "sub": grant["sub"], "iat": now, "exp": now + 900, "jti": str(uuid.uuid4()),
                  "client_id": client_id_, "skillproof_role": grant["role"], "tenant_id": grant["tenant"]}
        access = jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid, "typ": "at+jwt"})
        return JSONResponse({"access_token": access, "token_type": "Bearer", "expires_in": 900},
                            headers={"Cache-Control": "no-store"})

    return app


if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=8046)
    parser.add_argument("--redirect", action="append", required=True, help="Allowed redirect URI; repeat.")
    args = parser.parse_args()
    uvicorn.run(create_app(f"http://127.0.0.1:{args.port}", args.redirect), host="127.0.0.1", port=args.port)
