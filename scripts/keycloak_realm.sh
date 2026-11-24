#!/bin/bash
# Configure a TEST realm for SkillProof in a local Keycloak (verified with Keycloak 26.8.2):
#   bash scripts/keycloak_realm.sh ADMIN_PASSWORD USER_PASSWORD MACHINE_SECRET
# Creates realm "skillproof"; a client scope putting aud=skillproof-api, skillproof_role and tenant_id (user
# attributes), auth_time and amr into access tokens; the public client skillproof-catalogue (people, PKCE; direct grants
# on for scripted tests only, turn them off in production); the confidential machine client sync-host-1 (client
# credentials, role reporter); users alice, erin (evaluator), bob (approver), sync@test-machine (reporter).
# Keycloak signs access tokens with a JWT header: set SKILLPROOF_OIDC_ACCEPTED_TYPES=at+jwt,application/at+jwt,JWT.
# Sign-in methods (amr): the realm's browser flow is a copy whose password step reports "pwd" and whose one-time-code
# step reports "otp". erin must set up a one-time code (TOTP) at her first sign-in; alice signs in with a password only.
# KC_SERVER (default http://127.0.0.1:8180) and KC_TRUSTSTORE (a PKCS12 file holding the server's CA, password in
# KC_TRUSTPASS, default changeit) point the admin client at an HTTPS server.
set -euo pipefail
ADMIN_PASSWORD="$1"; USER_PASSWORD="$2"; MACHINE_SECRET="$3"
SERVER="${KC_SERVER:-http://127.0.0.1:8180}"
K=/opt/keycloak/bin/kcadm.sh
if [ -n "${KC_TRUSTSTORE:-}" ]; then $K config truststore --trustpass "${KC_TRUSTPASS:-changeit}" "$KC_TRUSTSTORE" >/dev/null; fi
$K config credentials --server "$SERVER" --realm master --user admin --password "$ADMIN_PASSWORD" >/dev/null
$K create realms -s realm=skillproof -s enabled=true >/dev/null
echo "realm created"

# Custom user attributes (skillproof_role, tenant_id) must be allowed by the user profile.
$K get users/profile -r skillproof > /tmp/profile.json
python3 - <<'PY'
import json
p = json.load(open("/tmp/profile.json"))
p["unmanagedAttributePolicy"] = "ENABLED"
json.dump(p, open("/tmp/profile.json", "w"))
PY
$K update users/profile -r skillproof -f /tmp/profile.json >/dev/null
echo "user profile: unmanaged attributes enabled"

# One client scope carrying what SkillProof needs in every access token.
SCOPE=$($K create client-scopes -r skillproof -s name=skillproof -s protocol=openid-connect -i)
$K create client-scopes/$SCOPE/protocol-mappers/models -r skillproof -s name=audience -s protocol=openid-connect \
  -s protocolMapper=oidc-audience-mapper -s 'config."included.custom.audience"=skillproof-api' \
  -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' >/dev/null
for claim in skillproof_role tenant_id; do
  $K create client-scopes/$SCOPE/protocol-mappers/models -r skillproof -s name=$claim -s protocol=openid-connect \
    -s protocolMapper=oidc-usermodel-attribute-mapper -s "config.\"user.attribute\"=$claim" -s "config.\"claim.name\"=$claim" \
    -s 'config."jsonType.label"=String' -s 'config."access.token.claim"=true' -s 'config."id.token.claim"=true' >/dev/null
done
echo "client scope with audience, skillproof_role and tenant_id"

# People sign in through a public client with PKCE (direct grants on only for this scripted test).
CAT=$($K create clients -r skillproof -s clientId=skillproof-catalogue -s publicClient=true -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=true -s 'redirectUris=["http://127.0.0.1:8798/catalogue"]' \
  -s 'attributes."pkce.code.challenge.method"=S256' -i)
$K update clients/$CAT/default-client-scopes/$SCOPE -r skillproof >/dev/null

# A machine signs in as itself (client credentials).
MACHINE=$($K create clients -r skillproof -s clientId=sync-host-1 -s publicClient=false -s serviceAccountsEnabled=true \
  -s standardFlowEnabled=false -s directAccessGrantsEnabled=false -s secret="$MACHINE_SECRET" -i)
$K update clients/$MACHINE/default-client-scopes/$SCOPE -r skillproof >/dev/null
SA=$($K get clients/$MACHINE/service-account-user -r skillproof --fields id --format csv --noquotes)
$K update users/$SA -r skillproof -s 'attributes.skillproof_role=["reporter"]' -s 'attributes.tenant_id=["local"]' >/dev/null
echo "clients: skillproof-catalogue (people), sync-host-1 (machine, reporter)"

for spec in alice:evaluator erin:evaluator bob:approver sync@test-machine:reporter; do
  name=${spec%%:*}; role=${spec##*:}
  id=$($K create users -r skillproof -s username="$name" -s enabled=true -s email="${name//@/.}@example.test" -s emailVerified=true \
    -s firstName="$name" -s lastName=test -s "attributes.skillproof_role=[\"$role\"]" -s 'attributes.tenant_id=["local"]' -i)
  $K set-password -r skillproof --userid "$id" --new-password "$USER_PASSWORD" >/dev/null
  echo "user $name ($role)"
done

# The sign-in time (auth_time) and methods (amr) in access tokens.
# (same client scope as above)
$K create client-scopes/$SCOPE/protocol-mappers/models -r skillproof -s name=auth_time -s protocol=openid-connect \
  -s protocolMapper=oidc-usersessionmodel-note-mapper -s 'config."user.session.note"=AUTH_TIME' \
  -s 'config."claim.name"=auth_time' -s 'config."jsonType.label"=long' -s 'config."access.token.claim"=true' >/dev/null
echo "auth_time mapper added"
$K create client-scopes/$SCOPE/protocol-mappers/models -r skillproof -s name=amr -s protocol=openid-connect \
  -s protocolMapper=oidc-amr-mapper -s 'config."access.token.claim"=true' >/dev/null
echo "amr mapper added"

# Give the browser flow's steps their method references, so amr says how the person signed in. Each reference needs a
# max age (seconds after that step): without one, Keycloak drops it from amr almost at once (AmrUtils.isAmrValid).
$K create authentication/flows/browser/copy -r skillproof -s newName=skillproof-browser >/dev/null
$K get authentication/flows/skillproof-browser/executions -r skillproof > /tmp/executions.json
for pair in auth-username-password-form:pwd auth-otp-form:otp; do
  provider=${pair%%:*}; ref=${pair##*:}
  exec_id=$(python3 -c "import json,sys; print(next(e['id'] for e in json.load(open('/tmp/executions.json')) if e.get('providerId') == sys.argv[1]))" "$provider")
  $K create authentication/executions/$exec_id/config -r skillproof -s alias=amr-$ref -s "config.\"default.reference.value\"=$ref" -s 'config."default.reference.maxAge"=3600' >/dev/null
  echo "sign-in step $provider reports amr $ref"
done
$K update realms/skillproof -s browserFlow=skillproof-browser >/dev/null
ERIN=$($K get users -r skillproof -q username=erin -q exact=true --fields id --format csv --noquotes)
$K update users/$ERIN -r skillproof -s 'requiredActions=["CONFIGURE_TOTP"]' >/dev/null
echo "erin sets up a one-time code at her first sign-in"
