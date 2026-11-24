#!/bin/bash
# Configure a TEST realm for SkillProof in a local Keycloak (verified with Keycloak 26.8.2):
#   bash scripts/keycloak_realm.sh ADMIN_PASSWORD USER_PASSWORD MACHINE_SECRET
# Creates realm "skillproof"; a client scope putting aud=skillproof-api, skillproof_role and tenant_id (user
# attributes), auth_time and amr into access tokens; the public client skillproof-catalogue (people, PKCE; direct grants
# on for scripted tests only, turn them off in production); the confidential machine client sync-host-1 (client
# credentials, role reporter); users alice, erin (evaluator), bob (approver), sync@test-machine (reporter).
# Keycloak signs access tokens with a JWT header: set SKILLPROOF_OIDC_ACCEPTED_TYPES=at+jwt,application/at+jwt,JWT.
# amr stays empty until the login flow's authenticators are given reference values in Keycloak.
set -euo pipefail
ADMIN_PASSWORD="$1"; USER_PASSWORD="$2"; MACHINE_SECRET="$3"
K=/opt/keycloak/bin/kcadm.sh
$K config credentials --server http://127.0.0.1:8180 --realm master --user admin --password "$ADMIN_PASSWORD" >/dev/null
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
if $K create client-scopes/$SCOPE/protocol-mappers/models -r skillproof -s name=amr -s protocol=openid-connect \
  -s protocolMapper=oidc-amr-mapper -s 'config."access.token.claim"=true' >/dev/null 2>/tmp/amr.err; then
  echo "amr mapper added"
else
  echo "amr mapper not available: $(head -c 200 /tmp/amr.err)"
fi
