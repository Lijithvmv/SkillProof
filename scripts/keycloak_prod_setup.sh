#!/bin/bash
# Production-mode Keycloak for SkillProof tests: PostgreSQL database, TLS with a local test CA, strict hostname.
# Run once as root in the skillproof-idp distro. Arg 1: database password (test value).
set -euo pipefail
DB_PASSWORD="$1"
export DEBIAN_FRONTEND=noninteractive
if ! command -v pg_ctlcluster >/dev/null; then
  apt-get update -qq && apt-get install -y -qq postgresql >/dev/null
fi
PGV=$(ls /etc/postgresql | sort -n | tail -1)
pg_ctlcluster "$PGV" main start || true
su postgres -c "psql -tAc \"select 1 from pg_roles where rolname='keycloak'\"" | grep -q 1 || \
  su postgres -c "psql -c \"create role keycloak login password '$DB_PASSWORD'\"" >/dev/null
su postgres -c "psql -tAc \"select 1 from pg_database where datname='keycloak'\"" | grep -q 1 || \
  su postgres -c "createdb -O keycloak keycloak"
echo "postgres $PGV: database keycloak ready"

TLS=/opt/keycloak/conf/tls
mkdir -p "$TLS" && cd "$TLS"
if [ ! -f server.crt ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 30 -nodes -keyout ca.key -out ca.crt -subj "/CN=SkillProof test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:3072 -sha256 -nodes -keyout server.key -out server.csr -subj "/CN=127.0.0.1" 2>/dev/null
  printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\n" > san.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -sha256 -extfile san.ext -out server.crt 2>/dev/null
  chmod 600 ca.key server.key
  rm -f truststore.p12
  keytool -importcert -noprompt -alias skillproof-test-ca -file ca.crt -keystore truststore.p12 -storetype PKCS12 -storepass changeit >/dev/null
fi
echo "TLS: server certificate for 127.0.0.1 signed by a local test CA (30 days)"

/opt/keycloak/bin/kc.sh build --db=postgres --health-enabled=true >/dev/null
echo "keycloak built for postgres"
