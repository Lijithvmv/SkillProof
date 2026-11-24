#!/bin/bash
# Keycloak in production mode: HTTPS only, PostgreSQL, strict hostname. Args: admin password, database password.
set -euo pipefail
PGV=$(ls /etc/postgresql | sort -n | tail -1)
pg_ctlcluster "$PGV" main start 2>/dev/null || true
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD="$1"
export KC_DB_PASSWORD="$2"
TLS=/opt/keycloak/conf/tls
exec /opt/keycloak/bin/kc.sh start --optimized \
  --db-url=jdbc:postgresql://127.0.0.1:5432/keycloak --db-username=keycloak \
  --https-certificate-file=$TLS/server.crt --https-certificate-key-file=$TLS/server.key \
  --https-port=8443 --http-enabled=false --http-host=0.0.0.0 \
  --hostname=https://127.0.0.1:8443
