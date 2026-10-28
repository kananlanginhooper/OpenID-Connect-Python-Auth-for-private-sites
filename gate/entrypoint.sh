#!/bin/bash
# Reads the client secret the provider made (shared volume) and keeps a cookie-encryption passphrase in /gate-data,
# then runs Apache in the foreground. Apache fills ${VARS} in gate.conf from this environment.
set -euo pipefail
secret_file=${OIDC_CLIENT_SECRET_FILE:-/shared/${OIDC_CLIENT_ID}.secret}
for _ in $(seq 60); do [ -s "$secret_file" ] && break; sleep 1; done
[ -s "$secret_file" ] || { echo "no client secret at $secret_file (is the provider up, and is ${OIDC_CLIENT_ID} in its clients file?)" >&2; exit 1; }
export OIDC_CLIENT_SECRET=$(tr -d '\n' < "$secret_file")
mkdir -p /gate-data
[ -s /gate-data/passphrase ] || (umask 077; head -c 32 /dev/urandom | base64 > /gate-data/passphrase)
export OIDC_CRYPTO_PASSPHRASE=$(cat /gate-data/passphrase)
set +u; source /etc/apache2/envvars; set -u
mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
exec apache2 -D FOREGROUND
