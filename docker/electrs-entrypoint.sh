#!/bin/sh
# Entrypoint of the electrs-neurai images.
#
# When the command line enables TLS listeners (--electrum-ssl-addr /
# --electrum-wss-addr) with --ssl-certfile / --ssl-keyfile pointing at files
# that don't exist yet, a self-signed certificate is created there first.
# Mount your own cert.pem / key.pem (e.g. Let's Encrypt) to use them instead.
set -eu

cert=""
key=""
prev=""
for arg in "$@"; do
    case "$prev" in
        --ssl-certfile) cert="$arg" ;;
        --ssl-keyfile) key="$arg" ;;
    esac
    case "$arg" in
        --ssl-certfile=*) cert="${arg#*=}" ;;
        --ssl-keyfile=*) key="${arg#*=}" ;;
    esac
    prev="$arg"
done

if [ -n "$cert" ] && [ -n "$key" ] && { [ ! -f "$cert" ] || [ ! -f "$key" ]; }; then
    echo "[entrypoint] no TLS certificate at $cert — generating a self-signed one"
    mkdir -p "$(dirname "$cert")" "$(dirname "$key")"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$key" -out "$cert" \
        -subj "/CN=${ELECTRS_TLS_CN:-electrs-neurai}" \
        -addext "subjectAltName=DNS:${ELECTRS_TLS_CN:-electrs-neurai},DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
    chmod 600 "$key"
fi

exec /usr/local/bin/electrs-neurai "$@"
