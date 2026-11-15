#!/bin/sh
# Entrypoint of the electrs-neurai image.
#
# * DAEMON_RPC_USER / DAEMON_RPC_PASSWORD: written as `auth` to
#   ~/.electrs/config.toml (electrs reads `auth` only from a config file).
# * ELECTRS_* variables that are set but empty (options left blank in a .env
#   file) are removed, so electrs keeps its defaults for them.
# * DOMAIN: names the self-signed certificate created below and, unless
#   ELECTRS_REPORT_SERVICES is set, the services that `server.features`
#   reports, with the public ports PUBLIC_TCP_PORT, PUBLIC_SSL_PORT,
#   PUBLIC_WS_PORT and PUBLIC_WSS_PORT.
# * --ssl-certfile / --ssl-keyfile pointing at files that do not exist: a
#   self-signed certificate is created there. electrs reloads the certificate
#   when those files change (for instance, renewed by the letsencrypt service).
set -eu

for var in $(env | sed -n 's/^\(ELECTRS_[A-Z0-9_]*\)=$/\1/p'); do
    unset "$var"
done

if [ -n "${DAEMON_RPC_USER:-}" ] && [ -n "${DAEMON_RPC_PASSWORD:-}" ]; then
    toml_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
    mkdir -p "$HOME/.electrs"
    (
        umask 077
        printf 'auth = "%s:%s"\n' "$(toml_escape "$DAEMON_RPC_USER")" \
            "$(toml_escape "$DAEMON_RPC_PASSWORD")" > "$HOME/.electrs/config.toml"
    )
fi
unset DAEMON_RPC_USER DAEMON_RPC_PASSWORD

if [ -n "${DOMAIN:-}" ] && [ -z "${ELECTRS_REPORT_SERVICES:-}" ]; then
    services=""
    for entry in "tcp:${PUBLIC_TCP_PORT:-}" "ssl:${PUBLIC_SSL_PORT:-}" \
        "ws:${PUBLIC_WS_PORT:-}" "wss:${PUBLIC_WSS_PORT:-}"; do
        port=${entry#*:}
        if [ -n "$port" ]; then
            services="${services:+$services,}${entry%%:*}://$DOMAIN:$port"
        fi
    done
    if [ -n "$services" ]; then
        export ELECTRS_REPORT_SERVICES="$services"
    fi
fi

cert="${ELECTRS_SSL_CERTFILE:-}"
key="${ELECTRS_SSL_KEYFILE:-}"
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
    cn="${TLS_CN:-${ELECTRS_TLS_CN:-${DOMAIN:-electrs-neurai}}}"
    echo "[entrypoint] no TLS certificate at $cert — generating a self-signed one for $cn"
    mkdir -p "$(dirname "$cert")" "$(dirname "$key")"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$key" -out "$cert" \
        -subj "/CN=$cn" \
        -addext "subjectAltName=DNS:$cn,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
    chmod 600 "$key"
fi
unset ELECTRS_TLS_CN

exec /usr/local/bin/electrs-neurai "$@"
