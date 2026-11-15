#!/bin/sh
# Entrypoint wrapper for the neuraiproject/neurai-node image.
#
# The image writes /data/neurai.conf from its NEURAI_* variables only on the
# first start. This keeps rpcuser / rpcpassword in step with the .env file on
# every start (electrs uses the same credentials), then runs the image's own
# entrypoint. Other settings still apply only on the first start: change them
# in neurai.conf inside the volume.
set -eu

conf=/data/neurai.conf

if [ -f "$conf" ] && [ -n "${NEURAI_RPC_USER:-}" ] && [ -n "${NEURAI_RPC_PASSWORD:-}" ]; then
    tmp="$conf.new"
    (
        umask 077
        grep -v -E '^[[:space:]]*(rpcuser|rpcpassword)[[:space:]]*=' "$conf" > "$tmp" || true
        printf 'rpcuser=%s\nrpcpassword=%s\n' "$NEURAI_RPC_USER" "$NEURAI_RPC_PASSWORD" >> "$tmp"
    )
    chown neurai:neurai "$tmp"
    mv -f "$tmp" "$conf"
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"
