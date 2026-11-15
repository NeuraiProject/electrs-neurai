#!/bin/sh
# Let's Encrypt certificate for electrs-neurai: the `letsencrypt` service of the
# docker-compose stacks, run in the certbot/certbot image.
#
# With DOMAIN set, it gets a certificate for it with the HTTP-01 challenge,
# which proves control of the domain: DOMAIN must resolve to this host, and
# port 80 of this host must be reachable from the internet while the challenge
# runs. No DNS provider API is needed. Twice a day it renews the certificate if
# it is due, and copies it to the electrs TLS volume, where electrs-neurai picks
# it up without restarting.
#
# Without DOMAIN it does nothing, and electrs keeps its self-signed certificate.
set -eu

if [ -z "${DOMAIN:-}" ]; then
    echo "[letsencrypt] DOMAIN is not set: electrs uses its self-signed certificate"
    while :; do sleep 86400; done
fi

tls_dir=/etc/electrs-tls
# The `electrs` user of the electrs-neurai image.
owner=${TLS_OWNER:-999:999}
port=${ACME_HTTP_PORT:-80}

name=$DOMAIN
set --
if [ "${LETSENCRYPT_STAGING:-0}" = 1 ]; then
    # Staging certificates are not trusted by clients; kept apart from the real one.
    name="$DOMAIN-staging"
    set -- --test-cert
fi
if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
    set -- "$@" --email "$LETSENCRYPT_EMAIL"
else
    set -- "$@" --register-unsafely-without-email
fi

install_certificate() {
    live=/etc/letsencrypt/live/$name
    if cmp -s "$live/fullchain.pem" "$tls_dir/cert.pem" &&
        cmp -s "$live/privkey.pem" "$tls_dir/key.pem"; then
        return 0
    fi
    # Copy next to the destination, then rename: electrs never reads half a file.
    cp "$live/privkey.pem" "$tls_dir/.key.pem.new"
    cp "$live/fullchain.pem" "$tls_dir/.cert.pem.new"
    chown "$owner" "$tls_dir/.key.pem.new" "$tls_dir/.cert.pem.new"
    chmod 600 "$tls_dir/.key.pem.new"
    chmod 644 "$tls_dir/.cert.pem.new"
    mv -f "$tls_dir/.key.pem.new" "$tls_dir/key.pem"
    mv -f "$tls_dir/.cert.pem.new" "$tls_dir/cert.pem"
    echo "[letsencrypt] installed the certificate of $DOMAIN for electrs-neurai"
}

while :; do
    if certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring \
        --preferred-challenges http --http-01-port "$port" \
        --cert-name "$name" -d "$DOMAIN" "$@"; then
        install_certificate
        sleep 43200
    else
        echo "[letsencrypt] no certificate for $DOMAIN: it must resolve to this host" \
            "and port $port must be reachable from the internet. Retrying in 1 hour."
        sleep 3600
    fi
done
