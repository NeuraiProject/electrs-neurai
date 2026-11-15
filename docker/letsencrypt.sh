#!/bin/sh
# Let's Encrypt certificate for electrs-neurai: the `letsencrypt` service of the
# docker-compose stacks, run in the certbot/dns-cloudflare image.
#
# With DOMAIN set, it gets a certificate for it with the DNS-01 challenge
# through the Cloudflare API: certbot publishes a TXT record in the domain's
# zone with CLOUDFLARE_API_TOKEN, so no port needs to be open on this host.
# Before asking Let's Encrypt, it checks that DOMAIN belongs to a Cloudflare
# zone the token can see. Twice a day it renews the certificate if it is due,
# and copies it to the electrs TLS volume, where electrs-neurai picks it up
# without restarting.
#
# Without DOMAIN it does nothing, and electrs keeps its self-signed certificate.
set -eu

idle() {
    echo "[letsencrypt] $*"
    while :; do sleep 86400; done
}

if [ -z "${DOMAIN:-}" ]; then
    idle "DOMAIN is not set: electrs uses its self-signed certificate"
fi
if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
    idle "DOMAIN is $DOMAIN but CLOUDFLARE_API_TOKEN is not set: no certificate"
fi

tls_dir=/etc/electrs-tls
# The `electrs` user of the electrs-neurai image.
owner=${TLS_OWNER:-999:999}
credentials=/root/.secrets/cloudflare.ini
mkdir -p "$(dirname "$credentials")"
(
    umask 077
    printf 'dns_cloudflare_api_token = %s\n' "$CLOUDFLARE_API_TOKEN" > "$credentials"
)

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

# DOMAIN must be in a Cloudflare zone the token can see; warn when it does not
# point anywhere, or when it goes through Cloudflare's proxy (ssl:// does not).
check_domain() {
    python3 - <<'EOF'
import json, os, sys, urllib.error, urllib.request

api = os.environ.get("CLOUDFLARE_API_URL", "https://api.cloudflare.com/client/v4")
domain = os.environ["DOMAIN"].lower().rstrip(".")

def get(path):
    req = urllib.request.Request(api + path, headers={"Authorization": "Bearer " + os.environ["CLOUDFLARE_API_TOKEN"]})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            return json.load(e)
        except ValueError:
            return {"success": False, "errors": [{"message": f"HTTP {e.code}"}]}
    except OSError as e:
        return {"success": False, "errors": [{"message": str(e)}]}

def errors(reply):
    return "; ".join(e.get("message", "?") for e in reply.get("errors") or []) or "unknown error"

labels = domain.split(".")
zone = None
for i in range(len(labels) - 1):
    reply = get("/zones?name=" + ".".join(labels[i:]))
    if not reply.get("success"):
        print(f"[letsencrypt] the Cloudflare API refused the token: {errors(reply)}")
        sys.exit(1)
    if reply["result"]:
        zone = reply["result"][0]
        break
if zone is None:
    print(f"[letsencrypt] {domain} is not in any Cloudflare zone this token can see: "
          "check DOMAIN, and the zone the token is restricted to")
    sys.exit(1)

reply = get(f"/zones/{zone['id']}/dns_records?name={domain}")
records = [r for r in reply.get("result") or [] if r.get("type") in ("A", "AAAA", "CNAME")]
if not records:
    print(f"[letsencrypt] warning: {domain} has no A, AAAA or CNAME record in {zone['name']}: "
          "clients will not find this server")
for r in records:
    if r.get("proxied"):
        print(f"[letsencrypt] warning: the {r['type']} record of {domain} is proxied (orange cloud): "
              "ssl:// cannot go through Cloudflare's proxy, set it to DNS only")
print(f"[letsencrypt] {domain} is in the Cloudflare zone {zone['name']}")
EOF
}

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
    if ! check_domain; then
        echo "[letsencrypt] retrying in 1 hour"
        sleep 3600
        continue
    fi
    if certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$credentials" \
        --dns-cloudflare-propagation-seconds "${CLOUDFLARE_PROPAGATION_SECONDS:-30}" \
        --non-interactive --agree-tos --keep-until-expiring \
        --cert-name "$name" -d "$DOMAIN" "$@"; then
        install_certificate
        sleep 43200
    else
        echo "[letsencrypt] no certificate for $DOMAIN (see certbot's message above)." \
            "Retrying in 1 hour."
        sleep 3600
    fi
done
