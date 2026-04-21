#!/bin/sh
set -eu

CERT_DIR=/etc/electrs-tls

# Generate a self-signed certificate on first start if none was mounted.
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    echo "[entrypoint] no certificate at $CERT_DIR — generating self-signed"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -subj "/CN=electrs-neurai" \
        -addext "subjectAltName=DNS:localhost,DNS:electrs,IP:127.0.0.1" \
        >/dev/null 2>&1
    chmod 600 "$CERT_DIR/key.pem"
fi

# WS↔TCP bridge: plaintext WebSocket on 127.0.0.1:50003 → TCP electrs:50001.
# nginx terminates TLS on :50004 and proxies the WS upgrade here.
echo "[entrypoint] starting websockify (127.0.0.1:50003 → electrs:50001)"
websockify 127.0.0.1:50003 electrs:50001 &

echo "[entrypoint] starting nginx (ssl :50002, wss :50004)"
exec nginx -g 'daemon off;'
