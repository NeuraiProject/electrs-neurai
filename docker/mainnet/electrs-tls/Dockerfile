# TLS gateway for electrs-neurai (mainnet).
#
#   ssl://:50002  ──┐ nginx (stream, TLS termination) ────────────► electrs:50001
#   wss://:50004  ──┘ nginx (http, TLS + WS upgrade) ──► websockify ──► electrs:50001
#
# A self-signed certificate is generated on first start if none is mounted at
# /etc/electrs-tls/. Mount your own cert.pem / key.pem there for production.

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qqy && \
    apt-get install -qqy --no-install-recommends \
        ca-certificates \
        nginx-full \
        openssl \
        websockify && \
    rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/etc/electrs-tls"]
EXPOSE 50002 50004

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
