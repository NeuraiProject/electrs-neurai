# Build electrs-neurai from a GitHub checkout.
#
# Override the source by passing build args:
#   docker build --build-arg REPO_REF=v1.2.3 -t electrs-neurai .

# ─── build stage ──────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS builder

ARG REPO_URL=https://github.com/NeuraiProject/electrs-neurai.git
ARG REPO_REF=master

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    RUST_VERSION=1.88.0 \
    ROCKSDB_INCLUDE_DIR=/usr/include \
    ROCKSDB_LIB_DIR=/usr/lib

RUN apt-get update -qqy && \
    apt-get install -qqy --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        g++ \
        git \
        libclang-dev \
        librocksdb-dev \
        libssl-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal --no-modify-path

WORKDIR /workspace

RUN git clone --branch ${REPO_REF} --single-branch ${REPO_URL} electrs-neurai

WORKDIR /workspace/electrs-neurai

RUN cargo build --release --locked --bin electrs && \
    strip target/release/electrs

# ─── runtime stage ────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS runtime

RUN apt-get update -qqy && \
    apt-get install -qqy --no-install-recommends \
        ca-certificates \
        librocksdb9.10 \
        libssl3 \
        openssl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --create-home --home-dir /home/electrs --shell /usr/sbin/nologin electrs && \
    mkdir -p /var/lib/electrs-neurai /etc/electrs-tls && \
    chown electrs:electrs /var/lib/electrs-neurai /etc/electrs-tls

COPY --from=builder /workspace/electrs-neurai/target/release/electrs /usr/local/bin/electrs-neurai
COPY --from=builder /workspace/electrs-neurai/docker/electrs-entrypoint.sh /usr/local/bin/electrs-entrypoint.sh

USER electrs
WORKDIR /home/electrs
VOLUME ["/var/lib/electrs-neurai", "/etc/electrs-tls"]
# 50001 tcp, 50002 ssl, 50004 wss (mainnet); 60001 testnet; 60401 regtest; 4224 metrics
EXPOSE 50001 50002 50004 60001 60401 4224

ENTRYPOINT ["/usr/local/bin/electrs-entrypoint.sh"]
CMD ["--network", "neurai", "--db-dir", "/var/lib/electrs-neurai", "--electrum-rpc-addr", "0.0.0.0:50001"]
