# Production image for electrs-neurai.
#
# Build from the project root:
#
#   cd NIP/software/electrs-neurai
#   docker build -f Dockerfile -t electrs-neurai:latest .
#
# Runtime ports (mainnet defaults):
#   50001/tcp  Electrum RPC
#   4224/tcp   Prometheus metrics  (when --features metrics)
#
# Volumes (typical layout):
#   -v electrs-neurai-db:/var/lib/electrs-neurai
#   -v ~/.neurai:/home/electrs/.neurai:ro   # cookie file / daemon dir

# ─── build stage ──────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    RUST_VERSION=1.85.0 \
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
        libclang-dev \
        librocksdb-dev \
        libssl-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain ${RUST_VERSION} --profile minimal --no-modify-path

WORKDIR /workspace/electrs-neurai
COPY . .

RUN cargo build --release --locked --bin electrs-neurai && \
    strip target/release/electrs-neurai

# ─── runtime stage ────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS runtime

RUN apt-get update -qqy && \
    apt-get install -qqy --no-install-recommends \
        ca-certificates \
        librocksdb9.10 \
        libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --create-home --home-dir /home/electrs --shell /usr/sbin/nologin electrs && \
    mkdir -p /var/lib/electrs-neurai && chown electrs:electrs /var/lib/electrs-neurai

COPY --from=builder /workspace/electrs-neurai/target/release/electrs-neurai /usr/local/bin/electrs-neurai

USER electrs
WORKDIR /home/electrs
VOLUME ["/var/lib/electrs-neurai"]
EXPOSE 50001 60001 60401 4224

ENTRYPOINT ["/usr/local/bin/electrs-neurai"]
CMD ["--network", "neurai", "--db-dir", "/var/lib/electrs-neurai", "--electrum-rpc-addr", "0.0.0.0:50001"]
