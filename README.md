# electrs-neurai — Electrum Server for Neurai

Electrum server for the Neurai (XNA) blockchain, adapted from
[romanz/electrs](https://github.com/romanz/electrs). Supports Neurai's
variable-size KAWPOW block headers, asset opcodes (`OP_XNA_ASSET`), legacy
base58check and bech32/bech32m address formats, mainnet / testnet / regtest,
and the standard Electrum v1.4 protocol plus `blockchain.address.*` and
`blockchain.asset.*` extensions.

A private, self-hosted Electrum server lets wallets track balances,
transaction history, and asset holdings without disclosing addresses to
third-party servers.

See [`NIP/software/ELECTRS_MIGRATION.md`](../ELECTRS_MIGRATION.md) for a
phase-by-phase log of the adaptation from upstream electrs.


## Features

 * Electrum protocol [v1.4](https://electrum-protocol.readthedocs.io/)
 * Neurai-native block header decoder — handles both 80-byte pre-KAWPOW and
   120-byte post-KAWPOW headers on mainnet, and the 80-byte SHA256d layout
   on testnet / regtest.
 * Scripthash index over every output, plus dedicated RocksDB column families
   for asset metadata, asset history and per-scripthash asset funding.
 * Mempool tracker with per-scripthash and per-asset-name lookups.
 * Neurai-aware address codec (base58check prefixes 53 / 127 → `N…` / `t…`,
   bech32/bech32m HRPs `nq` / `tnq` / `rnq`).
 * `blockchain.address.get_scripthash` and `blockchain.asset.*` RPC extensions —
   see [doc/neurai-rpc.md](doc/neurai-rpc.md).
 * Single RocksDB database, crash-safe, low index storage overhead.
 * Low CPU and memory usage after the initial sync.
 * `txindex` is **not** required on the Neurai daemon.

## Quick start with Docker

The repository ships with a production multi-stage `Dockerfile` and a
regtest integration stack in `regtest/`.

```bash
# Build the server image from the project root.
cd NIP/software/electrs-neurai
docker build -f Dockerfile -t electrs-neurai:latest .

# Point electrs at a running Neurai daemon:
docker run --rm -it \
    -v "$HOME/.neurai":/home/electrs/.neurai:ro \
    -v electrs-neurai-db:/var/lib/electrs-neurai \
    -p 50001:50001 \
    electrs-neurai:latest \
        --network=neurai \
        --daemon-rpc-addr=host.docker.internal:19001 \
        --daemon-p2p-addr=host.docker.internal:19000 \
        --electrum-rpc-addr=0.0.0.0:50001
```

## Building from source

Requirements:
- Rust 1.85.0 (pinned; see `rust-toolchain` expectations in the Dockerfiles)
- `cmake`, `clang`, `libclang-dev`, `librocksdb-dev`, `libssl-dev`, `pkg-config`
- The vendored `hasherkawpow-sys` crate included at `./hasherkawpow-sys`

```bash
cd NIP/software/electrs-neurai
cargo build --release --locked
./target/release/electrs-neurai --network=neurai ...
```

The development container `Dockerfile.dev` sets up the toolchain and bind-mount
layout for iterative work; see its header comment for usage.

## Configuration

Configuration is driven by `configure_me` via CLI flags, environment
variables (prefix `ELECTRS_`) and a TOML config file. A template lives in
[doc/config_example.toml](doc/config_example.toml). The authoritative option
list is [internal/config_specification.toml](internal/config_specification.toml);
run `electrs-neurai --help` for the generated reference.

Per-network defaults:

| Network  | Electrum RPC | Daemon RPC  | Daemon P2P  | DB subdir   | Address prefixes   |
|----------|--------------|-------------|-------------|-------------|--------------------|
| neurai   | `:50001`     | `:19001`    | `:19000`    | `neurai`    | `N…` / `nq1…`      |
| testnet  | `:60001`     | `:19101`    | `:19100`    | `testnet`   | `t…` / `tnq1…`     |
| regtest  | `:60401`     | `:19201`    | `:19200`    | `regtest`   | `t…` / `rnq1…`     |

Testnet and regtest use an epoch-based genesis block that is fetched from the
Neurai daemon over RPC at startup — you do not need to hardcode it in config.

## Tests

```bash
# Unit + crate-internal integration tests (no daemon required):
cargo test --locked

# End-to-end against a live regtest daemon (requires a Neurai daemon image
# that supports -regtest mode):
cd regtest
docker compose up --build -d
./e2e.sh
docker compose down -v
```

See [regtest/README.md](regtest/README.md) for prerequisites and the
step-by-step breakdown.

## Migration history

The adaptation from upstream `romanz/electrs` is tracked phase-by-phase in
[`../ELECTRS_MIGRATION.md`](../ELECTRS_MIGRATION.md).

## Contributing

Contributions are welcome — please refer to the
[Contributing Guidelines](CONTRIBUTING.md).

## License

MIT, inherited from upstream `romanz/electrs`. See [LICENSE](LICENSE).
