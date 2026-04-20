# electrs-neurai — regtest end-to-end harness

Live integration test for electrs-neurai against a real Neurai daemon in
regtest mode. Not run by `cargo test`; intended for manual validation and
future CI once a Neurai regtest daemon image is published.

## What it covers

1. Block indexing catches up with the daemon tip.
2. `blockchain.address.get_scripthash` resolves a regtest `t…` address to the
   expected SHA-256 of its scriptPubKey.
3. Asset issuance (`issue TESTASSET …`) lands in the `asset_meta` column family
   and is retrievable via `blockchain.asset.get_meta`.
4. `blockchain.asset.get_history` returns at least one confirmed entry for the
   issued asset.
5. An unconfirmed asset transfer is reported as a mempool entry in
   `blockchain.asset.get_history` (height `0` / `-1`).

## Prerequisites

- Docker + Docker Compose v2
- `nc` and `jq` on the host running `e2e.sh`
- A Neurai daemon image that supports `-regtest` mode. The default is
  `neurai-linux64-bin:latest`; override with the `NEURAI_DAEMON_IMAGE`
  environment variable.

## Usage

```
cd regtest

# Start the stack (builds electrs-neurai from the Dockerfile in the parent dir).
docker compose up --build -d

# Run the smoke test.
./e2e.sh

# Tear down (wipes both volumes).
docker compose down -v
```

## Ports and volumes

| Name           | Container             | Host          |
|----------------|-----------------------|---------------|
| Neurai RPC     | neurai-daemon:19201   | (internal)    |
| Neurai P2P     | neurai-daemon:19200   | (internal)    |
| Electrum RPC   | electrs:60401         | `:60401`      |

Volumes: `daemon-data` for the daemon's `~/.neurai` and `electrs-data` for the
index DB at `/var/lib/electrs-neurai`.

## Troubleshooting

- **`depends_on` healthcheck never passes** — Confirm the Neurai daemon
  image exposes the `neurai-cli` binary and accepts the `-regtest` flag.
- **electrs exits immediately with "daemon not available"** — The daemon
  probably isn't listening on all interfaces. The compose file already sets
  `-rpcbind=0.0.0.0 -rpcallowip=0.0.0.0/0`; verify the image doesn't override
  them.
- **`asset.get_meta` returns `null`** — Re-check the block was mined after
  `issue` (`generatetoaddress 1 "$ADDR"`), then wait a few seconds for
  electrs to finish its sync cycle.
