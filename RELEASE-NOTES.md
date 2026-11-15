# Unreleased — ElectrumX-neurai compatibility, native TLS and WebSocket

**ElectrumX-neurai protocol.** electrs-neurai now implements every method of
ElectrumX-neurai (48), with its parameter names, reply shapes, error messages
and subscription statuses, so the Electrum desktop wallet *electrum-neurai*
works against it. See [doc/neurai-rpc.md](doc/neurai-rpc.md).

* Protocol versions 1.0–1.4, negotiated like ElectrumX (electrum-neurai asks
  for exactly "1.0", which was rejected before).
* New: `blockchain.asset.*` (`get_assets_with_prefix`, `list_addresses_by_asset`,
  `broadcasts`, `is_frozen`, `verifier_string`, `restricted_associations`, and
  the `subscribe`/`unsubscribe` of each), `blockchain.tag.*` (`check`,
  `qualifier.list`, `h160.list` and their subscriptions),
  `blockchain.scripthash.get_mempool`, `blockchain.transaction.get_tsc_merkle`,
  `server.add_peer`, `cp_height` in `blockchain.block.header(s)`, `mode` in
  `blockchain.estimatefee` (falls back to the relay fee instead of -1),
  ElectrumX's `mempool.get_fee_histogram` binning, named parameters.
* `blockchain.asset.get_meta` uses ElectrumX's reply (`sats_in_circulation`,
  `divisions`, `has_ipfs`, base58 `ipfs`, `source`, `source_divisions`,
  `source_ipfs`; `{}` when unknown) and includes owner tokens.
* New indexes (DB format 5): qualifier tags and per-address freezes, global
  freezes, verifier strings, qualifier associations, broadcasts and asset
  names. Like `asset_meta`, they are append-only and checked against the active
  chain on read, so reorgs need no undo data. Mempool transactions are overlaid.
* ElectrumX bugs are not reproduced (asset names as bytes, the stray prefix
  byte in `get_assets_with_prefix`, unsubscribe always `false`, `tag.check`
  locations, mempool asset filters, ...). Validated with a differential test
  against ElectrumX-neurai on the same v1.0.7 regtest chain: every reply is
  identical except for those bugs.

**Transports.** Native TLS (`--electrum-ssl-addr`, rustls) and WebSocket
(`--electrum-ws-addr`, `--electrum-wss-addr`) with ElectrumX's framing (one
JSON-RPC message per text message). The Docker setups no longer need the
nginx + websockify container, whose WebSocket bridge rejected text frames.

**KAWPOW performance.** The block hash (`KAWPOWHash_OnlyMix`) is now two
Keccak permutations (about 2 µs). It used to run the full KAWPOW verification
(about 15 ms on mainnet, or 2 s when switching epochs), which made a restart
with a fully indexed mainnet take weeks, because headers are loaded from the DB
in random height order. The KAWPOW check is no longer repeated for every
downloaded block, because the block hash already depends on the `mix_hash`.

**Header anchors.** Mainnet headers up to height 1,732,000 are authenticated by
Neurai core's header anchors (`src/chainparamsanchors.h` from b778146, one hash
every 2,000 blocks, all checked against a v1.0.7 node). The KAWPOW block hash
commits to every header field, so a header chain that links to an anchor needs
no KAWPOW check. The remaining headers, and every header on testnet and regtest,
are verified in parallel, one epoch at a time, using ethash's shared,
thread-safe epoch context. If a block's hash differs from its anchor, every
header is verified.

**Neurai 2.0 / DePIN-Test.** electrs-neurai works with the DePIN-Test testnet
(checked against `/Neurai:2.0.0/` on testnet and on a regtest that uses every
feature below), and is ready for the unified fork on mainnet:

* The P2P handshake announces protocol 70031 (`UNIFIED_FORK_VERSION`): 2.0 nodes
  refuse lower versions (the testnet from the first handshake), and 1.0.7 nodes
  accept it.
* NIP-014 reference inputs: transactions are read by a new Neurai parser that
  knows the extended format's flag 2 and computes the txid like the daemon
  (it commits to the reference inputs). They used to stop indexing.
  `bitcoin_slices` is no longer used.
* Asset scripts follow `CScript::IsAssetScript` of 2.0, which keeps the 1.0.7
  rules below the fork: from the fork, the `"xna"` marker (NIP-040) and the
  AuthScript forms `OP_1`/`OP_2`/`OP_3 <32 bytes> OP_XNA_ASSET ... OP_DROP` for
  assets and tags; the payload is read to the end of the script as the daemon
  does. This also fixes mainnet transfers with a doubled `OP_XNA_ASSET`
  (block 1615824), which were indexed as plain outputs.
* DePIN transfer states (`&NAME` open/closed/sealed) are indexed separately
  from global freezes, and `get_meta` reports `transfer_state`.
* Asset names up to 121 bytes on networks with the fork scheduled.
* **DB format 6 — a full reindex runs automatically on upgrade** (about ten
  minutes on mainnet).

**TLS certificate reload.** electrs reloads `ssl_certfile` / `ssl_keyfile`
when they change, so renewed certificates need no restart. A certificate whose
key does not match yet (files half-replaced) is retried, and the current one is
kept meanwhile.

**Docker.** The mainnet and testnet stacks are configured with a `.env` file
(`.env.example` in each directory): RPC credentials shared by the node and
electrs, ports, electrs options and a domain. With `DOMAIN` and `CLOUDFLARE_API_TOKEN` set,
a `letsencrypt` service (certbot, DNS-01 through the Cloudflare API, no port to
open) checks that the domain is in a zone the token can see, then gets and
renews a certificate for it.
`docker/*/electrs/config.toml` is gone: set `NEURAI_RPC_PASSWORD` in `.env`. The
testnet stack now builds (its node directory was misplaced), uses ports
60001/60002/60004 so it can run next to mainnet, and publishes node RPC on
127.0.0.1 only. See [docker/README.md](docker/README.md).

**Testing.** `--network regtest-v1` indexes the regtest of the v1.0.7
release (X16Rv2 headers, new `hasherx16r-sys` crate), so the mainnet consensus
and asset code can be tested locally.

# Neurai v1.0.7 mainnet compatibility

Tested against `neuraiproject/neurai-node:v1.0.7`: asset scripts, blocks and
RPC responses from regtest; KAWPOW headers and the P2P handshake on mainnet.

* **DB format 4 — a full reindex runs automatically on upgrade.**
* Confirmed history, unspent outputs and balances now point at the right
  transaction. `bitcoin_slices` visits a transaction's inputs/outputs before
  `visit_transaction`; the block filters attributed every match to the
  previous transaction in the block (and could panic on coinbase outputs).
* Asset rows (`asset_history`, `asset_meta`) carry the txid of the transaction
  that contains the asset output (same visiting-order bug in the indexer).
* Asset payloads of 76 bytes or more (encoded with `OP_PUSHDATA1`: long names
  with an IPFS hash, transfers with a message) are recognised. They used to be
  indexed as plain outputs, invisible to the holder's address.
* `blockchain.asset.get_meta` reports the asset's current state, folded like
  the daemon's asset cache: `amount` is the total supply, reissues with units
  `-1` keep the decimal places, and reissues without IPFS keep the hash.
  Events from reorged blocks are ignored.
* Mempool tracking works with Neurai's `getmempoolentry` (`size`/`fee`, no
  `fees` object) — it used to drop every mempool transaction.
* `blockchain.transaction.get_merkle` / `id_from_pos` work with Neurai's
  `getblock` (no `nTx`).
* `blockchain.transaction.get` with `verbose=true` works: Neurai's
  `getrawtransaction` takes no `blockhash`, so confirmed transactions are
  decoded with `decoderawtransaction` and the block fields are added.
* `docker/mainnet` runs the official `neuraiproject/neurai-node:v1.0.7` image
  instead of building the `DePIN-Test` branch.

**Fixes from upstream electrs up to 0.12.1** (upstream's switch to `bindex`
in 0.12.0 is not ported: it requires Bitcoin Core 31+ RPC/REST features that
Neurai doesn't have).

* `blockchain.transaction.id_from_pos`: `merkle` is optional, and a bare txid
  is returned when it is `false` (protocol compliance).
* `bitcoin_slices` 0.12: rejects oversized length prefixes and too-large
  transactions instead of truncating them.
* Update dependencies (`bitcoin`, `crossbeam-channel`, `log`, `rayon`,
  `serde_json`, `sha2`, `signal-hook`).

**MSRV 1.88** (was 1.85), required by `sha2` 0.11.1 (fixes the AArch64 SHA-2
backend under Rust's aliasing model). The Dockerfiles install 1.88.0 with
rustup; Debian 13's packaged `cargo` (1.85) can no longer build the project.
* Document the GCC 15 `<cstdint>` workaround for building RocksDB.

# electrs-neurai 0.1.0 — initial Neurai release

First release of the Neurai adaptation of
[romanz/electrs](https://github.com/romanz/electrs) (upstream base: 0.11.1).
The migration log in `../ELECTRS_MIGRATION.md` has the per-phase breakdown;
the highlights:

**Neurai-specific core**

* Per-network constants (`NeuraiNetwork::{Mainnet, Testnet, Regtest}`) mirroring
  `src/chainparams.cpp` — P2P/RPC/Electrum ports, magic bytes, bech32 HRPs,
  base58 prefixes, KAWPOW activation time.
* `NeuraiBlockHeader` supporting both 80-byte pre-KAWPOW and 120-byte
  post-KAWPOW layouts; KAWPOW hashing wired through the sibling
  `hasherkawpow-sys` FFI crate.
* `neurai_to_bsl_block` helper that safely bridges variable-size Neurai blocks
  into `bitcoin_slices::bsl::Block::visit` for transaction iteration.
* Dynamic testnet / regtest genesis — fetched from the daemon at startup
  rather than hard-coded.

**Addresses**

* Native base58check codec for legacy `N…` / `t…` addresses.
* bech32 / bech32m codec for SegWit witness programs (`nq1…` / `tnq1…` /
  `rnq1…`), paving the way for post-quantum witness versions.
* New RPC: `blockchain.address.get_scripthash`.

**Assets**

* Full parser for Neurai asset outputs: `OP_XNA_ASSET` (`0xc0`) with the
  `"rvn"` magic prefix and all four `AssetType` variants (`q`, `t`, `r`, `o`),
  over both P2PKH and OP_1+`<32-byte>` base scripts.
* RocksDB column families `asset_meta`, `asset_history`, `asset_funding`
  for issuance metadata, per-asset tx history, and per-scripthash asset
  holdings. Format version bumped to `2`; existing DBs auto-reindex.
* New RPC: `blockchain.asset.get_meta`, `blockchain.asset.get_history`
  (confirmed + mempool entries).
* Mempool is asset-aware: `Mempool::by_asset_name` and
  `filter_by_asset_name`.

**Ops**

* Production `Dockerfile` (multi-stage: rustup builder → debian:trixie-slim
  runtime with `librocksdb9.10`, `libssl3`, dedicated `electrs` user).
* `Dockerfile.dev` for iterative Rust development.
* `Dockerfile.ci` for build + test in CI.
* `regtest/` Docker Compose harness with a 7-step end-to-end smoke test
  (`regtest/e2e.sh`).
* `doc/neurai-rpc.md` documents every Neurai-specific RPC extension.

**Removed from upstream**

* `submitpackage` / `blockchain.transaction.broadcast_package` (Neurai does
  not expose a `submitpackage` RPC).
* Dead `Config.magic` / `Config.bitcoin_network` fields.
* `bitcoin_network_for` helper (no longer needed — everything flows through
  `NetworkParams`).

---

## Upstream history (for reference)

The sections below are the unmodified release notes from upstream electrs up
to the fork point. They are kept for traceability.

# 0.11.1 (Feb 22 2026)

* Update `transaction.id_from_pos` response for API compliance.
* Expose configurable magic on non-signet.
* Update dependencies (`bitcoin`, `ctrlc`, `log`, `serde_json`, `signal-hook`, `tempfile`).

# 0.11.0 (Nov 16 2025)

* Update MSRV to 1.85
* Support Debian 13 (trixie) / Ubuntu 25.04 (plucky)
* Update RocksDB crate to `rust-rocksdb` 0.36
  - [Dynamic linking with RocksDB](doc/install.md) now requires [RocksDB 9.10.0](https://packages.debian.org/trixie/librocksdb-dev) (instead of 7.8.3).
  - Old electrs versions won't be able to read the new RocksDB database format (requiring reindex).
* Support `blockchain.transaction.broadcast_package` Electrum RPC.
* Update dependencies (`bitcoin`, `ctrlc`, `log`, `prometheus`, `rayon`, `serde`, `serde_json`, `tempfile`, `tempfile`).

# 0.10.10 (Jul 19 2025)

* Update documentation links and typos.
* Update dependencies (`bitcoin`, `crossbeam-channel`, `log`, `prometheus`, `signal-hook`, `tempfile`).

# 0.10.9 (Feb 01 2025)

* Update `bitcoin_slices` to 0.10.0
* Allow concurrent DB background operations for SSDs

# 0.10.8 (Dec 30 2024)

*  Separate blocks reading & index writing into scoped threads
*  Set HTTP `Content-Type` header for Prometheus response
*  Use `ctrlc` in place of `signal-hook` on Windows
*  Don't deserialize transactions if not needed
*  Run CI only on `master` branch and PRs
*  Update dependencies (`bitcoin`, `bitcoin_slices`, `crossbeam-channel`, `tempfile`)

# 0.10.7 (Nov 05 2024)

* Support testnet4
* Enable LTO in release build
* Don't sync mempool when bitcoind mempool is not yet loaded
* Update dependencies (`bitcoin`, `bitcoin_slices`)

# 0.10.6 (Sep 29 2024)

* Update dependencies (`bitcoin`, `configure_me_codegen`, `crossbeam-channel`, `log`)
* Deprecate unused config option `timestamp`
* Don't fail if bitcoind fee estimation is disabled
* Save on allocations by using fixed size types for database rows
* Add BTC Prague 2024 dev/hack/day slides

# 0.10.5 (May 18 2024)

* Update dependencies (`bitcoin`, `bitcoin_slices`, `bitcoincore-rpc`, `rayon`)
* Support latest bitcoind (https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/353 & https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/356)

# 0.10.4 (Mar 15 2024)

* Don't fail mempool sync on missing transactions (#997)
* Update dependencies (`anyhow`, `crossbeam-channel`, `log`, `secp256k1`, `secp256k1-sys`, `smallvec`, `tempfile`, `termcolor`, `thiserror`, `thiserror-impl`)

# 0.10.3 (Feb 10 2024)

* Update dependencies (`serde_json`, `tempfile`, `env_logger`, `rayon`, `bitcoin`, `crossbeam-channel`, `shlex`)
* Fix build on Debian 12 (#1001)

# 0.10.2 (Dec 31 2023)

* Use batched RPC to fetch mempool entries & transactions (#979)
* Avoid redundant recomputation of fee histogram bins (#971)
* Explain behavior of config file loading (#964)
* Don't flush when nothing is written to DB (#958)
* Allow setting RocksDB log directory (#959)
* Upgrade `bitcoin` to 0.31.0 (#941)
* Update dependencies (#953, #951, #980)

# 0.10.1 (Nov 01 2023)

* Fix build failure on Raspberry Pi 4 (32bit) (#940)
* Return first txid-matching transaction (#933)
* Add txid collision scanner (#928)
* Optimize indexing via `bitcoin_slices` (#927)
* Optimize index querying via `bitcoin_slices` (#913)
* Avoid precompiled 'serde_derive' >=1.0.172 (#924)
* Allow exiting mempool sync on SIGINT (#917)
* Allow skipping merkle proof downloads in `history.py` (#915)
* Remove IndexResult and index into db::WriteBatch (#914)
* Dockerfile: re-add curl for the second time, so it can be used for docker health checks (#912)
* Reuse buffer in p2p handling (#910)
* Preallocate serialized vector of HashPrefixRow (#909)
* Less verbose logging when bitcoind is warming up (#908)
* Drop Cirrus CI due to flakiness (#948)
* Update dependencies (`anyhow`, `bitcoin`, `electrs-rocksdb`, `rayon`, `rustix`, `serde`, `serde_derive`, `serde_json`, `signal-hook`, `syn`, `tempfile`)


# 0.10.0 (Jul 22 2023)

* Add ARM build and integration tests in Cirrus CI

# 0.10.0-rc.1 (Jun 21 2023)

* Bump MSRV to 1.63.0 and update Rust edition to 2021 (#773)
* Update dependencies (`anyhow`, `configure_me_codegen`, `electrs-rocksdb`, `env_logger`, `parking_lot`, `prometheus`, `rayon`, `serde`, `serde_derive`, `serde_json`)
  - Please note that [dynamic linking with RocksDB](doc/install.md) now requires [RocksDB 7.8.3](https://packages.debian.org/bookworm/librocksdb-dev) (instead of 6.11.4)!

# 0.9.14 (Jun 10 2023)

* Fix 'server.version' support for version range (#887)
* Allow not waiting for block download before sync (#888)
* Fix typo in config_specification.toml (#883)
* Bump bitcoind version used in CI (#882)
* Prefix Prometheus metrics with 'electrs_' (#881)
* Fixup error handling in Prometheus HTTP server (#880)
* Add address->scripthash conversion tool
* Update dependencies (crossbeam-channel, jsonrpc, bitcoincore-rpc, serde_json, tempfile)

# 0.9.13 (Mar 31 2023)

* Upgrade dependencies (`bitcoin` & `bitcoincore-rpc` #865, `crossbeam-channel` #854, `serde_json` #855, `tempfile` #850)
* Don't panic on unexpected magic (#861)
* contrib: rename xpub into get_balance (#627)

# 0.9.12 (Feb 25 2023)

* Update dependencies (`serde_json`, `signal-hook`, `electrs-bitcoincore-rpc`, `electrs-rocksdb`)
* Add `CONTRIBUTING.md` (#838)
* Add `blockchain.transaction.id_from_pos` RPC (#836)
* Add `blockchain.scripthash.unsubscribe` RPC (#833)
* Support IPv6 connections (#792)

# 0.9.11 (Jan 5 2023)

* Update dependencies (`secp256k1`, `serde_json`, `configure_me_codegen`, `env_logger`, `electrs-rocksdb`)
* Improve error logging in case of p2p error (#807)

# 0.9.10 (Nov 3 2022)

* Update dependencies (`bitcoin`, `bitcoincore-rpc`, `tiny_http`, `serde_json`, `env_logger`)
* Fix mempool fee rate formatting (#761)
* Allow configuring signet p2p magic (#762, #768)
* Don't panic in case of an invalid block header height (#786)

# 0.9.9 (Jul 12 2022)

* Update dependencies (`anyhow`, `crossbeam-channel`, `crossbeam-utils`, `regex`, `serde`, `serde from `, `serde_json`, `signal-hook`)
* Don't log scripthash (#737)

# 0.9.8 (Jun 3 2022)

* Update dependencies (`serde_json`, `serde`, `bitcoin`, `bitcoincore-rpc`, `rayon`, `log`)
* Support new Electrum release `getbalance` response format (#717)

# 0.9.7 (Apr 30 2022)

* Add build matrix to test all features in CI (#706)
* Install and run cargo-bloat in CI (#705)
* Add guide for other Ubuntu & Debian releases to compile and install librocksdb (#696)
* Update dependencies (`anyhow`, `log`, `crossbeam-channel`, `rayon`)

# 0.9.6 (Mar 4 2022)

* Allow skipping default config files (#686)
* Update dependencies (`anyhow`, `serde-json`)

# 0.9.5 (Feb 4 2022)

* Update dependencies (`serde-json`, `serde`, `tempfile`, `crossbeam-channel`)
* Fix `txid` index collision handling (#653)
* Use `bitcoincore_rpc`'s `getblockchaininfo` implementation (#656)

# 0.9.4 (Dec 30 2021)

* Update dependencies (`anyhow`, `serde`, `serde_json`, `signal-hook`)
* Improve p2p receiving metrics (#633)
* Warn on attempt to connect over SSL (#634)
* Disable `index_lookup_limit` by default (#635)
* Parse p2p messages in a separate thread (#638)
* Add server loop-related metrics

# 0.9.3 (Nov 20 2021)

* Support basic RPC handling during initial sync (#543)
* Update MSRV requirements to Rust 1.48 (#603)
* Bump `env_logger` to 0.9 (#604)
* Monitor RocksDB statistics via Prometheus (#605)
* Don't warn when queried with unsubscribed scripthashes (#609)
* Allow skipping merkle proofs' during subscription (#610)
* Remove `verbose` configuration (#615)
* Add `curl` to `Dockerfile` (#624)

# 0.9.2 (Oct 31 2021)

* Add a feature to ignore default config files (#396)
* Support Rust 1.48.0 and test on Debian 11 (#455)
* Allow multiple scripthashes' subscription in parallel(#464)
* Ignore `cargo audit` warning in `tiny_http` (#575)
* Re-organize and split documentation (#583)
* Use `/electrs:$VERSION/` in p2p 'user-agent' (#585)
* Build rocksdb with conditional SSE support (#595)
* Ignore 'addr' p2p messages (#596)

# 0.9.1 (Oct 19 2021)

* Initialize chain height metric (#515)
* Don't shutdown write-side before all responses are sent back (#523)
* Use p2p protocol to replace waitfornewblock hidden RPC (#526)
* Use correct Prometheus buckets for size and duration (#528)
* Don't ignore signals during IBD (#533)
* Expose index DB size as a Prometheus gauge metric (#544)
* Add p2p protocol monitoring (#546)
* Fix contrib/xpub.py support for ypub/zpub keys (#549)
* Rewrite and simplify p2p message receiving thread (#550)
* Re-introduce mempool vsize and txs' count metrics (#557, #562, #563)
* Allow RPC connection before initial sync is over (#558)

# 0.9.0 (Sep 30 2021)

**IMPORTANT: This release contains major changes, please read carefully!**

The four main things to watch out for:

* Database schema changed - this will cause **reindex after upgrade**.
* `mainnet` subdirectory was renamed to `bitcoin`, you should delete `mainnet` after successful reindex.
* We now use **bitcoin p2p protocol** to fetch blocks - some configurations may not work.
* Trace log level now logs much more information - make sure it's not used in production.

See [upgrading](doc/upgrading.md) section of our docs to learn more.

Full list of changes:

* Add electrs logo (#510)

## 0.9.0-rc2 (Sep 23 2021)

* Prevent panic during logging of p2p messages (#490)
* Don't collect process' Prometheus metrics by default (#492)
* Support initial sync resume (#494)

## 0.9.0-rc1 (Sep 17 2021)

* Fix incorrect ordering of same-block transactions (#297)
* Change DB index format and use Zstd compression (instead of Snappy)
* The database will be reindexed automatically when it encounters old version (#477)
* Don't use bitcoind JSON RPC for fetching blocks (#373)
* Use p2p protocol for headers and block fetching only.
  This is safer than reading `blk*dat` files and faster than JSON RPC.
* Support Electrum JSON RPC batching and errors
* Use `rust-bitcoincore-rpc` crate
* Increase default `index_lookup_limit` to 200
* Implement 'blockchain.scripthash.listunspent' RPC (#475)
* Update RocksDB to 6.11.4 (#473)
* Allow logging configuration via `RUST_LOG` environment variable (using `env_logger`)

# 0.8.12 (14 Sep 2021)

* Fail if `cookie` is specified (#478)
* Move usage in README up and recommend our guide (#463)
* A bunch of improvements to issue templates (#462)

# 0.8.11 (18 Aug 2021)

* Update dependencies (#401, #402)
* Add python example in RPC examples (#415, #417)
* Add regtest and signet networks in examples (#425)
* Clippy fixes (#430)
* CI fixes (#437, #438, #441)
* Update relevant versions (#450)
* Drop unused compression algorithms for RocksDB

# 0.8.10 (14 May 2021)

* Fix JSONRPC errors' handling (#398, #390)
* Optimize Dockerfile (#387, #388, #392)
* Fix signet default port (https://github.com/romanz/electrs/commit/b53178c140e575b0527a70ead566d50c7fe6cb1f)

# 0.8.9 (19 Mar 2021)

* Use non-batched RPC to reduce bitcoind memory usage (#373)
* Fix inverted logic of deprecation (#379)
* Ignore individual mempool transaction fetch fails (#381)
* Increase default wait_duration_secs to 10s (#384)

# 0.8.8 (22 Feb 2021)

* Deprecate `--cookie` configuration (@Kixunil)
* Update dependencies (@Kixunil)
* Improve documentation (@Kixunil)

# 0.8.7 (15 Jan 2021)

* Support signet (#239)

# 0.8.6 (25 Nov 2020)
* [Fix](https://github.com/romanz/electrs/commit/c88a0dc331eb16163276becf98fcc020565d97eb) Electrum fee histogram duplicates
* [Fix](https://github.com/romanz/electrs/commit/8f2f53303a62321e3ccd1a8dc42b46c63629a03f) Electrum protocol negotiation
* Update multiple crates (@kixunil): [lru](#333), [prometheus](#334), [dirs-next](#335)
* Support Rust 1.41.1 (for Debian stable)
* [Update](https://github.com/romanz/electrs/commit/af6ff09a275ec12b6fd0d6a101637f4710902a3c) bitcoin crate (@dr-orlovsky)
* [Fix](https://github.com/romanz/electrs/commit/4764dccbbe4cd04a6dc79771a686847d8e6e2edf) a deadlock when shutting down (@kixunil)

# 0.8.5 (1 July 2020)

* Add a 'blocks_dir' option (@darosior)
* Return fee for unconfirmed transactions history (for Electrum 4.0)
* Handle SIGUSR1 for external notifications

# 0.8.4 (3 June 2020)

* Update to latest rust-bitcoin (@dr-orlovsky)
* Fix deadlock and refactor RPC threading (@Kixunil)

# 0.8.3 (30 Jan 2020)

* Fix memory leak (@champo)

# 0.8.2 (6 Dec 2019)

* Downgrade rust-rocksdb to 0.12.2 (https://github.com/romanz/electrs/issues/193)

# 0.8.1 (20 Nov 2019)

* Allow setting `--cookie-file` path via configuration (@Kixunil)
* Bump rust-rocksdb to 0.13.0, using RockDB 6.2.4

# 0.8.0 (28 Oct 2019)

* Use `configure_me` instead of `clap` to support config files, environment variables and man pages (@Kixunil)
* Don't accept `--cookie` via CLI arguments (@Kixunil)
* Define cache size in MB instead of number of elements (@dagurval)
* Support Rust >=1.34 (for Debian)
* Bump rust-rocksdb to 0.12.3, using RockDB 6.1.2
* Bump bitcoin crate to 0.21 (@MichelKansou)

# 0.7.1 (27 July 2019)

* Allow stopping bulk indexing via SIGINT/SIGTERM
* Cache list of transaction IDs for blocks (@dagurval)

# 0.7.0 (13 June 2019)

* Support Bitcoin Core 0.18
* Build with LTO
* Allow building with latest Rust (via feature flag)
* Use iterators instead of returning vectors (@Kixunil)
* Use atomics instead of `Mutex<u64>` (@Kixunil)
* Better handling invalid blocks (@azuchi)

# 0.6.2 (17 May 2019)

* Support Rust 1.32 (for Debian)

# 0.6.1 (9 May 2019)

* Fix crash during initial sync
* Switch to `signal-hook` crate

# 0.6.0 (29 Apr 2019)

* Update to Rust 1.34
* Prefix Prometheus metrics with 'electrs_'
* Update RocksDB crate to 0.12.1
* Update Bitcoin crate to 0.18
* Support latest bitcoind mempool entry vsize field name
* Fix "chain-trimming" reorgs
* Serve by default on IPv4 localhost

# 0.5.0 (3 Mar 2019)

* Limit query results, to prevent RPC server to get stuck (see `--txid-limit` flag)
* Update RocksDB crate to 0.11
* Update Bitcoin crate to 0.17

# 0.4.3 (23 Dec 2018)

* Support Rust 2018 edition (1.31)
* Upgrade to Electrum protocol 1.4 (from 1.2)
* Let server banner be configurable via command-line flag
* Improve query.get_merkle_proof() performance

# 0.4.2 (22 Nov 2018)

* Update to rust-bitcoin 0.15.1
* Use bounded LRU cache for transaction retrieval
* Support 'server.ping' and partially 'blockchain.block.header' Electrum RPC

# 0.4.1 (14 Oct 2018)

* Don't run full compaction after initial import is over (when using JSONRPC)

# 0.4.0 (22 Sep 2018)

* Optimize for low-memory systems by using different RocksDB settings
* Rename `--skip_bulk_import` flag to `--jsonrpc-import`

# 0.3.2 (14 Sep 2018)

* Optimize block headers processing during startup
* Handle TCP disconnections during long RPCs
* Use # of CPUs for bulk indexing threads
* Update rust-bitcoin to 0.14
* Optimize block headers processing during startup


# 0.3.1 (20 Aug 2018)

* Reconnect to bitcoind only on transient errors
* Poll mempool after transaction broadcasting

# 0.3.0 (14 Aug 2018)

* Optimize for low-memory systems
* Improve compaction performance
* Handle disconnections from bitcoind by retrying
* Make `blk*.dat` ingestion more robust
* Support regtest network
* Support more Electrum RPC methods
* Export more Prometheus metrics (CPU, RAM, file descriptors)
* Add `scripts/run.sh` for building and running `electrs`
* Add some Python tools (as API usage examples)
* Change default Prometheus monitoring ports

# 0.2.0 (14 Jul 2018)

* Allow specifying custom bitcoind data directory
* Allow specifying JSONRPC cookie from commandline
* Improve initial bulk indexing performance
* Support 32-bit systems

# 0.1.0 (2 Jul 2018)

* Announcement: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2018-July/016190.html
* Published to https://crates.io/electrs and https://docs.rs/electrs
