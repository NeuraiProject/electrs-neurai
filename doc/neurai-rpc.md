# electrs-neurai — RPC reference

electrs-neurai speaks the protocol of **ElectrumX-neurai**
([NeuraiProject/electrumx-neurai](https://github.com/NeuraiProject/electrumx-neurai)),
so wallets written for it — in particular the Electrum desktop wallet
**electrum-neurai** — work unchanged. This page lists what is supported, the
few deliberate differences, and the electrs-neurai extensions. For the
semantics of each method, see ElectrumX-neurai's
[`docs/protocol-methods.rst`](https://github.com/NeuraiProject/electrumx-neurai/blob/main/docs/protocol-methods.rst).

## Transports

| Service | Option | Default | Framing |
|---------|--------|---------|---------|
| `tcp://` | `--electrum-rpc-addr` | `127.0.0.1:50001` (mainnet) | newline-delimited JSON-RPC |
| `ssl://` | `--electrum-ssl-addr` | disabled | newline-delimited JSON-RPC over TLS |
| `ws://`  | `--electrum-ws-addr`  | disabled | one JSON-RPC message per WebSocket message |
| `wss://` | `--electrum-wss-addr` | disabled | same, over TLS |

* TLS is native (rustls). `ssl://` and `wss://` need `--ssl-certfile` and
  `--ssl-keyfile` (PEM; PKCS#8, PKCS#1 or SEC1 key). The Docker images create a
  self-signed certificate on first start when the files don't exist.
* WebSocket framing is ElectrumX's (aiorpcX 0.22): every request is a whole
  JSON-RPC message or batch in one text (or binary) message, without a newline;
  every response and notification is sent as its own *text* message, without a
  newline. Incoming messages are limited to 5 MB, like ElectrumX `MAX_RECV`.
* `server.features` advertises the services given with `--report-services`
  (e.g. `ssl://electrum.example.org:50002,wss://electrum.example.org:50004`),
  or the listening addresses when it is not set.

## Protocol version

Like ElectrumX-neurai: protocol `1.0` to `1.4`, negotiated with ElectrumX's
algorithm (`server.version` accepts a version string or a `[min, max]` pair;
electrum-neurai asks for `"1.0"`). An unsupported version gets an error reply
and the connection is closed; a second `server.version` is an error. All
methods are available whatever version was negotiated.

## Methods

Every method registered by ElectrumX-neurai is supported, with the same
positional **and named** parameters, result shapes and error messages:

| Group | Methods |
|-------|---------|
| server | `server.version`, `server.features`, `server.banner`, `server.donation_address`, `server.ping`, `server.peers.subscribe` (always `[]`), `server.add_peer` (always `false`) |
| headers & fees | `blockchain.headers.subscribe`, `blockchain.block.header` (with `cp_height`), `blockchain.block.headers` (with `cp_height`), `blockchain.estimatefee` (with `mode`), `blockchain.relayfee`, `mempool.get_fee_histogram` |
| scripthash | `blockchain.scripthash.get_balance`, `.get_history`, `.get_mempool`, `.listunspent`, `.subscribe`, `.unsubscribe` |
| transactions | `blockchain.transaction.broadcast`, `.get`, `.get_merkle`, `.get_tsc_merkle`, `.id_from_pos` |
| assets | `blockchain.asset.get_meta`, `.get_assets_with_prefix`, `.list_addresses_by_asset`, `.broadcasts`, `.is_frozen`, `.verifier_string`, `.restricted_associations`, and `.subscribe` / `.unsubscribe` for the asset itself and for `broadcasts`, `is_frozen`, `verifier_string`, `restricted_associations` |
| tags | `blockchain.tag.check`, `blockchain.tag.qualifier.list`, `blockchain.tag.h160.list`, `blockchain.tag.qualifier.subscribe` / `.unsubscribe`, `blockchain.tag.h160.subscribe` / `.unsubscribe` |

Notes:

* Asset outputs (`<P2PKH> OP_XNA_ASSET <payload> OP_DROP`) are indexed under
  the scripthash of their base script, so `blockchain.scripthash.*` of a plain
  address include its asset transactions. `get_balance` / `listunspent` take
  ElectrumX's `asset` parameter (`false`, `true`, a name, or a list where `null`
  means XNA); in multi-asset replies XNA uses the key `"rvn"`.
* `blockchain.asset.get_meta` replies `{}` for an unknown asset and otherwise
  `{"sats_in_circulation", "divisions", "reissuable", "has_ipfs", ["ipfs"],
  "source": {"tx_hash", "tx_pos", "height"}, ["source_divisions"], ["source_ipfs"]}`.
  The state is folded from the issuance events like the daemon does (reissues add
  to the supply; units `-1` and reissues without IPFS keep the previous values,
  whose outputs are then given as `source_divisions` / `source_ipfs`).
  IPFS and TXID references are the base58 encoding of their 34 bytes.
* Mempool entries in asset and tag replies have `"height": -1`.
* `blockchain.asset.list_addresses_by_asset` is answered by the daemon's
  `listaddressesbyasset`, which needs `assetindex=1` on the node.
* `blockchain.transaction.get` with `verbose=true` does not need `txindex`:
  confirmed transactions are decoded with `decoderawtransaction` and the block
  fields (`blockhash`, `confirmations`, `time`, `blocktime`, `hex`) are added.

### Subscription statuses

Statuses are `sha256` of the following strings (hex, *not* reversed), or
`null` when there is no data — the same as ElectrumX, which matters because
electrum-neurai recomputes them:

| Subscription | Hashed string |
|--------------|---------------|
| scripthash | `"{tx_hash}:{height}:"` for every history entry |
| asset | `f"{sats_in_circulation}{divisions}{reissuable}{has_ipfs}"` + `ipfs` when `has_ipfs` |
| tag.qualifier / tag.h160 | `";".join(f"{key}:{height}{tx_hash}{tx_pos}{flag}")`, sorted by key |
| broadcasts | `";".join(f"{tx_hash}:{height}{tx_pos}{data}{expiration}")`, ascending by `(height, tx_hash, tx_pos)` |
| restricted_associations | `";".join(f"{asset}:{height}{tx_hash}{restricted_tx_pos}{qualifying_tx_pos}{associated}")`, sorted by asset |

Booleans are written `True` / `False` and a missing expiration `None`.
`is_frozen` and `verifier_string` subscriptions send the data object itself.
Notifications are sent when the value changes after a new block or a mempool
update.

### Differences from ElectrumX-neurai (bugs not reproduced)

| ElectrumX-neurai | electrs-neurai |
|------------------|----------------|
| Confirmed asset names are Python `bytes`, so `listunspent` / `get_balance` with assets produce no reply | asset names are strings |
| `get_assets_with_prefix` names start with a stray `a` | plain names |
| asset/tag `*.unsubscribe` always return `false` | `true` when the item was subscribed |
| `tag.check` reports `tx_hash` / `tx_pos` / `height` decoded from the lookup key | the real location of the tag |
| mempool tags are never merged into `tag.h160.list`; mempool associations are wrong | merged / computed correctly |
| broadcasts and freezes are not always undone on reorgs | every asset event is checked against the active chain |
| `restricted_associations.subscribe` notifications echo `"##NAME"` | `"#NAME"`, as subscribed |

`blockchain.transaction.get_tsc_merkle` keeps ElectrumX's behaviour of using
`sha256d(raw header)` as the `block_hash` target, which for KAWPOW headers is
not the block hash.

## electrs-neurai extensions

### `blockchain.address.get_scripthash`

Resolve a Neurai address (base58check `N…` / `t…`, or bech32 `nq1…` / `tnq1…` /
`rnq1…`) to its Electrum scripthash (64 hex characters).

```json
{"id": 1, "method": "blockchain.address.get_scripthash", "params": ["NQ…"]}
```

### `blockchain.asset.get_history`

Every confirmed `(asset, tx, height)` event and every mempool transaction that
touched an asset. Confirmed entries: `{"height", "block_hash", "tx_prefix"}`
where `tx_prefix` is the last 16 hex characters of the displayed txid; mempool
entries: `{"height": 0 or -1, "tx_hash", "fee"}`.

## Behaviour during initial sync

Until the first index compaction completes, index-dependent methods return
`{"code": -32603, "message": "unavailable index"}`. `server.*`,
`blockchain.headers.subscribe`, `blockchain.block.header(s)`,
`blockchain.estimatefee` and `blockchain.relayfee` remain available.
