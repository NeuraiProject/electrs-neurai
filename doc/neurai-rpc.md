# electrs-neurai — RPC reference

All of the standard Electrum v1.4 methods (see the
[upstream protocol docs](https://electrum-protocol.readthedocs.io/)) are
supported. This page covers only the **Neurai-specific extensions**.

Transport and framing are identical to upstream: newline-delimited JSON-RPC 2.0
over a TCP connection (default mainnet port `50001`, testnet `60001`, regtest
`60401`).

---

## `blockchain.address.get_scripthash`

Resolve a Neurai address string to its Electrum scripthash.

Useful for wallets that need to subscribe to an address by human-readable
string (Neurai addresses don't decode with the upstream `bitcoin::Address`
type because of the custom base58 prefixes and bech32 HRPs).

### Request
```json
{"id": 1, "method": "blockchain.address.get_scripthash", "params": ["NQ…"]}
```

### Params
| # | Type   | Description                                                            |
|---|--------|------------------------------------------------------------------------|
| 0 | string | A Neurai address — legacy base58check (`N…` / `t…`) or bech32 (`nq1…`, `tnq1…`, `rnq1…`, plus bech32m for taproot / future post-quantum witness versions). |

### Response
A 64-character lowercase hex string: the Electrum scripthash, i.e.
`SHA256(script_pubkey)` in Electrum's big-endian display order.

```json
{"id": 1, "result": "4b3d912c1523ece4615e91bf0d27381ca72169dbf6b1c2ffcc9f92381d4984a3"}
```

### Errors
- `{"code": 1, "message": "address version byte X does not match network …"}`
  — address prefix doesn't match the server's network.
- `{"code": 1, "message": "wrong bech32 HRP: expected nq, got …"}` — HRP
  mismatch between the address and the server's network.
- `{"code": 1, "message": "invalid base58check checksum"}` — standard checksum
  failure.

---

## `blockchain.asset.get_meta`

Return the stored metadata for an asset, or `null` if the name is unknown.

Written to the server's `asset_meta` column family on every `New` and
`Reissue` output indexed from a confirmed block.

### Request
```json
{"id": 1, "method": "blockchain.asset.get_meta", "params": ["TESTASSET"]}
```

### Params
| # | Type   | Description           |
|---|--------|-----------------------|
| 0 | string | Full asset name, e.g. `TESTASSET`, `ROOT/SUB`, `ROOT#UNIQUE`, `ROOT!`. |

### Response
Either `null` (no row found) or an object:

```json
{
  "name": "TESTASSET",
  "event": "new",
  "issuance_txid": "a3d9…",
  "issuance_height": 12345,
  "amount": 1000000000,
  "units": 8,
  "reissuable": true,
  "ipfs_hash": "11112222…",
  "ipfs_type": "ipfs"
}
```

| Field              | Type              | Notes                                                                              |
|--------------------|-------------------|------------------------------------------------------------------------------------|
| `name`             | string            | Echo of the requested name.                                                        |
| `event`            | `"new"` / `"reissue"` | The **latest** issuance event recorded for this asset.                         |
| `issuance_txid`    | hex string (64)   | Full txid of the issuance/reissue transaction.                                     |
| `issuance_height`  | integer           | Block height at which the event was confirmed.                                     |
| `amount`           | integer (satoshi-equivalent) | Signed 64-bit. `New` = initial supply; `Reissue` = additional supply issued. |
| `units`            | integer (0–8)     | Decimal places.                                                                    |
| `reissuable`       | boolean           | Whether further reissuance is allowed after this event.                            |
| `ipfs_hash`        | hex string (64) / `null` | 32-byte IPFS content hash or TXID reference.                                |
| `ipfs_type`        | `"ipfs"` / `"txid"` / `null` | Marker byte: `0x12` = IPFS SHA-256, `0x54` = on-chain tx reference.      |

---

## `blockchain.asset.get_history`

Return every confirmed `(asset, tx, height)` event and every unconfirmed
mempool transaction that touched the given asset. Confirmed entries are
sorted by ascending `(height, tx_prefix)`; mempool entries are appended last
and sorted by `(has_unconfirmed_inputs, tx_hash)` so transactions that depend
on other unconfirmed ones come after clean ones — matching the convention
used by `blockchain.scripthash.get_history`.

Multiple transactions in the same block that touch the same asset each
produce their own entry, so the client sees true per-transaction granularity
(not just block-level coarsening).

### Request
```json
{"id": 1, "method": "blockchain.asset.get_history", "params": ["TESTASSET"]}
```

### Params
| # | Type   | Description           |
|---|--------|-----------------------|
| 0 | string | Full asset name.      |

### Response
A JSON array of heterogeneous objects. Each entry is either **confirmed** or
**unconfirmed** — clients disambiguate by presence of `tx_prefix` /
`block_hash` vs `tx_hash`.

```json
[
  { "height": 12345, "block_hash": "a7f3…", "tx_prefix": "4a1b2c3d4e5f6071" },
  { "height": 12345, "block_hash": "a7f3…", "tx_prefix": "9988776655443322" },
  { "height": 12350, "block_hash": "b802…", "tx_prefix": "0011223344556677" },
  { "height": 0,   "tx_hash": "cafe…", "fee": 4242 },
  { "height": -1,  "tx_hash": "babe…", "fee": 8000 }
]
```

| Field         | Present on   | Type        | Meaning                                                             |
|---------------|--------------|-------------|---------------------------------------------------------------------|
| `height`      | all          | integer     | Positive = confirmed; `0` = mempool (no unconfirmed inputs); `-1` = mempool and the tx depends on other unconfirmed outputs. |
| `block_hash`  | confirmed    | hex (64)    | Block containing the transaction.                                  |
| `tx_prefix`   | confirmed    | hex (16)    | 16-character suffix of the transaction's txid **as displayed to users**. Lets clients distinguish multiple events in the same block without a daemon round-trip: `tx_hash.ends_with(tx_prefix)` picks the matching transaction when the block is fetched. |
| `tx_hash`     | unconfirmed  | hex (64)    | Full txid of the mempool transaction, in the standard Electrum display byte order. |
| `fee`         | unconfirmed  | integer     | Satoshi-equivalent fee as reported by the daemon.                  |

> **Byte order of `tx_prefix`** — The server stores `txid.as_byte_array()[..8]`
> (the first 8 bytes in consensus / wire order), but emits it reversed so the
> hex string is directly comparable to the tail of the user-facing txid
> display (which is the reversed hex of consensus bytes). In practice:
>
> - If your client keeps txids as display-order hex (the usual Electrum
>   convention): match with `display_txid.ends_with(tx_prefix)`.
> - If your client holds txids as raw `[u8; 32]` in consensus order: match
>   with `bytes[..8] == reverse(hex_decode(tx_prefix))`.
>
> Returning the full 32-byte txid per confirmed event would require re-reading
> the block, so only the 8-byte fingerprint is persisted in the
> `asset_history` column family. Clients that need the full txid can fetch
> the block and select the matching tx by suffix.

---

## Behaviour during initial sync

While electrs-neurai is still building its index (the period before the first
compaction completes), all three new methods return the standard
`{"code": -32603, "message": "unavailable index"}` error, matching the
behaviour of `blockchain.scripthash.get_history` and other index-dependent
methods. A handful of bootstrap methods (`blockchain.block.header`,
`blockchain.block.headers`, `blockchain.headers.subscribe`, `server.version`)
remain available so clients can display a meaningful "syncing" status.
