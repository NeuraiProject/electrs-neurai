# Chunked UTXO sets

**Status:** version 1, implemented by electrs-neurai. An extension: no existing
method changes.

## Motivation

`blockchain.scripthash.listunspent` returns every UTXO of an address in a single
reply. For an address with hundreds of thousands of UTXOs that reply is tens of
megabytes (about 91 MB for the largest mining pool address): clients with a
message size limit fail, and every refresh downloads the whole set again. Such
addresses can't be subscribed to either: `blockchain.scripthash.subscribe`
refuses histories of 101,010 transactions or more.

The methods below let a wallet:

1. download the confirmed UTXO set of an address, XNA and assets, in chunks of at
   most 128 KB, and check that it got the whole set from a single snapshot;
2. later ask only for what changed after the block it has, even days later;
3. be notified when the set or the mempool changes, whatever the size of the
   address.

## Compatibility

* No existing method changes its parameters, results or errors. Wallets that
  don't know these methods see no difference.
* A server that supports them advertises `"utxo_chunks": 1` (the version of this
  document) in `server.features`. Clients check it before using them; other
  servers answer "method not found".
* Small addresses get everything in a single reply, so a wallet can use these
  methods for every address, not only the large ones.

## Flow

```
utxo_subscribe(sh)               → status
utxo_sync(sh, null)              → the whole set, as changes from an empty set
  ├─ one chunk:  the changes come inline
  └─ n chunks:   utxo_chunk(sh, id, 0 … n-1), each checked against its hash
check count and set_hash, keep the set and block_hash

notification (sh, new status)
utxo_sync(sh, block_hash)        → only what changed since block_hash
```

The wallet keeps four things per address: its UTXO set, the `block_hash` of
that set, its `set_hash` and its `count`.

## UTXO entries

The objects of `listunspent`:

```json
{"height": 1234560, "tx_hash": "…", "tx_pos": 0, "value": 100000000, "asset": null}
```

Every UTXO is included: XNA (`"asset": null`, `value` in satoshis) and every
asset (`"asset": "NAME"`, `value` in the asset's smallest units). There is no
filter; a wallet that wants less filters locally. Confirmed UTXOs have their
block height; mempool UTXOs have `"height": 0`.

## Hashes

The hash of a UTXO `u`, `h(u)`, is the SHA-256 of the UTF-8 string

```
"{tx_hash}:{tx_pos}:{height}:{value}:{asset}"
```

with `tx_hash` as displayed (64 lowercase hex characters), the integers in
decimal, and `asset` empty for XNA, read as a 256-bit big-endian unsigned
integer. All the sums below are modulo 2²⁵⁶ and are written as 64 lowercase hex
characters (big-endian).

* The **set hash** of a set of UTXOs is the sum of their `h(u)`. The empty set
  has the hash `"000…000"`.
* The **hash of some changes** is the sum of `h(u)` of the added UTXOs minus the
  sum of `h(u)` of the removed ones. Applying changes to a set adds their hash to
  the set hash.

```python
import hashlib

N = 2**256

def utxo_hash(u):
    s = f"{u['tx_hash']}:{u['tx_pos']}:{u['height']}:{u['value']}:{u['asset'] or ''}"
    return int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")

def changes_hash(added, removed):
    """`removed` as whole UTXOs: the client takes them from its own set."""
    h = sum(map(utxo_hash, added)) - sum(map(utxo_hash, removed))
    return format(h % N, "064x")

def set_hash(utxos):
    return changes_hash(utxos, [])
```

Since it is a sum, the hash doesn't depend on the order of the UTXOs nor on how
the changes are split into chunks, and a wallet updates the hash of its set
without hashing the whole set again.

It detects lost, duplicated or mixed-up UTXOs (chunks of different replies).
It is not a proof against a dishonest server, which sends both the data and the
hashes; see [Trust](#trust).

## Methods

### `blockchain.scripthash.utxo_sync(scripthash, from_block=null)`

How the confirmed UTXO set of `scripthash` changed from block `from_block` (the
block of the wallet's set) to the current tip, and what the mempool does to it.
With `from_block` null, the changes are the whole set.

| Key | Value |
|-----|-------|
| `from_block` | the `from_block` asked for, when the reply holds the changes from it; `null` when the reply is the whole set, which **replaces** the wallet's set |
| `height`, `block_hash` | the current tip |
| `count`, `set_hash` | of the confirmed set at the tip |
| `chunks` | hashes of the chunks of changes, in order; there is always at least one |
| `id` | opaque string to pass to `utxo_chunk`; `null` when the changes are inline |
| `added`, `removed` | only when there is a single chunk: its changes |
| `mempool` | `{"added": [UTXOs], "spent": [{"tx_hash", "tx_pos"}]}` |

The changes are set differences: `removed` lists, as `{"tx_hash", "tx_pos"}`,
the UTXOs of the set at `from_block` that are not in the set at the tip, and
`added` the UTXOs of the set at the tip that were not in the set at
`from_block`. The chunks hold every removed outpoint first, then the added
UTXOs ordered by `(height, tx_hash, tx_pos)`; the server splits them so that
the JSON of each chunk is at most 128 KB (about 900 UTXOs).

The server answers the whole set (`"from_block": null`) when it can't give the
changes from `from_block`: the block is unknown to it, or older than the changes
it keeps. electrs-neurai gives the changes:

* for addresses paid in 10,000 blocks or more, from any of the last 43,200
  blocks (about 30 days) of their journal, or from the blocks it undid in a
  reorg (up to 100), so a wallet that stopped on such a block gets back to the
  active chain through ordinary changes. The journal starts when the server
  first builds the address' snapshot;
* for other addresses, from any block of the active chain (they are computed
  from the address' history).

The changes only depend on the chain, so a wallet can ask a different server
than the one it synced with.

With `from_block` equal to the tip, there are no changes (one empty chunk whose
hash is `"000…000"`) and only the mempool is new.

`mempool.added` lists the outputs of mempool transactions to the address that
no other mempool transaction spends; `mempool.spent` the UTXOs of the confirmed
set at the tip spent by mempool transactions. The wallet's spendable view is
the confirmed set without `mempool.spent`, plus `mempool.added`. The mempool
part is not split into chunks, like `get_mempool`.

### `blockchain.scripthash.utxo_chunk(scripthash, id, index)`

`{"added": [UTXOs], "removed": [{"tx_hash", "tx_pos"}]}` of chunk `index` (from
0) of the reply `id`.

New blocks don't change a reply: its chunks keep describing the changes up to
its `block_hash`. The server keeps them for at least 10 minutes after their last
use by `utxo_sync` or `utxo_chunk`; after that, or after a restart of the
server, it answers error 10. An `index` out of range is an invalid parameter.

### `blockchain.scripthash.utxo_subscribe(scripthash)`

Returns the status of `scripthash` and sends the notification

```json
{"method": "blockchain.scripthash.utxo_subscribe", "params": ["<scripthash>", "<status>"]}
```

whenever it changes, after a new block or a mempool update. The status is the
hash of the spendable view:

```
status = set_hash + Σ h(mempool.added) − Σ h(mempool.spent)     (mod 2²⁵⁶)
```

so the wallet computes it from its last `utxo_sync` and calls `utxo_sync` with
its `block_hash` when a notification brings a different one. Blocks that don't
change the address don't send notifications; the next `utxo_sync` still gets
their changes.

Unlike `blockchain.scripthash.subscribe`, it works for addresses of any size.

### `blockchain.scripthash.utxo_unsubscribe(scripthash)`

`true` when the scripthash was subscribed with `utxo_subscribe`, otherwise
`false`.

## Wallet

* Apply the chunks of a reply, in order, to a copy of the set: the removed
  outpoints first, then the added UTXOs. Check each chunk against its hash
  (taking the removed UTXOs from the copy), then `count` and
  `set_hash = old set_hash + Σ chunks` (the old one is `"000…000"` when
  `from_block` is `null`). Only then replace the set, its `block_hash`,
  `set_hash` and `count`. An interrupted download leaves the set as it was.
* Several `utxo_chunk` requests can be sent without waiting for each reply.
* On error 10, call `utxo_sync` again with the `block_hash` of the set.
* A check that fails means a broken reply: start again with `utxo_sync(sh, null)`
  or ask another server.

## Errors

| Code | Message | What the client does |
|------|---------|----------------------|
| 10 | `snapshot expired` | call `utxo_sync` again with the `block_hash` of its set |

Other errors are the usual ones (`1` for bad requests, `-32603` while the index
is being built).

## Limits

* Every reply is at most 128 KB, except the `mempool` part.
* The list of chunk hashes fits in 128 KB up to about 1,900 chunks, that is
  about 250 MB of UTXOs.

## Trust

The same as `listunspent`: the server could hide or invent UTXOs. Before
spending a UTXO a wallet can check that the output exists in a block of its
header chain with `blockchain.transaction.get` and
`blockchain.transaction.get_merkle`. That it is unspent can't be proven with the
Electrum protocol; a transaction spending a missing or spent output is rejected
by the network when broadcast.

## Example

```
→ {"id":1,"method":"blockchain.scripthash.utxo_subscribe","params":["8b01…"]}
← {"id":1,"result":"5c1e…"}
→ {"id":2,"method":"blockchain.scripthash.utxo_sync","params":["8b01…",null]}
← {"id":2,"result":{"from_block":null,"height":1234567,"block_hash":"0000…a1",
     "count":650312,"set_hash":"5c1e…","id":"f3a9…","chunks":["a1…","07…", …],
     "mempool":{"added":[],"spent":[]}}}
→ {"id":3,"method":"blockchain.scripthash.utxo_chunk","params":["8b01…","f3a9…",0]}
← {"id":3,"result":{"removed":[],"added":[{"height":120034,"tx_hash":"…","tx_pos":1,
     "value":5000000,"asset":null}, …]}}
   … chunks 1 to 709 …
← {"method":"blockchain.scripthash.utxo_subscribe","params":["8b01…","9d42…"]}
→ {"id":713,"method":"blockchain.scripthash.utxo_sync","params":["8b01…","0000…a1"]}
← {"id":713,"result":{"from_block":"0000…a1","height":1234568,"block_hash":"0000…b2",
     "count":650315,"set_hash":"9d42…","id":null,"chunks":["3f…"],
     "removed":[…],"added":[…],"mempool":{"added":[],"spent":[]}}}
```

## Server notes (electrs-neurai)

* The `UtxoSnapshot` of an address paid in 10,000 blocks or more reads every
  new block once for all clients, and writes down, block by block, the UTXOs
  added and removed (with all their data): its journal, stored in the DB with
  the snapshot (format 2). It answers `utxo_sync` from an old block, undoes
  reorgs without rebuilding the snapshot, and keeps the blocks that left the
  active chain. Its set hash is computed when first needed, then kept up to
  date.
* The changes of other addresses are computed from their history
  (`ScriptHashStatus`), and their mempool part from the mempool transactions
  read with it, so that both are of the same moment.
* Replies of more than one chunk are kept as sorted UTXOs with the chunk
  boundaries and hashes, by `(scripthash, from_block, tip)`, and shared by every
  client: until 10 minutes after their last use, the least recently used
  dropped first beyond 256 MB. The JSON of a chunk is written when it is
  requested.
* The mempool part is found from the mempool's spends or from the address'
  UTXOs, whichever are fewer. Outputs of mempool transactions that are already
  confirmed (the mempool is polled after a new block is indexed) are not listed.
* `utxo_subscribe` keeps no history per client for long histories: each block
  updates their shared snapshot once for all subscribers. Short histories are
  kept per subscription, like `blockchain.scripthash.subscribe`.
* Clients are limited per IP (see [config.md](config.md#limits-per-ip)): one
  wallet downloading a 90 MB set is not slowed down, but many at once from the
  same IP are.

## Not in this version

* The history in chunks, which needs an index of the history by address.
* Resuming a first download whose chunks expired: the wallet starts it again.
