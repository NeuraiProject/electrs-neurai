use anyhow::Result;
use bitcoin::{
    hashes::{sha256, Hash, HashEngine},
    Amount, BlockHash, OutPoint, Transaction, Txid,
};
use rayon::prelude::*;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::neurai::{
    asset::{effective_script, parse_asset_script, AssetData},
    tx, NetworkParams,
};

use std::convert::TryFrom;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::ControlFlow,
};

use crate::{
    cache::Cache,
    chain::Chain,
    daemon::Daemon,
    index::Index,
    mempool::Mempool,
    types::{ScriptHash, SerBlock, StatusHash},
};

/// Given a scripthash, store relevant inputs and outputs of a specific transaction
struct TxEntry {
    txid: Txid,
    outputs: Vec<TxOutput>, // relevant funded outputs and their amounts
    spent: Vec<OutPoint>,   // relevant spent outpoints
}

// Funded outputs of a transaction.
//
// `value` is always the XNA satoshi value from the txout (the dust value on
// asset-wrapped outputs, the full native amount otherwise). `asset` carries
// the parsed asset payload when present — used by commit 4 onward to compute
// per-asset balance and unspent.
struct TxOutput {
    index: u32,
    value: Amount,
    #[allow(dead_code)] // read by per-asset Balance/UnspentEntry in commit 4
    asset: Option<AssetTxOutput>,
}

/// Asset metadata attached to a `TxOutput`. `amount` is in the asset's own
/// minimum units (mirrors the daemon: `OWNER_ASSET_AMOUNT = 1 * COIN`, transfer
/// amounts already in min-units).
//
// Fields are read by per-asset balance/unspent logic in commit 4. Silenced
// here so the intermediate commit builds without dead_code warnings.
#[derive(Clone)]
#[allow(dead_code)]
struct AssetTxOutput {
    name: String,
    amount: u64,
}

/// Extract `(name, amount_in_min_units)` from a parsed asset output.
/// Returns `None` if the amount is invalid (negative or doesn't fit `u64`).
/// We intentionally do NOT normalize with `abs()` — a negative amount is a
/// data corruption signal, not something to mask.
fn asset_tx_output_of(data: &AssetData) -> Option<AssetTxOutput> {
    let (name, amount_i64) = match data {
        AssetData::New(a) => (a.name.clone(), a.amount),
        AssetData::Transfer(a) => (a.name.clone(), a.amount),
        AssetData::Reissue(a) => (a.name.clone(), a.amount),
        // Owner tokens have no `amount` field in the script — the daemon's
        // OWNER_ASSET_AMOUNT (= 1 * COIN = 100_000_000) is implicit.
        AssetData::Owner(a) => (a.name.clone(), 100_000_000_i64),
    };
    let amount = u64::try_from(amount_i64).ok()?;
    Some(AssetTxOutput { name, amount })
}

impl TxEntry {
    fn new(txid: Txid) -> Self {
        Self {
            txid,
            outputs: Vec::new(),
            spent: Vec::new(),
        }
    }

    /// Relevant (scripthash-wise) funded outpoints
    fn funding_outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        make_outpoints(self.txid, &self.outputs)
    }
}

// Confirmation height of a transaction or its mempool state:
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-history
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-mempool
enum Height {
    Confirmed { height: usize },
    Unconfirmed { has_unconfirmed_inputs: bool },
}

impl Height {
    fn as_i64(&self) -> i64 {
        match self {
            Self::Confirmed { height } => i64::try_from(*height).unwrap(),
            Self::Unconfirmed {
                has_unconfirmed_inputs: true,
            } => -1,
            Self::Unconfirmed {
                has_unconfirmed_inputs: false,
            } => 0,
        }
    }
}

impl Serialize for Height {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.as_i64())
    }
}

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_i64().fmt(f)
    }
}

// A single history entry:
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-history
// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-mempool
#[derive(Serialize)]
pub(crate) struct HistoryEntry {
    #[serde(rename = "tx_hash")]
    txid: Txid,
    height: Height,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "bitcoin::amount::serde::as_sat::opt"
    )]
    fee: Option<Amount>,
}

impl HistoryEntry {
    // Hash to compute ScriptHash status, as defined here:
    // https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#status
    fn hash(&self, engine: &mut sha256::HashEngine) {
        let s = format!("{}:{}:", self.txid, self.height);
        engine.input(s.as_bytes());
    }

    pub(crate) fn is_unconfirmed(&self) -> bool {
        matches!(self.height, Height::Unconfirmed { .. })
    }

    fn confirmed(txid: Txid, height: usize) -> Self {
        Self {
            txid,
            height: Height::Confirmed { height },
            fee: None,
        }
    }

    fn unconfirmed(txid: Txid, has_unconfirmed_inputs: bool, fee: Amount) -> Self {
        Self {
            txid,
            height: Height::Unconfirmed {
                has_unconfirmed_inputs,
            },
            fee: Some(fee),
        }
    }
}

/// ScriptHash subscription status
pub struct ScriptHashStatus {
    scripthash: ScriptHash, // specific scripthash to be queried
    tip: BlockHash,         // used for skipping confirmed entries' sync
    confirmed: HashMap<BlockHash, Vec<TxEntry>>, // confirmed entries, partitioned per block (may contain stale blocks)
    mempool: Vec<TxEntry>,                       // unconfirmed entries
    history: Vec<HistoryEntry>,                  // computed from confirmed and mempool entries
    statushash: Option<StatusHash>,              // computed from history
}

/// Key used in per-asset balance maps. `"rvn"` is the conventional name for
/// native XNA balance — kept from the Ravencoin fork at protocol level
/// (also matches the `ASSET_MAGIC = b"rvn"` in the asset wire format).
pub(crate) const NATIVE_ASSET_KEY: &str = "rvn";

/// Per-asset balance entry. Both fields are in the asset's own minimum units
/// (sats for XNA, `OWNER_ASSET_AMOUNT`-style units for assets). Widened to
/// `i128` because asset amounts are `i64` and the unconfirmed delta is the
/// signed difference of two `i64` sums — which can overflow `i64`.
#[derive(Default, Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) struct AssetBalance {
    pub confirmed: i128,
    pub unconfirmed: i128,
}

/// Specific scripthash balance, grouped by asset (key `"rvn"` for native).
///
/// Serializes with the *legacy single-asset* shape (`{"confirmed": N,
/// "unconfirmed": M}` from the `"rvn"` entry) for backward compatibility with
/// pre-asset clients. Commit 5 introduces the `asset` request parameter that
/// switches to the multi-asset map shape (`{"rvn": {...}, "TOKEN": {...}}`).
///
/// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-get-balance
#[derive(Default, Eq, PartialEq, Debug)]
pub(crate) struct Balance {
    pub by_asset: BTreeMap<String, AssetBalance>,
}

impl Balance {
    /// Native (XNA) entry, or zeroes if no native UTXOs exist.
    pub fn native(&self) -> AssetBalance {
        self.by_asset
            .get(NATIVE_ASSET_KEY)
            .copied()
            .unwrap_or_default()
    }
}

impl Serialize for Balance {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Legacy wire shape: emit just the native entry. The multi-asset shape
        // is built explicitly by the Electrum handler when the caller passes
        // `asset=True` / list (commit 5).
        let native = self.native();
        let mut state = serializer.serialize_struct("Balance", 2)?;
        state.serialize_field("confirmed", &(native.confirmed as i64))?;
        state.serialize_field("unconfirmed", &(native.unconfirmed as i64))?;
        state.end()
    }
}

/// A single unspent transaction output entry.
///
/// Wire shape (ElectrumX-neurai compatible):
/// - native: `{"tx_hash":..., "tx_pos":..., "height":..., "value":<xna_sats>, "asset": null}`
/// - asset:  `{"tx_hash":..., "tx_pos":..., "height":..., "value":<asset_units>, "asset": "TOKEN"}`
///
/// `asset` is *always* serialized — `null` for native — so wallets can
/// distinguish the two cases without ambiguity.
///
/// https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#blockchain-scripthash-listunspent
#[derive(Serialize, Debug)]
pub(crate) struct UnspentEntry {
    height: usize, // 0 = mempool entry
    tx_hash: Txid,
    tx_pos: u32,
    /// XNA satoshis when `asset.is_none()`, asset min-units when `asset.is_some()`.
    value: u64,
    /// `None` for native UTXOs, asset name for asset-wrapped UTXOs.
    /// Always serialized (no `skip_serializing_if`) — matches ElectrumX shape.
    asset: Option<String>,
}

impl UnspentEntry {
    /// Asset name for this UTXO, or `None` if it's a native XNA UTXO.
    pub fn asset(&self) -> Option<&str> {
        self.asset.as_deref()
    }
}

#[derive(Default)]
struct OutputInfo {
    height: usize,
    /// XNA sats for native, asset min-units for asset outputs.
    value: u64,
    /// `None` for native, `Some(name)` for asset outputs.
    asset: Option<String>,
    /// Insertion order: confirmed transactions are inserted in chain order,
    /// then mempool ones — the order ElectrumX lists UTXOs in.
    seq: usize,
}

#[derive(Default)]
struct Unspent {
    // mapping an outpoint to its (value, height, asset) tuple
    outpoints: HashMap<OutPoint, OutputInfo>,
    balance: Balance,
    next_seq: usize,
}

impl Unspent {
    fn build(status: &ScriptHashStatus, chain: &Chain) -> Self {
        let mut unspent = Unspent::default();
        // First, add all relevant entries' funding outputs to the outpoints' map,
        // in chain order (entries are already sorted by position within a block).
        status
            .confirmed_height_entries(chain)
            .collect::<BTreeMap<usize, &[TxEntry]>>()
            .into_iter()
            .for_each(|(height, entries)| entries.iter().for_each(|e| unspent.insert(e, height)));
        // Then, remove spent outpoints from the map
        status
            .confirmed_entries(chain)
            .for_each(|e| unspent.remove(e));

        let confirmed = unspent.balance_by_asset();
        // Apply mempool effects (first fundings, then spends).
        status.mempool.iter().for_each(|e| unspent.insert(e, 0)); // mempool height = 0
        status.mempool.iter().for_each(|e| unspent.remove(e));

        let total = unspent.balance_by_asset();

        // Build per-asset confirmed + unconfirmed-delta map. Keys union of
        // both maps so we capture assets that exist only confirmed (negative
        // delta if spent in mempool) or only in mempool (zero confirmed).
        let keys: std::collections::BTreeSet<&String> =
            confirmed.keys().chain(total.keys()).collect();
        let mut by_asset: BTreeMap<String, AssetBalance> = BTreeMap::new();
        for key in keys {
            let c = *confirmed.get(key).unwrap_or(&0);
            let t = *total.get(key).unwrap_or(&0);
            by_asset.insert(
                key.clone(),
                AssetBalance {
                    confirmed: c,
                    unconfirmed: t - c,
                },
            );
        }
        unspent.balance = Balance { by_asset };
        unspent
    }

    /// UTXOs in ElectrumX order: confirmed by (height, position in block,
    /// output index), then mempool. Zero-value outputs are not listed
    /// (ElectrumX `db.all_utxos` skips them).
    fn into_entries(self) -> Vec<UnspentEntry> {
        let mut outpoints: Vec<(OutPoint, OutputInfo)> = self.outpoints.into_iter().collect();
        outpoints.sort_by_key(|(outpoint, info)| (info.seq, outpoint.vout));
        outpoints
            .into_iter()
            .filter(|(_, info)| info.value > 0)
            .map(|(outpoint, info)| UnspentEntry {
                height: info.height,
                tx_hash: outpoint.txid,
                tx_pos: outpoint.vout,
                value: info.value,
                asset: info.asset,
            })
            .collect()
    }

    /// Sum of unspent values grouped by asset (key `"rvn"` for native).
    fn balance_by_asset(&self) -> BTreeMap<String, i128> {
        let mut map: BTreeMap<String, i128> = BTreeMap::new();
        // Zero-value outputs carry no balance and ElectrumX doesn't report a key for them.
        for info in self.outpoints.values().filter(|info| info.value > 0) {
            let key = info
                .asset
                .clone()
                .unwrap_or_else(|| NATIVE_ASSET_KEY.to_string());
            *map.entry(key).or_insert(0_i128) += info.value as i128;
        }
        map
    }

    fn insert(&mut self, entry: &TxEntry, height: usize) {
        let seq = self.next_seq;
        self.next_seq += 1;
        for output in &entry.outputs {
            let outpoint = OutPoint {
                txid: entry.txid,
                vout: output.index,
            };
            // Asset-wrapped output: value = asset min-units, asset = Some(name).
            // The XNA dust on an asset output is intentionally dropped — the
            // dust is locked with the asset and not separately spendable
            // (matches ElectrumX-neurai).
            // Native output: value = XNA sats, asset = None.
            let info = match &output.asset {
                Some(a) => OutputInfo {
                    height,
                    value: a.amount,
                    asset: Some(a.name.clone()),
                    seq,
                },
                None => OutputInfo {
                    height,
                    value: output.value.to_sat(),
                    asset: None,
                    seq,
                },
            };
            self.outpoints.insert(outpoint, info);
        }
    }

    fn remove(&mut self, entry: &TxEntry) {
        for spent in &entry.spent {
            self.outpoints.remove(spent);
        }
    }
}

impl ScriptHashStatus {
    /// Return non-synced (empty) status for a given script hash.
    pub fn new(scripthash: ScriptHash) -> Self {
        Self {
            scripthash,
            tip: BlockHash::all_zeros(),
            confirmed: HashMap::new(),
            mempool: Vec::new(),
            history: Vec::new(),
            statushash: None,
        }
    }

    /// Iterate through confirmed TxEntries with their corresponding block heights.
    /// Skip entries from stale blocks.
    fn confirmed_height_entries<'a>(
        &'a self,
        chain: &'a Chain,
    ) -> impl Iterator<Item = (usize, &'a [TxEntry])> + 'a {
        self.confirmed
            .iter()
            .filter_map(move |(blockhash, entries)| {
                chain
                    .get_block_height(blockhash)
                    .map(|height| (height, &entries[..]))
            })
    }

    /// Iterate through confirmed TxEntries.
    /// Skip entries from stale blocks.
    fn confirmed_entries<'a>(&'a self, chain: &'a Chain) -> impl Iterator<Item = &'a TxEntry> + 'a {
        self.confirmed_height_entries(chain)
            .flat_map(|(_height, entries)| entries)
    }

    /// Collect all funded and confirmed outpoints (as a set).
    fn confirmed_outpoints(&self, chain: &Chain) -> HashSet<OutPoint> {
        self.confirmed_entries(chain)
            .flat_map(TxEntry::funding_outpoints)
            .collect()
    }

    /// Collect unspent transaction entries
    pub(crate) fn get_unspent(&self, chain: &Chain) -> Vec<UnspentEntry> {
        Unspent::build(self, chain).into_entries()
    }

    /// Collect unspent transaction balance
    pub(crate) fn get_balance(&self, chain: &Chain) -> Balance {
        Unspent::build(self, chain).balance
    }

    /// Collect transaction history entries
    pub(crate) fn get_history(&self) -> &[HistoryEntry] {
        &self.history
    }

    /// Collect all confirmed history entries (in block order).
    fn get_confirmed_history(&self, chain: &Chain) -> Vec<HistoryEntry> {
        self.confirmed_height_entries(chain)
            .collect::<BTreeMap<usize, &[TxEntry]>>()
            .into_iter()
            .flat_map(|(height, entries)| {
                entries
                    .iter()
                    .map(move |e| HistoryEntry::confirmed(e.txid, height))
            })
            .collect()
    }

    /// Collect all mempool history entries (keeping transactions with unconfirmed parents last).
    fn get_mempool_history(&self, mempool: &Mempool) -> Vec<HistoryEntry> {
        let mut entries = self
            .mempool
            .iter()
            .filter_map(|e| mempool.get(&e.txid))
            .collect::<Vec<_>>();
        entries.sort_by_key(|e| (e.has_unconfirmed_inputs, e.txid));
        entries
            .into_iter()
            .map(|e| HistoryEntry::unconfirmed(e.txid, e.has_unconfirmed_inputs, e.fee))
            .collect()
    }

    /// Apply `func` only on the new blocks (to be fetched via p2p interface).
    fn for_new_blocks<B, F>(&self, blockhashes: B, daemon: &Daemon, func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        daemon.for_blocks(
            blockhashes
                .into_iter()
                .filter(|blockhash| !self.confirmed.contains_key(blockhash)),
            func,
        )
    }

    /// Get funding and spending entries from new blocks.
    /// Also cache relevant transactions and their merkle proofs.
    fn sync_confirmed(
        &self,
        index: &Index,
        daemon: &Daemon,
        cache: &Cache,
        outpoints: &mut HashSet<OutPoint>,
    ) -> Result<HashMap<BlockHash, Vec<TxEntry>>> {
        let params = index.chain().params();
        let fork_active = |blockhash: &BlockHash| {
            index
                .chain()
                .get_block_height(blockhash)
                .is_some_and(|height| params.fork_active(height))
        };

        // Will be updated during the following block scans
        let mut result = HashMap::<BlockHash, HashMap<usize, TxEntry>>::new();

        let funding_blockhashes = index.limit_result(index.filter_by_funding(self.scripthash))?;
        self.for_new_blocks(funding_blockhashes, daemon, |blockhash, block| {
            let block_entries = result.entry(blockhash).or_default();

            let fork = fork_active(&blockhash);
            for filtered_outputs in filter_block_txs_outputs(block, self.scripthash, params, fork) {
                cache.add_tx(filtered_outputs.txid, move || filtered_outputs.tx_bytes);
                outpoints.extend(make_outpoints(
                    filtered_outputs.txid,
                    &filtered_outputs.result,
                ));
                block_entries
                    .entry(filtered_outputs.pos)
                    .or_insert_with(|| TxEntry::new(filtered_outputs.txid))
                    .outputs = filtered_outputs.result;
            }
        })?;
        let spending_blockhashes: HashSet<BlockHash> = outpoints
            .par_iter()
            .flat_map_iter(|outpoint| index.filter_by_spending(*outpoint))
            .collect();
        self.for_new_blocks(spending_blockhashes, daemon, |blockhash, block| {
            let block_entries = result.entry(blockhash).or_default();

            for filtered_inputs in filter_block_txs_inputs(&block, outpoints, params) {
                cache.add_tx(filtered_inputs.txid, move || filtered_inputs.tx_bytes);
                block_entries
                    .entry(filtered_inputs.pos)
                    .or_insert_with(|| TxEntry::new(filtered_inputs.txid))
                    .spent = filtered_inputs.result;
            }
        })?;

        Ok(result
            .into_iter()
            .map(|(blockhash, entries_map)| {
                let sorted_entries: Vec<TxEntry> = entries_map
                    .into_iter()
                    .collect::<BTreeMap<usize, TxEntry>>() // sort transactions by their position in a block
                    .into_values() // drop position within block
                    .collect();
                (blockhash, sorted_entries)
            })
            .collect())
    }

    /// Get funding and spending entries from current mempool.
    /// Also cache relevant transactions.
    fn sync_mempool(
        &self,
        mempool: &Mempool,
        cache: &Cache,
        outpoints: &mut HashSet<OutPoint>,
    ) -> Vec<TxEntry> {
        let mut result = HashMap::<Txid, TxEntry>::new();
        // extract relevant funding transactions
        for entry in mempool.filter_by_funding(&self.scripthash) {
            let funding_outputs = filter_outputs(&entry.tx, self.scripthash, entry.fork);
            assert!(!funding_outputs.is_empty());
            // store funded outpoints (to check for spending later)
            outpoints.extend(make_outpoints(entry.txid, &funding_outputs));
            result
                .entry(entry.txid) // the transaction may already exist
                .or_insert_with(|| TxEntry::new(entry.txid))
                .outputs = funding_outputs;
            cache.add_tx(entry.txid, || entry.raw.clone());
        }
        for entry in outpoints
            .iter()
            .flat_map(|outpoint| mempool.filter_by_spending(outpoint))
        {
            let spent_outpoints = filter_inputs(&entry.tx, outpoints);
            assert!(!spent_outpoints.is_empty());
            result
                .entry(entry.txid) // the transaction may already exist
                .or_insert_with(|| TxEntry::new(entry.txid))
                .spent = spent_outpoints;
            cache.add_tx(entry.txid, || entry.raw.clone());
        }
        result.into_values().collect()
    }

    /// Sync with currently confirmed txs and mempool, downloading non-cached transactions via p2p protocol.
    /// After a successful sync, script-hash status is updated.
    pub(crate) fn sync(
        &mut self,
        index: &Index,
        mempool: &Mempool,
        daemon: &Daemon,
        cache: &Cache,
    ) -> Result<()> {
        let mut outpoints: HashSet<OutPoint> = self.confirmed_outpoints(index.chain());

        let new_tip = index.chain().tip();
        if self.tip != new_tip {
            let update = self.sync_confirmed(index, daemon, cache, &mut outpoints)?;
            self.confirmed.extend(update); // add new blocks to the map
            self.tip = new_tip;
        }
        if !self.confirmed.is_empty() {
            debug!(
                "{} transactions from {} blocks",
                self.confirmed.values().map(Vec::len).sum::<usize>(),
                self.confirmed.len()
            );
        }
        self.mempool = self.sync_mempool(mempool, cache, &mut outpoints);
        if !self.mempool.is_empty() {
            debug!("{} mempool transactions", self.mempool.len());
        }
        // update history entries and status hash
        self.history.clear();
        self.history
            .extend(self.get_confirmed_history(index.chain()));
        self.history.extend(self.get_mempool_history(mempool));

        self.statushash = compute_status_hash(&self.history);
        Ok(())
    }

    /// Get current status hash.
    pub fn statushash(&self) -> Option<StatusHash> {
        self.statushash
    }
}

fn make_outpoints(txid: Txid, outputs: &[TxOutput]) -> impl Iterator<Item = OutPoint> + '_ {
    outputs
        .iter()
        .map(move |out| OutPoint::new(txid, out.index))
}

fn filter_outputs(tx: &Transaction, scripthash: ScriptHash, fork: bool) -> Vec<TxOutput> {
    let outputs = tx.output.iter().zip(0u32..);
    outputs
        .filter_map(move |(txo, vout)| {
            // Match against the effective scripthash so asset-wrapped outputs
            // (whose full-script hash differs from the bare-address hash) are
            // attributed to the subscriber's bare address. See `effective_script`.
            let bytes = txo.script_pubkey.as_bytes();
            if ScriptHash::hash(&effective_script(bytes, fork)) == scripthash {
                let asset = parse_asset_script(bytes, fork).and_then(|a| asset_tx_output_of(&a.data));
                Some(TxOutput {
                    index: vout,
                    value: txo.value,
                    asset,
                })
            } else {
                None
            }
        })
        .collect()
}

fn filter_inputs(tx: &Transaction, outpoints: &HashSet<OutPoint>) -> Vec<OutPoint> {
    tx.input
        .iter()
        .filter_map(|txi| {
            if outpoints.contains(&txi.previous_output) {
                Some(txi.previous_output)
            } else {
                None
            }
        })
        .collect()
}

// See https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#status for details
fn compute_status_hash(history: &[HistoryEntry]) -> Option<StatusHash> {
    if history.is_empty() {
        return None;
    }
    let mut engine = StatusHash::engine();
    for entry in history {
        entry.hash(&mut engine);
    }
    Some(StatusHash::from_engine(engine))
}

struct FilteredTx<T> {
    tx_bytes: Box<[u8]>,
    txid: Txid,
    pos: usize,
    result: Vec<T>,
}

fn filter_block_txs_outputs(
    block: SerBlock,
    scripthash: ScriptHash,
    params: &'static NetworkParams,
    fork: bool,
) -> Vec<FilteredTx<TxOutput>> {
    // `tx::visit_block` calls `visit_tx_out` for every output of a transaction
    // and only then `visit_transaction` for that same transaction (its txid
    // needs the fully parsed slice). Matches are buffered and attributed to the
    // transaction passed to the following `visit_transaction` call.
    struct FindOutputs {
        scripthash: ScriptHash,
        fork: bool,
        result: Vec<FilteredTx<TxOutput>>,
        buffer: Vec<TxOutput>,
        pos: usize,
    }
    impl tx::Visitor for FindOutputs {
        fn visit_transaction(&mut self, tx: &tx::Transaction) -> ControlFlow<()> {
            if !self.buffer.is_empty() {
                self.result.push(FilteredTx::<TxOutput> {
                    tx_bytes: tx.as_bytes().into(),
                    txid: tx.txid(),
                    pos: self.pos,
                    result: std::mem::take(&mut self.buffer),
                });
            }
            self.pos += 1;
            ControlFlow::Continue(())
        }
        fn visit_tx_out(&mut self, vout: usize, tx_out: &tx::TxOut) -> ControlFlow<()> {
            // Use the effective scripthash (base script for asset-wrapped
            // outputs) so the subscriber's bare-address hash matches.
            let bytes = tx_out.script_pubkey();
            let current = ScriptHash::hash(&effective_script(bytes, self.fork));
            if current == self.scripthash {
                let asset = parse_asset_script(bytes, self.fork).and_then(|a| asset_tx_output_of(&a.data));
                self.buffer.push(TxOutput {
                    index: vout as u32,
                    value: Amount::from_sat(tx_out.value()),
                    asset,
                })
            }
            ControlFlow::Continue(())
        }
    }
    let mut find_outputs = FindOutputs {
        scripthash,
        fork,
        result: vec![],
        buffer: vec![],
        pos: 0,
    };
    // never stops early
    let _ = tx::visit_block(&block, params, &mut find_outputs).expect("core returned invalid block");
    find_outputs.result
}

fn filter_block_txs_inputs(
    block: &SerBlock,
    outpoints: &HashSet<OutPoint>,
    params: &'static NetworkParams,
) -> Vec<FilteredTx<OutPoint>> {
    // Same visiting order as in `filter_block_txs_outputs`: inputs first, then
    // `visit_transaction` for the transaction that owns them.
    struct FindInputs<'a> {
        outpoints: &'a HashSet<OutPoint>,
        result: Vec<FilteredTx<OutPoint>>,
        buffer: Vec<OutPoint>,
        pos: usize,
    }

    impl tx::Visitor for FindInputs<'_> {
        fn visit_transaction(&mut self, tx: &tx::Transaction) -> ControlFlow<()> {
            if !self.buffer.is_empty() {
                self.result.push(FilteredTx::<OutPoint> {
                    tx_bytes: tx.as_bytes().into(),
                    txid: tx.txid(),
                    pos: self.pos,
                    result: std::mem::take(&mut self.buffer),
                });
            }
            self.pos += 1;
            ControlFlow::Continue(())
        }
        fn visit_tx_in(&mut self, _vin: usize, tx_in: &tx::TxIn) -> ControlFlow<()> {
            let current: OutPoint = tx_in.prevout();
            if self.outpoints.contains(&current) {
                self.buffer.push(current);
            }
            ControlFlow::Continue(())
        }
    }

    let mut find_inputs = FindInputs {
        outpoints,
        result: vec![],
        buffer: vec![],
        pos: 0,
    };
    // never stops early
    let _ = tx::visit_block(block, params, &mut find_inputs).expect("core returned invalid block");
    find_inputs.result
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr};

    use crate::neurai::{NeuraiNetwork, NetworkParams};
    use crate::types::ScriptHash;

    use super::HistoryEntry;
    use bitcoin::{Address, Amount};
    use bitcoin_test_data::blocks::mainnet_702861;
    use serde_json::json;

    fn testnet_params() -> &'static NetworkParams {
        NetworkParams::for_network(NeuraiNetwork::Testnet)
    }

    #[test]
    fn test_txinfo_json() {
        let txid = "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b"
            .parse()
            .unwrap();
        assert_eq!(
            json!(HistoryEntry::confirmed(txid, 123456)),
            json!({"tx_hash": "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b", "height": 123456})
        );
        assert_eq!(
            json!(HistoryEntry::unconfirmed(txid, true, Amount::from_sat(123))),
            json!({"tx_hash": "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b", "height": -1, "fee": 123})
        );
        assert_eq!(
            json!(HistoryEntry::unconfirmed(txid, false, Amount::from_sat(123))),
            json!({"tx_hash": "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b", "height": 0, "fee": 123})
        );
    }

    #[test]
    fn test_find_outputs() {
        // Bitcoin mainnet_702861 has an 80-byte header — valid as a pre-KAWPOW block
        // under testnet params (kawpow_activation_time = 0xFFFFFFFF).
        let block = mainnet_702861().to_vec();
        let params = testnet_params();

        let addr = Address::from_str("1A9MXXG26vZVySrNNytQK1N8bX42ZuJ6Ax")
            .unwrap()
            .assume_checked();
        let scripthash = ScriptHash::new(&addr.script_pubkey());

        let result = &super::filter_block_txs_outputs(block, scripthash, params, false)[0];
        // The matching output is in transaction index 8 (see
        // `test_filters_attribute_matches_to_their_own_tx` for a full cross-check).
        assert_eq!(
            result.txid.to_string(),
            "7bcdcb44422da5a99daad47d6ba1c3d6f2e48f961a75e42c4fa75029d4b0ef49"
        );
        assert_eq!(result.pos, 8);
        assert_eq!(result.result[0].index, 0);
        assert_eq!(result.result[0].value.to_sat(), 709503);
    }

    #[test]
    fn test_find_inputs() {
        let block = mainnet_702861().to_vec();
        let params = testnet_params();
        let outpoint = bitcoin::OutPoint::from_str(
            "cc135e792b37a9c4ffd784f696b1e38bd1197f8e67ae1f96c9f13e4618b91866:3",
        )
        .unwrap();
        let mut outpoints = HashSet::new();
        outpoints.insert(outpoint);

        let result = &super::filter_block_txs_inputs(&block, &outpoints, params)[0];
        assert_eq!(
            result.txid.to_string(),
            "7bcdcb44422da5a99daad47d6ba1c3d6f2e48f961a75e42c4fa75029d4b0ef49"
        );
        assert_eq!(result.pos, 8);
        assert_eq!(result.result[0], outpoint);
    }

    /// Cross-check both block filters against a full `rust-bitcoin` decode of
    /// the same block: every output and every spent outpoint must be reported
    /// with the txid and position of the transaction that really contains it.
    fn assert_filters_match_full_decode(block_bytes: &[u8], params: &'static NetworkParams) {
        use bitcoin::consensus::deserialize;
        use bitcoin::hashes::Hash;
        let block: bitcoin::Block = deserialize(block_bytes).expect("80-byte header block");
        for (pos, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            for (vout, out) in tx.output.iter().enumerate() {
                let sh = ScriptHash::hash(&crate::neurai::asset::effective_script(
                    out.script_pubkey.as_bytes(),
                    false,
                ));
                let found = super::filter_block_txs_outputs(block_bytes.to_vec(), sh, params, false);
                assert!(
                    found.iter().any(|f| f.txid == txid
                        && f.pos == pos
                        && f.result.iter().any(|o| o.index == vout as u32)),
                    "output {txid}:{vout} (tx #{pos}) not attributed to its own tx"
                );
            }
            for input in tx.input.iter().filter(|i| !i.previous_output.is_null()) {
                let outpoints = HashSet::from([input.previous_output]);
                let found = super::filter_block_txs_inputs(&block_bytes.to_vec(), &outpoints, params);
                assert_eq!(found.len(), 1);
                assert_eq!((found[0].txid, found[0].pos), (txid, pos));
            }
        }
    }

    #[test]
    fn test_filters_attribute_matches_to_their_own_tx() {
        assert_filters_match_full_decode(mainnet_702861(), testnet_params());
    }

    /// Regtest block 1101 mined by neuraid v1.0.7 (80-byte pre-KAWPOW header),
    /// with asset issuance outputs including an OP_PUSHDATA1 payload.
    #[test]
    fn test_filters_on_real_neurai_v107_block() {
        use bitcoin::hashes::{hex::FromHex, Hash};
        let hex = include_str!("../tests/fixtures/neurai-v1.0.7-regtest-block-1101.hex");
        let block = Vec::<u8>::from_hex(hex.trim()).unwrap();
        let params = NetworkParams::for_network(NeuraiNetwork::Regtest);
        assert_filters_match_full_decode(&block, params);

        // tx #2 vout 0 pays this P2PKH and nothing else in the block does.
        let spk = Vec::<u8>::from_hex("76a914528f02193798914da2e61e5ab15b2c516436a29f88ac").unwrap();
        let found = super::filter_block_txs_outputs(block, ScriptHash::hash(&spk), params, false);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].txid.to_string(),
            "0218cb7e8ca0abdc7c9066660a0a183c64e8370522c34622dbf0d160307157d2"
        );
        assert_eq!(found[0].pos, 2);
    }

    // ─── asset_tx_output_of ─────────────────────────────────────────────────

    #[test]
    fn asset_tx_output_of_transfer_positive() {
        use crate::neurai::asset::{AssetData, TransferAsset};

        let data = AssetData::Transfer(TransferAsset {
            name: "TOKEN".into(),
            amount: 5_000_000_000,
            message: None,
        });
        let out = super::asset_tx_output_of(&data).expect("positive amount accepted");
        assert_eq!(out.name, "TOKEN");
        assert_eq!(out.amount, 5_000_000_000);
    }

    #[test]
    fn asset_tx_output_of_negative_amount_rejected() {
        use crate::neurai::asset::{AssetData, TransferAsset};

        // A negative amount is a data-corruption signal — must produce None,
        // NOT be normalized with abs(). This preserves the anomaly instead of
        // silently treating a corrupt asset as a positive balance.
        let data = AssetData::Transfer(TransferAsset {
            name: "TOKEN".into(),
            amount: -1,
            message: None,
        });
        assert!(super::asset_tx_output_of(&data).is_none());
    }

    #[test]
    fn asset_tx_output_of_owner_uses_implicit_amount() {
        use crate::neurai::asset::{AssetData, OwnerAsset};

        let data = AssetData::Owner(OwnerAsset {
            name: "TOKEN!".into(),
        });
        let out = super::asset_tx_output_of(&data).expect("owner token always valid");
        assert_eq!(out.name, "TOKEN!");
        // OWNER_ASSET_AMOUNT = 1 * COIN = 100_000_000 (mirrors src/assets/assets.h:36)
        assert_eq!(out.amount, 100_000_000);
    }

    // ─── Balance / UnspentEntry wire shape ────────────────────────────────────

    #[test]
    fn balance_legacy_wire_shape_native_only() {
        use super::{AssetBalance, Balance, NATIVE_ASSET_KEY};
        use std::collections::BTreeMap;

        let mut by_asset = BTreeMap::new();
        by_asset.insert(
            NATIVE_ASSET_KEY.to_string(),
            AssetBalance {
                confirmed: 12_345,
                unconfirmed: -200,
            },
        );
        by_asset.insert(
            "TOKEN".to_string(),
            AssetBalance {
                confirmed: 99_999,
                unconfirmed: 0,
            },
        );
        let balance = Balance { by_asset };

        // Legacy single-asset wire shape: only the native (rvn) entry is exposed
        // by Balance::serialize. Multi-asset shape is built explicitly in the
        // electrum handler when the caller asks for it (commit 5).
        assert_eq!(
            json!(balance),
            json!({"confirmed": 12_345, "unconfirmed": -200})
        );
    }

    #[test]
    fn balance_legacy_wire_shape_empty() {
        // No UTXOs anywhere → zero balance, never missing fields.
        let balance = super::Balance::default();
        assert_eq!(json!(balance), json!({"confirmed": 0, "unconfirmed": 0}));
    }

    #[test]
    fn unspent_entry_serializes_asset_always_present_null_for_native() {
        use super::UnspentEntry;

        let entry_native = UnspentEntry {
            height: 100,
            tx_hash: "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            tx_pos: 0,
            value: 1_000_000,
            asset: None,
        };
        // Native: `asset` is `null` and `value` is XNA sats.
        assert_eq!(
            json!(entry_native),
            json!({
                "height": 100,
                "tx_hash": "0000000000000000000000000000000000000000000000000000000000000001",
                "tx_pos": 0,
                "value": 1_000_000,
                "asset": null,
            })
        );

        let entry_asset = UnspentEntry {
            height: 100,
            tx_hash: "0000000000000000000000000000000000000000000000000000000000000002"
                .parse()
                .unwrap(),
            tx_pos: 1,
            value: 5_000,
            asset: Some("TOKEN".into()),
        };
        // Asset: `asset` is the name, `value` is in the asset's own min-units.
        assert_eq!(
            json!(entry_asset),
            json!({
                "height": 100,
                "tx_hash": "0000000000000000000000000000000000000000000000000000000000000002",
                "tx_pos": 1,
                "value": 5_000,
                "asset": "TOKEN",
            })
        );
    }

    #[test]
    fn asset_tx_output_of_new_and_reissue() {
        use crate::neurai::asset::{AssetData, NewAsset, ReissueAsset};

        let new = AssetData::New(NewAsset {
            name: "MYCOIN".into(),
            amount: 21_000_000 * 100_000_000,
            units: 8,
            reissuable: true,
            ipfs: None,
        });
        let out = super::asset_tx_output_of(&new).unwrap();
        assert_eq!(out.amount, 21_000_000 * 100_000_000);

        let reissue = AssetData::Reissue(ReissueAsset {
            name: "MYCOIN".into(),
            amount: 1_000,
            units: 8,
            reissuable: false,
            ipfs: None,
        });
        let out = super::asset_tx_output_of(&reissue).unwrap();
        assert_eq!(out.amount, 1_000);
    }
}
