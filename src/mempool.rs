use anyhow::{Context, Result};

use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::iter::FromIterator;
use std::ops::Bound;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use serde::ser::{Serialize, SerializeSeq, Serializer};

use crate::index::{tx_asset_events, TxAssetOutputs, TxLocation};
use crate::types::{AssetEventKind, AssetEventRow, AssetMetaEventRow};
use crate::{
    daemon::Daemon,
    metrics::{Gauge, Metrics},
    neurai::asset::{parse_asset_script, AssetData},
    signals::ExitFlag,
    types::ScriptHash,
};

/// Asset events found in mempool transactions, by name / logical key.
#[derive(Default)]
pub(crate) struct MempoolAssets {
    pub meta: HashMap<Vec<u8>, Vec<AssetMetaEventRow>>,
    pub events: HashMap<(AssetEventKind, Vec<u8>), Vec<AssetEventRow>>,
}

impl MempoolAssets {
    pub(crate) fn events(&self, kind: AssetEventKind, key: &[u8]) -> &[AssetEventRow] {
        self.events
            .get(&(kind, key.to_vec()))
            .map_or(&[], Vec::as_slice)
    }

    pub(crate) fn meta(&self, name: &[u8]) -> &[AssetMetaEventRow] {
        self.meta.get(name).map_or(&[], Vec::as_slice)
    }
}

pub(crate) struct Entry {
    pub txid: Txid,
    pub tx: Transaction,
    pub fee: Amount,
    pub vsize: u64,
    pub has_unconfirmed_inputs: bool,
}

/// Mempool current state
pub(crate) struct Mempool {
    entries: HashMap<Txid, Entry>,
    by_funding: BTreeSet<(ScriptHash, Txid)>,
    by_spending: BTreeSet<(OutPoint, Txid)>,
    /// Asset-name → txids that touched it in mempool.
    ///
    /// Keys are the raw asset-name bytes (exactly as stored on chain), not a hash
    /// prefix — mempool is small enough that exact names are cheap.
    by_asset_name: HashMap<Vec<u8>, HashSet<Txid>>,
    fees: FeeHistogram,
    /// `mempool.get_fee_histogram` reply, computed like ElectrumX.
    compact_histogram: Vec<(f64, u64)>,
    /// Asset events of mempool transactions (overlaid on confirmed state).
    assets: MempoolAssets,
    /// Bumped whenever the set of mempool transactions changes.
    generation: u64,
    // stats
    vsize: Gauge,
    count: Gauge,
}

/// An update to [`Mempool`]'s internal state. This can be fetched
/// asynchronously using [`MempoolSyncUpdate::poll`], and applied
/// using [`Mempool::apply_sync_update`].
pub(crate) struct MempoolSyncUpdate {
    new_entries: Vec<Entry>,
    removed_entries: HashSet<Txid>,
}

impl MempoolSyncUpdate {
    /// Poll the bitcoin node and compute a [`MempoolSyncUpdate`] based on the given set of
    /// `old_txids` which are already cached.
    pub fn poll(
        daemon: &Daemon,
        old_txids: HashSet<Txid>,
        exit_flag: &ExitFlag,
    ) -> Result<MempoolSyncUpdate> {
        let txids = daemon.get_mempool_txids()?;
        debug!("loading {} mempool transactions", txids.len());

        let new_txids = HashSet::<Txid>::from_iter(txids);

        let to_add = &new_txids - &old_txids;
        let to_remove = &old_txids - &new_txids;

        let to_add: Vec<Txid> = to_add.into_iter().collect();
        let mut new_entries = Vec::with_capacity(to_add.len());

        for txids_chunk in to_add.chunks(1000) {
            exit_flag.poll().context("mempool update interrupted")?;
            let entries = daemon.get_mempool_entries(txids_chunk)?;
            ensure!(
                txids_chunk.len() == entries.len(),
                "got {} mempools entries, expected {}",
                entries.len(),
                txids_chunk.len()
            );
            let txs = daemon.get_mempool_transactions(txids_chunk)?;
            ensure!(
                txids_chunk.len() == txs.len(),
                "got {} mempools transactions, expected {}",
                txs.len(),
                txids_chunk.len()
            );
            let chunk_entries: Vec<Entry> = txids_chunk
                .iter()
                .zip(entries.into_iter().zip(txs))
                .filter_map(|(txid, (entry, tx))| {
                    let entry = match entry {
                        Some(entry) => entry,
                        None => {
                            debug!("missing mempool entry: {}", txid);
                            return None;
                        }
                    };
                    let tx = match tx {
                        Some(tx) => tx,
                        None => {
                            debug!("missing mempool tx: {}", txid);
                            return None;
                        }
                    };
                    Some(Entry {
                        txid: *txid,
                        tx,
                        vsize: entry.vsize,
                        fee: entry.fee().expect("filtered by Daemon::get_mempool_entries"),
                        has_unconfirmed_inputs: !entry.depends.is_empty(),
                    })
                })
                .collect();

            new_entries.extend(chunk_entries);
        }

        let update = MempoolSyncUpdate {
            new_entries,
            removed_entries: to_remove,
        };
        Ok(update)
    }
}

fn asset_name_bytes(data: &AssetData) -> Vec<u8> {
    match data {
        AssetData::New(a) => a.name.as_bytes().to_vec(),
        AssetData::Transfer(a) => a.name.as_bytes().to_vec(),
        AssetData::Reissue(a) => a.name.as_bytes().to_vec(),
        AssetData::Owner(a) => a.name.as_bytes().to_vec(),
    }
}

// Smallest possible txid
fn txid_min() -> Txid {
    Txid::all_zeros()
}

// Largest possible txid
fn txid_max() -> Txid {
    Txid::from_byte_array([0xFF; 32])
}

impl Mempool {
    pub fn new(metrics: &Metrics) -> Self {
        Self {
            entries: Default::default(),
            by_funding: Default::default(),
            by_spending: Default::default(),
            by_asset_name: Default::default(),
            fees: FeeHistogram::default(),
            compact_histogram: Vec::new(),
            assets: MempoolAssets::default(),
            generation: 0,
            vsize: metrics.gauge(
                "mempool_txs_vsize",
                "Total vsize of mempool transactions (in bytes)",
                "fee_rate",
            ),
            count: metrics.gauge(
                "mempool_txs_count",
                "Total number of mempool transactions",
                "fee_rate",
            ),
        }
    }

    /// Compact fee histogram exactly as ElectrumX builds it
    /// (`electrumx/server/mempool.py` `_update_histogram` / `_compress_histogram`):
    /// fee rates in sat/byte rounded *down* to 0.1, weighted by the full
    /// serialized size, grouped in tranches of at least 100 kB that grow ×1.1.
    pub(crate) fn compact_fee_histogram(&self) -> &[(f64, u64)] {
        &self.compact_histogram
    }

    pub(crate) fn assets(&self) -> &MempoolAssets {
        &self.assets
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    fn update_assets(&mut self) {
        let mut assets = MempoolAssets::default();
        for entry in self.entries.values() {
            let mut outputs = TxAssetOutputs::default();
            for (vout, output) in entry.tx.output.iter().enumerate() {
                outputs.add_output(vout as u32, output.script_pubkey.as_bytes());
            }
            if outputs.is_empty() {
                continue;
            }
            let loc = TxLocation {
                txid: entry.txid,
                block_hash: bitcoin::BlockHash::all_zeros(),
                height: 0,
                tx_pos: 0,
            };
            let events = tx_asset_events(loc, outputs);
            for meta in events.meta {
                assets.meta.entry(meta.name.clone()).or_default().push(meta);
            }
            for event in events.events {
                assets
                    .events
                    .entry((event.kind, event.key.clone()))
                    .or_default()
                    .push(event);
            }
        }
        self.assets = assets;
    }

    fn update_compact_histogram(&mut self) {
        let mut histogram: Vec<(f64, u64)> = Vec::new();
        {
            let mut by_rate = std::collections::BTreeMap::<u64, u64>::new(); // key: f64 bits
            for entry in self.entries.values() {
                let size = bitcoin::consensus::serialize(&entry.tx).len() as u64;
                if size == 0 {
                    continue;
                }
                let fee_rate = entry.fee.to_sat() as f64 / size as f64;
                let fee_rate = (10.0 * fee_rate).floor() / 10.0;
                *by_rate.entry(fee_rate.to_bits()).or_default() += size;
            }
            histogram.extend(by_rate.into_iter().map(|(bits, size)| (f64::from_bits(bits), size)));
        }
        // Sorted by descending fee rate (all rates are non-negative, so the
        // bit pattern order equals the numeric order).
        histogram.reverse();
        self.compact_histogram = compress_histogram(&histogram, 100_000.0);
    }

    pub(crate) fn get(&self, txid: &Txid) -> Option<&Entry> {
        self.entries.get(txid)
    }

    pub(crate) fn filter_by_funding(&self, scripthash: &ScriptHash) -> Vec<&Entry> {
        let range = (
            Bound::Included((*scripthash, txid_min())),
            Bound::Included((*scripthash, txid_max())),
        );
        self.by_funding
            .range(range)
            .map(|(_, txid)| self.get(txid).expect("missing funding mempool tx"))
            .collect()
    }

    pub(crate) fn filter_by_spending(&self, outpoint: &OutPoint) -> Vec<&Entry> {
        let range = (
            Bound::Included((*outpoint, txid_min())),
            Bound::Included((*outpoint, txid_max())),
        );
        self.by_spending
            .range(range)
            .map(|(_, txid)| self.get(txid).expect("missing spending mempool tx"))
            .collect()
    }

    /// Return every mempool `Entry` that carries any output referring to the given asset name.
    pub(crate) fn filter_by_asset_name(&self, name: &[u8]) -> Vec<&Entry> {
        self.by_asset_name
            .get(name)
            .into_iter()
            .flatten()
            .map(|txid| self.get(txid).expect("missing asset mempool tx"))
            .collect()
    }

    /// Apply a [`MempoolSyncUpdate`] to the mempool state.
    pub fn apply_sync_update(&mut self, update: MempoolSyncUpdate) {
        let removed = update.removed_entries.len();
        let added = update.new_entries.len();

        for txid_to_remove in update.removed_entries {
            self.remove_entry(txid_to_remove);
        }

        for entry in update.new_entries {
            self.add_entry(entry);
        }

        self.update_metrics();
        self.update_compact_histogram();
        if added > 0 || removed > 0 {
            self.generation += 1;
            self.update_assets();
        }

        debug!(
            "{} mempool txs: {} added, {} removed",
            self.entries.len(),
            added,
            removed,
        );
    }

    fn update_metrics(&mut self) {
        for i in 0..FeeHistogram::BINS {
            let bin_index = FeeHistogram::BINS - i - 1; // from 63 to 0
            let (lower, upper) = FeeHistogram::bin_range(bin_index);
            let label = format!("[{:20.0}, {:20.0})", lower, upper);
            self.vsize.set(&label, self.fees.vsize[bin_index] as f64);
            self.count.set(&label, self.fees.count[bin_index] as f64);
        }
    }

    pub fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) {
        let loaded = match daemon.get_mempool_info() {
            Ok(info) => info.loaded.unwrap_or(true),
            Err(e) => {
                warn!("mempool sync failed: {}", e);
                return;
            }
        };
        if !loaded {
            warn!("mempool not loaded");
            return;
        }

        let old_txids = HashSet::<Txid>::from_iter(self.entries.keys().copied());

        let poll_result = MempoolSyncUpdate::poll(daemon, old_txids, exit_flag);

        let sync_update = match poll_result {
            Ok(sync_update) => sync_update,
            Err(e) => {
                warn!("mempool sync failed: {}", e);
                return;
            }
        };

        self.apply_sync_update(sync_update);
    }

    /// Add a transaction entry to the mempool and update the fee histogram.
    fn add_entry(&mut self, entry: Entry) {
        for txi in &entry.tx.input {
            self.by_spending.insert((txi.previous_output, entry.txid));
        }
        for txo in &entry.tx.output {
            // For asset-wrapped outputs, hash the base script (P2PKH/AuthScript
            // before OP_XNA_ASSET) so the mempool index keys match the
            // scripthash a wallet subscribes to. See `effective_script` in
            // neurai/asset.rs.
            let bytes = txo.script_pubkey.as_bytes();
            let asset = parse_asset_script(bytes);
            let scripthash = match &asset {
                Some(a) => ScriptHash::hash(&a.base_script),
                None => ScriptHash::hash(bytes),
            };
            self.by_funding.insert((scripthash, entry.txid)); // may have duplicates
            if let Some(asset) = asset {
                let name = asset_name_bytes(&asset.data);
                self.by_asset_name
                    .entry(name)
                    .or_default()
                    .insert(entry.txid);
            }
        }

        self.modify_fee_histogram(entry.fee, entry.vsize as i64);

        assert!(
            self.entries.insert(entry.txid, entry).is_none(),
            "duplicate mempool txid"
        );
    }

    /// Remove a transaction entry from the mempool and update the fee histogram.
    fn remove_entry(&mut self, txid: Txid) {
        let entry = self.entries.remove(&txid).expect("missing tx from mempool");
        for txi in entry.tx.input {
            self.by_spending.remove(&(txi.previous_output, txid));
        }
        for txo in entry.tx.output {
            let bytes = txo.script_pubkey.as_bytes();
            let asset = parse_asset_script(bytes);
            let scripthash = match &asset {
                Some(a) => ScriptHash::hash(&a.base_script),
                None => ScriptHash::hash(bytes),
            };
            self.by_funding.remove(&(scripthash, txid)); // may have misses
            if let Some(asset) = asset {
                let name = asset_name_bytes(&asset.data);
                if let Some(txids) = self.by_asset_name.get_mut(&name) {
                    txids.remove(&txid);
                    if txids.is_empty() {
                        self.by_asset_name.remove(&name);
                    }
                }
            }
        }

        self.modify_fee_histogram(entry.fee, -(entry.vsize as i64));
    }

    /// Apply a change to the fee histogram. Used when transactions are added or
    /// removed from the mempool. If `vsize_change` is positive, we increase
    /// the histogram vsize and TX count in the appropriate bin. If negative,
    /// we decrease them.
    fn modify_fee_histogram(&mut self, fee: Amount, vsize_change: i64) {
        let vsize = vsize_change.unsigned_abs();
        let bin_index = FeeHistogram::bin_index(fee, vsize);
        if vsize_change >= 0 {
            self.fees.insert(bin_index, vsize);
        } else {
            self.fees.remove(bin_index, vsize);
        }
    }
}

/// ElectrumX `MemPool._compress_histogram`. `histogram` must be sorted by
/// descending fee rate.
fn compress_histogram(histogram: &[(f64, u64)], mut bin_size: f64) -> Vec<(f64, u64)> {
    let mut compact = vec![];
    let mut cum_size = 0u64;
    let mut prev_fee_rate: Option<f64> = None;
    for &(fee_rate, size) in histogram {
        // a big lump of txs at this specific rate: flush the previous tranche first
        if size as f64 > 2.0 * bin_size {
            if let Some(prev) = prev_fee_rate {
                if cum_size > 0 {
                    compact.push((prev, cum_size));
                    cum_size = 0;
                    bin_size *= 1.1;
                }
            }
        }
        cum_size += size;
        if cum_size as f64 > bin_size {
            compact.push((fee_rate, cum_size));
            cum_size = 0;
            bin_size *= 1.1;
        }
        prev_fee_rate = Some(fee_rate);
    }
    compact
}

pub(crate) struct FeeHistogram {
    /// bins[64-i] contains transactions' statistics inside the fee band of [2**(i-1), 2**i).
    /// bins[64] = [0, 1)
    /// bins[63] = [1, 2)
    /// bins[62] = [2, 4)
    /// bins[61] = [4, 8)
    /// bins[60] = [8, 16)
    /// ...
    /// bins[1] = [2**62, 2**63)
    /// bins[0] = [2**63, 2**64)
    vsize: [u64; FeeHistogram::BINS],
    count: [u64; FeeHistogram::BINS],
}

impl Default for FeeHistogram {
    fn default() -> Self {
        Self {
            vsize: [0; FeeHistogram::BINS],
            count: [0; FeeHistogram::BINS],
        }
    }
}

impl FeeHistogram {
    const BINS: usize = 65; // 0..=64

    fn bin_index(fee: Amount, vsize: u64) -> usize {
        let fee_rate = fee.to_sat() / vsize;
        usize::try_from(fee_rate.leading_zeros()).unwrap()
    }

    fn bin_range(bin_index: usize) -> (u128, u128) {
        let limit = 1u128 << (FeeHistogram::BINS - bin_index - 1);
        (limit / 2, limit)
    }

    fn insert(&mut self, bin_index: usize, vsize: u64) {
        // skip transactions with too low fee rate (<1 sat/vB)
        if let Some(bin) = self.vsize.get_mut(bin_index) {
            *bin += vsize
        }
        if let Some(bin) = self.count.get_mut(bin_index) {
            *bin += 1
        }
    }

    fn remove(&mut self, bin_index: usize, vsize: u64) {
        // skip transactions with too low fee rate (<1 sat/vB)
        if let Some(bin) = self.vsize.get_mut(bin_index) {
            *bin = bin.checked_sub(vsize).unwrap_or_else(|| {
                warn!("removing TX from mempool caused bin count to unexpectedly drop below zero");
                0
            });
        }
        if let Some(bin) = self.count.get_mut(bin_index) {
            *bin = bin.checked_sub(1).unwrap_or_else(|| {
                warn!("removing TX from mempool caused bin vsize to unexpectedly drop below zero");
                0
            });
        }
    }
}

impl Serialize for FeeHistogram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.vsize.len()))?;
        // https://electrum-protocol.readthedocs.io/en/latest/protocol-methods.html#mempool-get-fee-histogram
        let fee_rates =
            (0..FeeHistogram::BINS).map(|i| u64::MAX.checked_shr(i as u32).unwrap_or(0));
        fee_rates
            .zip(self.vsize.iter().copied())
            .skip_while(|(_fee_rate, vsize)| *vsize == 0)
            .try_for_each(|element| seq.serialize_element(&element))?;
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::{asset_name_bytes, FeeHistogram};
    use crate::neurai::asset::{AssetData, TransferAsset};
    use bitcoin::Amount;
    use serde_json::json;

    #[test]
    fn asset_name_bytes_covers_every_variant() {
        let transfer = AssetData::Transfer(TransferAsset {
            name: "TOKEN".to_string(),
            amount: 1,
            message: None,
        });
        assert_eq!(asset_name_bytes(&transfer), b"TOKEN");
    }

    #[test]
    fn test_histogram() {
        let items = vec![
            (Amount::from_sat(20), 10),
            (Amount::from_sat(10), 10),
            (Amount::from_sat(60), 10),
            (Amount::from_sat(30), 10),
            (Amount::from_sat(70), 10),
            (Amount::from_sat(50), 10),
            (Amount::from_sat(40), 10),
            (Amount::from_sat(80), 10),
            (Amount::from_sat(1), 100),
        ];
        let mut hist = FeeHistogram::default();
        for (amount, vsize) in items {
            let bin_index = FeeHistogram::bin_index(amount, vsize);
            hist.insert(bin_index, vsize);
        }
        assert_eq!(
            json!(hist),
            json!([[15, 10], [7, 40], [3, 20], [1, 10], [0, 100]])
        );

        {
            let bin_index = FeeHistogram::bin_index(Amount::from_sat(5), 1); // 5 sat/byte
            hist.remove(bin_index, 11);
            assert_eq!(
                json!(hist),
                json!([[15, 10], [7, 29], [3, 20], [1, 10], [0, 100]])
            );
        }

        {
            let bin_index = FeeHistogram::bin_index(Amount::from_sat(13), 1); // 13 sat/byte
            hist.insert(bin_index, 80);
            assert_eq!(
                json!(hist),
                json!([[15, 90], [7, 29], [3, 20], [1, 10], [0, 100]])
            );
        }

        {
            let bin_index = FeeHistogram::bin_index(Amount::from_sat(99), 1); // 99 sat/byte
            hist.insert(bin_index, 15);
            assert_eq!(
                json!(hist),
                json!([
                    [127, 15],
                    [63, 0],
                    [31, 0],
                    [15, 90],
                    [7, 29],
                    [3, 20],
                    [1, 10],
                    [0, 100]
                ])
            );
        }
    }
}

#[cfg(test)]
mod compact_histogram_tests {
    use super::compress_histogram;

    /// Vectors produced by ElectrumX `MemPool._compress_histogram(..., bin_size=100_000)`.
    #[test]
    fn matches_electrumx_compression() {
        // Small mempool: everything below the first 100 kB tranche → empty.
        assert!(compress_histogram(&[(10.0, 500), (1.0, 300)], 100_000.0).is_empty());

        let hist = [(50.0, 60_000), (20.0, 50_000), (10.0, 250_000), (1.0, 120_000)];
        // 60k + 50k > 100k → (20.0, 110000); then 250k > 2*110k: nothing pending,
        // 250k > 110k → (10.0, 250000); 120k > 121k? no → dropped.
        assert_eq!(
            compress_histogram(&hist, 100_000.0),
            vec![(20.0, 110_000), (10.0, 250_000)]
        );

        // Big lump flushes the previous partial tranche first.
        let hist = [(5.0, 40_000), (2.0, 300_000)];
        assert_eq!(
            compress_histogram(&hist, 100_000.0),
            vec![(5.0, 40_000), (2.0, 300_000)]
        );
    }
}
