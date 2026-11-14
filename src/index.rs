use anyhow::{Context, Result};
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Txid};
use bitcoin_slices::{bsl, Visit, Visitor};
use std::ops::ControlFlow;
use std::thread;

use crate::neurai::asset::{
    is_null_asset_script, parse_asset_script, AssetData, AssetOutput, IpfsRef,
};
use crate::neurai::block::neurai_to_bsl_block;
use crate::neurai::NetworkParams;
use crate::{
    chain::{Chain, NewHeader},
    daemon::Daemon,
    db::{DBStore, WriteBatch},
    metrics::{self, Gauge, Histogram, Metrics},
    signals::ExitFlag,
    types::{
        bsl_txid, AssetFundingRow, AssetHistoryRow, AssetMetaEvent, AssetMetaEventRow,
        AssetMetadata, HashPrefixRow, HeaderRow, ScriptHash, ScriptHashRow, SerBlock,
        SpendingPrefixRow, TxidRow,
    },
};

#[derive(Clone)]
struct Stats {
    update_duration: Histogram,
    update_size: Histogram,
    height: Gauge,
    db_properties: Gauge,
}

impl Stats {
    fn new(metrics: &Metrics) -> Self {
        Self {
            update_duration: metrics.histogram_vec(
                "index_update_duration",
                "Index update duration (in seconds)",
                "step",
                metrics::default_duration_buckets(),
            ),
            update_size: metrics.histogram_vec(
                "index_update_size",
                "Index update size (in bytes)",
                "step",
                metrics::default_size_buckets(),
            ),
            height: metrics.gauge("index_height", "Indexed block height", "type"),
            db_properties: metrics.gauge("index_db_properties", "Index DB properties", "name"),
        }
    }

    fn observe_duration<T>(&self, label: &str, f: impl FnOnce() -> T) -> T {
        self.update_duration.observe_duration(label, f)
    }

    fn observe_size<const N: usize>(&self, label: &str, rows: &[[u8; N]]) {
        self.update_size.observe(label, (rows.len() * N) as f64);
    }

    fn observe_batch(&self, batch: &WriteBatch) {
        self.observe_size("write_funding_rows", &batch.funding_rows);
        self.observe_size("write_spending_rows", &batch.spending_rows);
        self.observe_size("write_txid_rows", &batch.txid_rows);
        self.observe_size("write_header_rows", &batch.header_rows);
        self.observe_size("write_asset_history_rows", &batch.asset_history_rows);
        self.observe_size("write_asset_funding_rows", &batch.asset_funding_rows);
        debug!(
            "writing {} funding and {} spending rows from {} transactions, {} blocks \
             ({} asset-meta, {} asset-history, {} asset-funding)",
            batch.funding_rows.len(),
            batch.spending_rows.len(),
            batch.txid_rows.len(),
            batch.header_rows.len(),
            batch.asset_meta_rows.len(),
            batch.asset_history_rows.len(),
            batch.asset_funding_rows.len(),
        );
    }

    fn observe_chain(&self, chain: &Chain) {
        self.height.set("tip", chain.height() as f64);
    }

    fn observe_db(&self, store: &DBStore) {
        for (cf, name, value) in store.get_properties() {
            self.db_properties
                .set(&format!("{}:{}", name, cf), value as f64);
        }
    }
}

/// Confirmed transactions' address index
pub struct Index {
    store: DBStore,
    batch_size: usize,
    lookup_limit: Option<usize>,
    chain: Chain,
    stats: Stats,
    is_ready: bool,
    flush_needed: bool,
    params: &'static NetworkParams,
}

impl Index {
    pub(crate) fn load(
        store: DBStore,
        mut chain: Chain,
        metrics: &Metrics,
        batch_size: usize,
        lookup_limit: Option<usize>,
        reindex_last_blocks: usize,
    ) -> Result<Self> {
        let params = chain.params();
        if let Some(row) = store.get_tip() {
            let tip = deserialize(&row).expect("invalid tip");
            let headers = store
                .iter_headers()
                .map(move |row| HeaderRow::from_db_row(row, params).header);
            chain.load(headers, tip);
            chain.drop_last_headers(reindex_last_blocks);
        };
        let stats = Stats::new(metrics);
        stats.observe_chain(&chain);
        stats.observe_db(&store);
        Ok(Index {
            store,
            batch_size,
            lookup_limit,
            params,
            chain,
            stats,
            is_ready: false,
            flush_needed: false,
        })
    }

    pub(crate) fn chain(&self) -> &Chain {
        &self.chain
    }

    pub(crate) fn limit_result<T>(&self, entries: impl Iterator<Item = T>) -> Result<Vec<T>> {
        let mut entries = entries.fuse();
        let result: Vec<T> = match self.lookup_limit {
            Some(lookup_limit) => entries.by_ref().take(lookup_limit).collect(),
            None => entries.by_ref().collect(),
        };
        if entries.next().is_some() {
            bail!(">{} index entries, query may take too long", result.len())
        }
        Ok(result)
    }

    pub(crate) fn filter_by_txid(&self, txid: Txid) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_txid(TxidRow::scan_prefix(txid))
            .map(|row| HashPrefixRow::from_db_row(row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn filter_by_funding(
        &self,
        scripthash: ScriptHash,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_funding(ScriptHashRow::scan_prefix(scripthash))
            .map(|row| HashPrefixRow::from_db_row(row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    pub(crate) fn filter_by_spending(
        &self,
        outpoint: OutPoint,
    ) -> impl Iterator<Item = BlockHash> + '_ {
        self.store
            .iter_spending(SpendingPrefixRow::scan_prefix(outpoint))
            .map(|row| HashPrefixRow::from_db_row(row).height())
            .filter_map(move |height| self.chain.get_block_hash(height))
    }

    /// Yield one entry per `(asset, tx, height)` row stored in the asset history CF,
    /// preserving per-transaction granularity so multiple matching transactions in
    /// the same block all surface in `blockchain.asset.get_history`.
    pub(crate) fn filter_by_asset_name(
        &self,
        name: &[u8],
    ) -> impl Iterator<Item = (BlockHash, usize, [u8; 8])> + '_ {
        self.store
            .iter_asset_history(AssetHistoryRow::scan_prefix(name))
            .filter_map(move |row| {
                let height = AssetHistoryRow::height(&row);
                let block_hash = self.chain.get_block_hash(height)?;
                let mut tx_prefix = [0u8; 8];
                tx_prefix.copy_from_slice(&row[8..16]);
                Some((block_hash, height, tx_prefix))
            })
    }

    /// Yield one entry per `(scripthash, asset, tx, height)` row — same granularity
    /// contract as [`filter_by_asset_name`] but keyed on scripthash.
    #[allow(dead_code)]
    pub(crate) fn filter_asset_funding_by_scripthash(
        &self,
        scripthash: ScriptHash,
    ) -> impl Iterator<Item = (BlockHash, usize, [u8; 8])> + '_ {
        self.store
            .iter_asset_funding(AssetFundingRow::scan_prefix_by_scripthash(scripthash))
            .filter_map(move |row| {
                let height = AssetFundingRow::height(&row);
                let block_hash = self.chain.get_block_hash(height)?;
                let mut name_prefix = [0u8; 8];
                name_prefix.copy_from_slice(&row[8..16]);
                Some((block_hash, height, name_prefix))
            })
    }

    /// Current asset state: its `New` / `Reissue` events on the active chain,
    /// folded in chain order. Events from blocks that were reorged away are
    /// dropped by checking their block hash against the chain at their height.
    pub(crate) fn get_asset_metadata(&self, name: &[u8]) -> Option<AssetMetadata> {
        let events: Vec<AssetMetaEventRow> = self
            .store
            .iter_asset_meta(AssetMetaEventRow::scan_prefix(name))
            .into_iter()
            .filter_map(|(key, value)| match AssetMetaEventRow::from_db(&key, &value) {
                Ok(row) => Some(row),
                Err(e) => {
                    warn!("skipping invalid asset_meta row: {}", e);
                    None
                }
            })
            .filter(|row| row.name == name) // 8-byte name prefixes may collide
            .filter(|row| self.chain.get_block_hash(row.height as usize) == Some(row.block_hash))
            .collect();
        AssetMetadata::fold(&events)
    }

    // Return `Ok(true)` when the chain is fully synced and the index is compacted.
    pub(crate) fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        let new_headers = self
            .stats
            .observe_duration("headers", || daemon.get_new_headers(&self.chain))?;
        match (new_headers.first(), new_headers.last()) {
            (Some(first), Some(last)) => {
                let count = new_headers.len();
                info!(
                    "indexing {} blocks: [{}..{}]",
                    count,
                    first.height(),
                    last.height()
                );
            }
            _ => {
                if self.flush_needed {
                    self.store.flush(); // full compaction is performed on the first flush call
                    self.flush_needed = false;
                }
                self.is_ready = true;
                return Ok(true); // no more blocks to index (done for now)
            }
        }

        thread::scope(|scope| -> Result<()> {
            let (tx, rx) = crossbeam_channel::bounded(1);

            let chunks = new_headers.chunks(self.batch_size);
            let index = &self; // to be moved into reader thread
            let reader = thread::Builder::new()
                .name("index_build".into())
                .spawn_scoped(scope, move || -> Result<()> {
                    for chunk in chunks {
                        exit_flag.poll().with_context(|| {
                            format!(
                                "indexing interrupted at height: {}",
                                chunk.first().unwrap().height()
                            )
                        })?;
                        let batch = index.index_blocks(daemon, chunk)?;
                        tx.send(batch).context("writer disconnected")?;
                    }
                    Ok(()) // `tx` is dropped, to stop the iteration on `rx`
                })
                .expect("spawn failed");

            let index = &self; // to be moved into writer thread
            let writer = thread::Builder::new()
                .name("index_write".into())
                .spawn_scoped(scope, move || {
                    let stats = &index.stats;
                    for mut batch in rx {
                        stats.observe_duration("sort", || batch.sort()); // pre-sort to optimize DB writes
                        stats.observe_batch(&batch);
                        stats.observe_duration("write", || index.store.write(&batch));
                        stats.observe_db(&index.store);
                    }
                })
                .expect("spawn failed");

            reader.join().expect("reader thread panic")?;
            writer.join().expect("writer thread panic");
            Ok(())
        })?;
        self.chain.update(new_headers);
        self.stats.observe_chain(&self.chain);
        self.flush_needed = true;
        Ok(false) // sync is not done
    }

    fn index_blocks(&self, daemon: &Daemon, chunk: &[NewHeader]) -> Result<WriteBatch> {
        let blockhashes: Vec<BlockHash> = chunk.iter().map(|h| h.hash()).collect();
        let mut heights = chunk.iter().map(|h| h.height());

        let mut batch = WriteBatch::default();
        let params = self.params;

        daemon.for_blocks(blockhashes, |blockhash, block| {
            let height = heights.next().expect("unexpected block");
            self.stats.observe_duration("block", || {
                index_single_block(blockhash, block, height, &mut batch, params);
            });
            self.stats.height.set("tip", height as f64);
        })?;
        let heights: Vec<_> = heights.collect();
        assert!(
            heights.is_empty(),
            "some blocks were not indexed: {:?}",
            heights
        );
        Ok(batch)
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.is_ready
    }
}

fn asset_name_of(data: &AssetData) -> &str {
    match data {
        AssetData::New(a) => a.name.as_str(),
        AssetData::Transfer(a) => a.name.as_str(),
        AssetData::Reissue(a) => a.name.as_str(),
        AssetData::Owner(a) => a.name.as_str(),
    }
}

/// Where an asset output sits on the chain.
struct OutputLocation {
    txid: Txid,
    block_hash: BlockHash,
    height: u32,
    tx_pos: u32,
    vout: u32,
}

/// Build the `asset_meta` event row for a `New` or `Reissue` output.
/// Transfer/Owner outputs don't change metadata — they're tracked only in
/// history/funding.
fn asset_meta_event_of(data: &AssetData, loc: &OutputLocation) -> Option<AssetMetaEventRow> {
    let (event, name, amount, units, reissuable, ipfs) = match data {
        AssetData::New(a) => (
            AssetMetaEvent::New,
            &a.name,
            a.amount,
            i8::try_from(a.units).unwrap_or(i8::MAX),
            a.reissuable,
            a.ipfs.as_ref(),
        ),
        AssetData::Reissue(a) => (
            AssetMetaEvent::Reissue,
            &a.name,
            a.amount,
            a.units,
            a.reissuable,
            a.ipfs.as_ref(),
        ),
        AssetData::Transfer(_) | AssetData::Owner(_) => return None,
    };
    let (ipfs_marker, ipfs_hash) = match ipfs {
        Some(IpfsRef { marker, hash }) => (*marker, *hash),
        None => (0u8, [0u8; 32]),
    };
    Some(AssetMetaEventRow {
        name: name.as_bytes().to_vec(),
        event,
        txid: loc.txid,
        block_hash: loc.block_hash,
        height: loc.height,
        tx_pos: loc.tx_pos,
        vout: loc.vout,
        amount,
        units,
        reissuable,
        ipfs_marker,
        ipfs_hash,
    })
}

fn index_single_block(
    block_hash: BlockHash,
    block: SerBlock,
    height: usize,
    batch: &mut WriteBatch,
    params: &'static NetworkParams,
) {
    // Parse the Neurai block header (80 or 120 bytes) and get a bsl-compatible
    // synthetic block (80-byte fake header + original tx bytes).
    let (neurai_header, synthetic_block) = neurai_to_bsl_block(&block, params)
        .expect("core returned block with invalid header");

    // Store the header directly (bypassing visit_block_header in the bsl visitor).
    batch
        .header_rows
        .push(HeaderRow::new(neurai_header).to_db_row());

    struct IndexBlockVisitor<'a> {
        batch: &'a mut WriteBatch,
        height: usize,
        block_hash: BlockHash,
        tx_pos: u32,
        /// Asset outputs of the transaction being parsed. `bitcoin_slices`
        /// calls `visit_tx_out` for every output *before* `visit_transaction`
        /// (the txid is only known once the whole transaction is parsed), so
        /// they are indexed when `visit_transaction` runs.
        pending_assets: Vec<(u32, ScriptHash, AssetOutput)>,
    }

    impl Visitor for IndexBlockVisitor<'_> {
        fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
            let txid = bsl_txid(tx);
            self.batch
                .txid_rows
                .push(TxidRow::row(txid, self.height).to_db_row());
            for (vout, scripthash, asset) in std::mem::take(&mut self.pending_assets) {
                let loc = OutputLocation {
                    txid,
                    block_hash: self.block_hash,
                    height: self.height as u32,
                    tx_pos: self.tx_pos,
                    vout,
                };
                self.index_asset_output(scripthash, asset, &loc);
            }
            self.tx_pos += 1;
            ControlFlow::Continue(())
        }

        fn visit_tx_out(&mut self, vout: usize, tx_out: &bsl::TxOut) -> ControlFlow<()> {
            let script_bytes = tx_out.script_pubkey();
            let script = bitcoin::Script::from_bytes(script_bytes);
            // Skip unspendable outputs:
            //   * OP_RETURN data carriers,
            //   * Null-asset scripts (OP_XNA_ASSET-prefixed: address tagging,
            //     freeze/unfreeze, global restrictions, verifier strings) —
            //     mirrors `CScript::IsUnspendable` in the daemon.
            if !script.is_op_return() && !is_null_asset_script(script_bytes) {
                // Asset-wrapped outputs must hash on the *base* script (the
                // P2PKH or AuthScript prefix before OP_XNA_ASSET) so that a
                // wallet subscribed to the bare address sees the asset
                // transfer. Compute the scripthash from the base when present,
                // and reuse the parsed AssetOutput for the asset event.
                let asset = parse_asset_script(script_bytes);
                let scripthash = match &asset {
                    Some(a) => ScriptHash::hash(&a.base_script),
                    None => ScriptHash::hash(script_bytes),
                };
                self.batch
                    .funding_rows
                    .push(ScriptHashRow::row(scripthash, self.height).to_db_row());
                if let Some(asset) = asset {
                    self.pending_assets.push((vout as u32, scripthash, asset));
                }
            }
            ControlFlow::Continue(())
        }

        fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn) -> ControlFlow<()> {
            let prevout: OutPoint = tx_in.prevout().into();
            if !prevout.is_null() {
                let row = SpendingPrefixRow::row(prevout, self.height);
                self.batch.spending_rows.push(row.to_db_row());
            }
            ControlFlow::Continue(())
        }
        // visit_block_header: default no-op (header already stored above)
    }

    impl IndexBlockVisitor<'_> {
        fn index_asset_output(
            &mut self,
            scripthash: ScriptHash,
            asset: AssetOutput,
            loc: &OutputLocation,
        ) {
            let name_bytes = asset_name_of(&asset.data).as_bytes();
            self.batch
                .asset_history_rows
                .push(AssetHistoryRow::row(name_bytes, loc.txid, self.height));
            self.batch
                .asset_funding_rows
                .push(AssetFundingRow::row(scripthash, name_bytes, self.height));

            if let Some(event) = asset_meta_event_of(&asset.data, loc) {
                self.batch.asset_meta_rows.push((event.key(), event.value()));
            }
        }
    }

    let mut index_block = IndexBlockVisitor {
        batch,
        height,
        block_hash,
        tx_pos: 0,
        pending_assets: Vec::new(),
    };
    bsl::Block::visit(&synthetic_block, &mut index_block).expect("core returned invalid block");

    let len = block_hash
        .consensus_encode(&mut (&mut batch.tip_row as &mut [u8]))
        .expect("in-memory writers don't error");
    debug_assert_eq!(len, BlockHash::LEN);
}

#[cfg(test)]
mod tests {
    use super::{asset_meta_event_of, asset_name_of, index_single_block, OutputLocation};
    use crate::db::WriteBatch;
    use crate::neurai::asset::{
        parse_asset_script, AssetData, ASSET_MAGIC, OP_DROP, OP_XNA_ASSET, TYPE_NEW, TYPE_TRANSFER,
    };
    use crate::neurai::{NeuraiNetwork, NetworkParams};
    use crate::types::{AssetHistoryRow, AssetMetaEvent, AssetMetaEventRow};
    use bitcoin::hashes::{hex::FromHex, Hash};
    use bitcoin::{BlockHash, Txid};
    use std::str::FromStr;

    /// Helper: construct a P2PKH + OP_XNA_ASSET payload script exactly as the
    /// visitor would see it coming out of `bitcoin_slices::bsl::Block::visit`.
    fn make_p2pkh_asset_script(type_byte: u8, tail: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(ASSET_MAGIC);
        payload.push(type_byte);
        payload.extend_from_slice(tail);

        let mut script = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 push-20
        script.extend_from_slice(&[0xAAu8; 20]);
        script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
        script.push(OP_XNA_ASSET);
        script.push(payload.len() as u8);
        script.extend_from_slice(&payload);
        script.push(OP_DROP);
        script
    }

    fn location(height: u32) -> OutputLocation {
        OutputLocation {
            txid: Txid::from_byte_array([0x42u8; 32]),
            block_hash: BlockHash::from_byte_array([0x24u8; 32]),
            height,
            tx_pos: 3,
            vout: 1,
        }
    }

    /// Parse a synthetic new-asset output, lift it to an `asset_meta` event row
    /// and check the DB key/value round-trip — the `visit_tx_out` →
    /// `asset_meta_event_of` → `key()/value()` pipeline the indexer runs.
    #[test]
    fn pipeline_new_asset_to_meta_event_roundtrip() {
        let mut body = Vec::new();
        body.push(5u8); // name length
        body.extend_from_slice(b"TOKEN");
        body.extend_from_slice(&5_000i64.to_le_bytes());
        body.push(2); // units
        body.push(1); // reissuable
        body.push(0); // no ipfs
        let script = make_p2pkh_asset_script(TYPE_NEW, &body);

        let asset = parse_asset_script(&script).expect("parse");
        assert_eq!(asset_name_of(&asset.data), "TOKEN");

        let event = asset_meta_event_of(&asset.data, &location(1_234)).expect("metadata");
        assert_eq!(event.name, b"TOKEN");
        assert_eq!(event.event, AssetMetaEvent::New);
        assert_eq!(event.amount, 5_000);
        assert_eq!(event.units, 2);
        assert!(event.reissuable);
        assert_eq!((event.height, event.tx_pos, event.vout), (1_234, 3, 1));
        assert_eq!(event.ipfs_marker, 0);

        let decoded = AssetMetaEventRow::from_db(&event.key(), &event.value()).unwrap();
        assert_eq!(decoded, event);
    }

    /// Transfer outputs must *not* produce metadata rows (only New/Reissue do).
    #[test]
    fn pipeline_transfer_has_no_metadata() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"COIN");
        body.extend_from_slice(&1i64.to_le_bytes());
        let script = make_p2pkh_asset_script(TYPE_TRANSFER, &body);

        let asset = parse_asset_script(&script).expect("parse");
        assert!(matches!(asset.data, AssetData::Transfer(_)));
        assert!(asset_meta_event_of(&asset.data, &location(1)).is_none());
    }

    /// Regtest block 1101 mined by neuraid v1.0.7: coinbase + three `issue`
    /// transactions (SHORT, LONGTRANSFERNAME12345, and a 30-char name with an
    /// IPFS hash whose payload needs OP_PUSHDATA1). Every asset row must carry
    /// the txid of the transaction that actually contains the output.
    #[test]
    fn real_v107_block_assets_are_attributed_to_their_own_tx() {
        let params = NetworkParams::for_network(NeuraiNetwork::Regtest);
        let hex = include_str!("../tests/fixtures/neurai-v1.0.7-regtest-block-1101.hex");
        let block = Vec::<u8>::from_hex(hex.trim()).unwrap();
        let block_hash =
            BlockHash::from_str("18c6ce11c89a6b132e1f51bca36e317a5d03a1b65e3257595419492e4c036c0c")
                .unwrap();
        let mut batch = WriteBatch::default();
        index_single_block(block_hash, block, 1101, &mut batch, params);

        let issues = [
            ("SHORT", "fcc43c0b3ce4fbc51b146023e6f70af89ce6a6be167921562ef9ff0276931f74", 1000, 2),
            ("LONGTRANSFERNAME12345", "0218cb7e8ca0abdc7c9066660a0a183c64e8370522c34622dbf0d160307157d2", 500, 0),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123", "b8cbbbc6561ed4f2edae553eaa7941eb85f400f4c55c53616926b671644309f9", 1000, 8),
        ];
        assert_eq!(batch.txid_rows.len(), 4);
        assert_eq!(batch.asset_history_rows.len(), 2 * issues.len()); // owner + new each
        assert_eq!(batch.asset_meta_rows.len(), issues.len());

        for (tx_pos, (name, txid, qty, units)) in issues.iter().enumerate() {
            let txid = Txid::from_str(txid).unwrap();
            for asset in [name.to_string(), format!("{name}!")] {
                let row = AssetHistoryRow::row(asset.as_bytes(), txid, 1101);
                assert!(batch.asset_history_rows.contains(&row), "missing history row for {asset}");
            }
            let (key, value) = &batch.asset_meta_rows[tx_pos];
            let event = AssetMetaEventRow::from_db(key, value).unwrap();
            assert_eq!(event.name, name.as_bytes());
            assert_eq!(event.txid, txid);
            assert_eq!(event.block_hash, block_hash);
            assert_eq!((event.height, event.tx_pos), (1101, tx_pos as u32 + 1));
            assert_eq!(event.amount, qty * 100_000_000);
            assert_eq!(event.units, *units);
        }
        let (key, value) = &batch.asset_meta_rows[2];
        let event = AssetMetaEventRow::from_db(key, value).unwrap();
        assert_eq!(event.ipfs_marker, 0x12);
    }
}
