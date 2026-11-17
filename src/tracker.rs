use parking_lot::RwLock;
use std::ops::ControlFlow;
use std::sync::Arc;

use anyhow::{Context, Result};
use bitcoin::{BlockHash, Txid};

use crate::neurai::{tx, NeuraiBlockHeader, NetworkParams};
use bitcoin::Amount;

use crate::{
    cache::Cache,
    chain::Chain,
    config::Config,
    daemon::Daemon,
    db::DBStore,
    index::Index,
    mempool::Mempool,
    metrics::Metrics,
    signals::ExitFlag,
    status::{Balance, ScriptHashStatus, UnspentEntry},
    types::ScriptHash,
};

/// Returned by [`Tracker::get_asset_history`].
pub(crate) struct AssetHistory {
    /// One entry per `(height, txid_prefix)` stored in the `asset_history` column
    /// family, sorted by ascending `(height, txid_prefix)`. Multiple entries may
    /// share the same block — that happens whenever several transactions in the
    /// same block touched the asset.
    pub confirmed: Vec<ConfirmedAssetEntry>,
    /// Unconfirmed mempool entries; last in the Electrum ordering convention.
    pub mempool: Vec<AssetMempoolEntry>,
}

pub(crate) struct ConfirmedAssetEntry {
    pub height: usize,
    pub block_hash: BlockHash,
    /// First 8 bytes of the txid that touched the asset. The row schema only
    /// stores a prefix; callers wanting full txids can fetch the block via the
    /// daemon and scan it for matching outputs/inputs.
    pub tx_prefix: [u8; 8],
}

pub(crate) struct AssetMempoolEntry {
    pub txid: Txid,
    pub has_unconfirmed_inputs: bool,
    pub fee: Amount,
}

/// One entry from [`Tracker::get_asset_funding`]. Represents a `(block, asset)`
/// pair where the queried scripthash received an asset-carrying output.
///
/// `asset_name_prefix` is `SHA256(name)[..8]` and is therefore a **one-way**
/// identifier: there is no direct index today that resolves it back to the
/// full name. The `asset_meta` CF is keyed by the full name, not by its hash
/// prefix, so recovering the name from this prefix alone would require either
/// a full scan of `asset_meta` (hashing each key) or a new auxiliary
/// `name_prefix → name` index — whichever the first RPC consumer of this
/// method chooses to build.
#[allow(dead_code)]
pub(crate) struct AssetFundingEntry {
    pub height: usize,
    pub block_hash: BlockHash,
    pub asset_name_prefix: [u8; 8],
}

/// Electrum protocol subscriptions' tracker
pub struct Tracker {
    index: Index,
    /// Replaced by `sync`, never changed in place (like the chain of `Index`).
    mempool: RwLock<Arc<Mempool>>,
    metrics: Metrics,
    ignore_mempool: bool,
}

pub(crate) enum Error {
    NotReady,
}

impl Tracker {
    pub fn new(
        config: &Config,
        metrics: Metrics,
        genesis_hash: BlockHash,
        genesis_header: NeuraiBlockHeader,
    ) -> Result<Self> {
        let store = DBStore::open(
            &config.db_path,
            config.db_log_dir.as_deref(),
            config.auto_reindex,
            config.db_parallelism,
        )?;
        let params = NetworkParams::for_network(config.network);
        let chain = Chain::new_with_genesis(params, genesis_hash, genesis_header);
        Ok(Self {
            index: Index::load(
                store,
                chain,
                &metrics,
                config.index_batch_size,
                config.index_lookup_limit,
                config.reindex_last_blocks,
            )
            .context("failed to open index")?,
            mempool: RwLock::new(Arc::new(Mempool::new(&metrics))),
            metrics,
            ignore_mempool: config.ignore_mempool,
        })
    }

    /// The current chain, which doesn't change while the caller keeps it.
    pub(crate) fn chain(&self) -> Arc<Chain> {
        self.index.chain()
    }

    pub(crate) fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub(crate) fn get_unspent(&self, status: &ScriptHashStatus) -> Vec<UnspentEntry> {
        status.get_unspent(&self.index.chain())
    }

    /// Indexes new blocks and updates the mempool. The RPC handlers keep
    /// working meanwhile, on the chain and mempool they already have.
    pub(crate) fn sync(&self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        let done = self.index.sync(daemon, exit_flag)?;
        if done && !self.ignore_mempool {
            let chain = self.index.chain();
            let fork = chain.params().fork_active(chain.height() + 1);
            let current = self.mempool();
            // asking the daemon takes most of the time: done without a lock
            if let Some(update) = current.poll(daemon, exit_flag, fork) {
                let mut next = Mempool::clone(&current);
                next.apply(update);
                *self.mempool.write() = Arc::new(next);
            }
        }
        Ok(done)
    }

    pub(crate) fn status(&self) -> Result<(), Error> {
        if self.index.is_ready() {
            return Ok(());
        }
        Err(Error::NotReady)
    }

    pub(crate) fn update_scripthash_status(
        &self,
        status: &mut ScriptHashStatus,
        daemon: &Daemon,
        cache: &Cache,
    ) -> Result<bool> {
        self.update_scripthash_status_on(status, &self.chain(), daemon, cache)
    }

    /// `update_scripthash_status` up to the tip of `chain`.
    pub(crate) fn update_scripthash_status_on(
        &self,
        status: &mut ScriptHashStatus,
        chain: &Chain,
        daemon: &Daemon,
        cache: &Cache,
    ) -> Result<bool> {
        let prev_statushash = status.statushash();
        status.sync(&self.index, chain, &self.mempool(), daemon, cache)?;
        Ok(prev_statushash != status.statushash())
    }

    pub(crate) fn get_balance(&self, status: &ScriptHashStatus) -> Balance {
        status.get_balance(&self.chain())
    }

    pub(crate) fn index(&self) -> &Index {
        &self.index
    }

    /// The current mempool, which doesn't change while the caller keeps it.
    pub(crate) fn mempool(&self) -> Arc<Mempool> {
        Arc::clone(&self.mempool.read())
    }

    pub(crate) fn compact_fee_histogram(&self) -> Vec<(f64, u64)> {
        self.mempool().compact_fee_histogram().to_vec()
    }

    /// One entry per row in `asset_history` — so multiple events in the same block
    /// all surface (deduplicated only on exact `(height, txid_prefix)` pairs, which
    /// is already handled by RocksDB because such rows share a single key).
    pub(crate) fn get_asset_history(&self, name: &[u8]) -> AssetHistory {
        let mut confirmed: Vec<ConfirmedAssetEntry> = self
            .index
            .filter_by_asset_name(name)
            .map(|(block_hash, height, tx_prefix)| ConfirmedAssetEntry {
                height,
                block_hash,
                tx_prefix,
            })
            .collect();
        confirmed.sort_by_key(|e| (e.height, e.tx_prefix));
        confirmed.dedup_by(|a, b| a.height == b.height && a.tx_prefix == b.tx_prefix);

        let current = self.mempool();
        let mut mempool: Vec<AssetMempoolEntry> = current
            .filter_by_asset_name(name)
            .into_iter()
            .map(|entry| AssetMempoolEntry {
                txid: entry.txid,
                has_unconfirmed_inputs: entry.has_unconfirmed_inputs,
                fee: entry.fee,
            })
            .collect();
        // Unconfirmed-input txs last, then by txid for determinism.
        mempool.sort_by_key(|e| (e.has_unconfirmed_inputs, e.txid));

        AssetHistory { confirmed, mempool }
    }

    /// Per `(scripthash, asset_name_prefix, height)` row. The `asset_funding`
    /// row layout is `scripthash_prefix(8) | name_prefix(8) | height(4)` — note
    /// that the middle 8 bytes identify the **asset name** (SHA-256 prefix), not
    /// the txid. So this query answers *"which distinct (block, asset) pairs did
    /// the given scripthash receive?"* — not per-transaction granularity.
    ///
    /// Currently unused by any RPC handler; kept for a future
    /// `scripthash.listassets`-style query.
    #[allow(dead_code)]
    pub(crate) fn get_asset_funding(
        &self,
        scripthash: ScriptHash,
    ) -> Vec<AssetFundingEntry> {
        let mut entries: Vec<AssetFundingEntry> = self
            .index
            .filter_asset_funding_by_scripthash(scripthash)
            .map(|(block_hash, height, name_prefix)| AssetFundingEntry {
                height,
                block_hash,
                asset_name_prefix: name_prefix,
            })
            .collect();
        entries.sort_by_key(|e| (e.height, e.asset_name_prefix));
        entries.dedup_by(|a, b| a.height == b.height && a.asset_name_prefix == b.asset_name_prefix);
        entries
    }

    pub(crate) fn lookup_transaction(
        &self,
        daemon: &Daemon,
        txid: Txid,
    ) -> Result<Option<(BlockHash, Box<[u8]>)>> {
        // Note: there are two blocks with coinbase transactions having same txid (see BIP-30)
        let blockhashes = self.index.filter_by_txid(txid);
        let mut result = None;
        daemon.for_blocks(blockhashes, |blockhash, block| {
            if result.is_some() {
                return; // keep first matching transaction
            }
            let params = self.chain().params();
            let mut visitor = FindTransaction::new(txid);
            result = match tx::visit_block(&block, params, &mut visitor) {
                Ok(_) => visitor.found.map(|tx| (blockhash, tx)),
                Err(e) => panic!("core returned invalid block: {:#}", e),
            };
        })?;
        Ok(result)
    }
}

pub struct FindTransaction {
    txid: bitcoin::Txid,
    found: Option<Box<[u8]>>, // no need to deserialize
}

impl FindTransaction {
    pub fn new(txid: bitcoin::Txid) -> Self {
        Self { txid, found: None }
    }
}
impl tx::Visitor for FindTransaction {
    fn visit_transaction(&mut self, tx: &tx::Transaction) -> ControlFlow<()> {
        if self.txid == tx.txid() {
            self.found = Some(tx.as_bytes().into());
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}
