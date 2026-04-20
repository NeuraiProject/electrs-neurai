use std::ops::ControlFlow;

use anyhow::{Context, Result};
use bitcoin::{BlockHash, Txid};
use bitcoin_slices::{bsl, Error::VisitBreak, Visit, Visitor};

use crate::neurai::block::neurai_to_bsl_block;
use crate::neurai::NetworkParams;
use bitcoin::Amount;

use crate::{
    cache::Cache,
    chain::Chain,
    config::Config,
    daemon::Daemon,
    db::DBStore,
    index::Index,
    mempool::{FeeHistogram, Mempool},
    metrics::Metrics,
    signals::ExitFlag,
    status::{Balance, ScriptHashStatus, UnspentEntry},
    types::{bsl_txid, AssetMetadata, ScriptHash},
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
    mempool: Mempool,
    metrics: Metrics,
    ignore_mempool: bool,
}

pub(crate) enum Error {
    NotReady,
}

impl Tracker {
    pub fn new(config: &Config, metrics: Metrics, genesis_hash: BlockHash) -> Result<Self> {
        let store = DBStore::open(
            &config.db_path,
            config.db_log_dir.as_deref(),
            config.auto_reindex,
            config.db_parallelism,
        )?;
        let params = NetworkParams::for_network(config.network);
        let chain = Chain::new_with_genesis(params, genesis_hash);
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
            mempool: Mempool::new(&metrics),
            metrics,
            ignore_mempool: config.ignore_mempool,
        })
    }

    pub(crate) fn chain(&self) -> &Chain {
        self.index.chain()
    }

    pub(crate) fn fees_histogram(&self) -> &FeeHistogram {
        self.mempool.fees_histogram()
    }

    pub(crate) fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub(crate) fn get_unspent(&self, status: &ScriptHashStatus) -> Vec<UnspentEntry> {
        status.get_unspent(self.index.chain())
    }

    pub(crate) fn sync(&mut self, daemon: &Daemon, exit_flag: &ExitFlag) -> Result<bool> {
        let done = self.index.sync(daemon, exit_flag)?;
        if done && !self.ignore_mempool {
            self.mempool.sync(daemon, exit_flag);
            // TODO: double check tip - and retry on diff
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
        let prev_statushash = status.statushash();
        status.sync(&self.index, &self.mempool, daemon, cache)?;
        Ok(prev_statushash != status.statushash())
    }

    pub(crate) fn get_balance(&self, status: &ScriptHashStatus) -> Balance {
        status.get_balance(self.chain())
    }

    pub(crate) fn get_asset_metadata(&self, name: &[u8]) -> Option<AssetMetadata> {
        self.index.get_asset_metadata(name)
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

        let mut mempool: Vec<AssetMempoolEntry> = self
            .mempool
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
            let (_, synthetic_block) = neurai_to_bsl_block(&block, params)
                .expect("core returned block with invalid header");
            let mut visitor = FindTransaction::new(txid);
            result = match bsl::Block::visit(&synthetic_block, &mut visitor) {
                Ok(_) | Err(VisitBreak) => visitor.found.map(|tx| (blockhash, tx)),
                Err(e) => panic!("core returned invalid block: {:?}", e),
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
impl Visitor for FindTransaction {
    fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
        if self.txid == bsl_txid(tx) {
            self.found = Some(tx.as_ref().into());
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}
