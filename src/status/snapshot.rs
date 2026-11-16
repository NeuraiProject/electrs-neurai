//! UTXO snapshots of the scripthashes with long histories: their confirmed
//! UTXOs and a journal of the last blocks' changes, shared by every client
//! (`listunspent`, `get_balance`, `get_mempool`, `utxo_sync`, `utxo_subscribe`).

use anyhow::Result;
use bitcoin::{hashes::Hash, BlockHash, OutPoint, Txid};
use parking_lot::Mutex;
use rayon::prelude::*;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

use super::{
    filter_block_txs_inputs, filter_block_txs_outputs, filter_outputs, listed, mempool_entries,
    mempool_history, mempool_utxo, utxo_of, Balance, OutputInfo, ScriptHashStatus, TxEntry,
    Unspent, UnspentStatus, LONG_HISTORY_BLOCKS,
};
use crate::{
    cache::Cache,
    chain::Chain,
    daemon::Daemon,
    index::Index,
    mempool::Mempool,
    types::ScriptHash,
    utxo::{Changes, MempoolPart, Sum256, Utxo},
};

/// Bounds of `UtxoSnapshots`.
const MAX_UTXO_SNAPSHOTS: usize = 1_000;
const MAX_UTXO_SNAPSHOT_OUTPOINTS: usize = 2_000_000;
/// New blocks after which an updated `UtxoSnapshot` is saved again.
const UTXO_SNAPSHOT_SAVE_BLOCKS: usize = 1_000;
/// Version of `UtxoSnapshot::to_bytes` (1: without the journal).
const UTXO_SNAPSHOT_FORMAT: u8 = 2;
/// Serialized size of a native UTXO: txid, vout, height, value, seq, asset tag.
const MIN_UTXO_BYTES: usize = 32 + 4 + 8 + 8 + 8 + 1;
/// Blocks of changes kept in the journal of a `UtxoSnapshot`: about 30 days
/// of 1-minute blocks. Clients that synced before get the whole set again.
const JOURNAL_BLOCKS: usize = 43_200;
/// Most UTXOs (added and removed) in the journal of a `UtxoSnapshot`.
const MAX_JOURNAL_UTXOS: usize = 2_000_000;
/// Most blocks kept after a reorg took them out of the active chain.
const MAX_STALE_BLOCKS: usize = 100;

/// Reads little-endian fields of `UtxoSnapshot::to_bytes`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.array()?))
    }

    fn usize(&mut self) -> Option<usize> {
        usize::try_from(self.u64()?).ok()
    }

    fn utxo(&mut self) -> Option<(OutPoint, OutputInfo)> {
        let outpoint = OutPoint::new(Txid::from_byte_array(self.array()?), self.u32()?);
        let info = OutputInfo {
            height: self.usize()?,
            value: self.u64()?,
            seq: self.usize()?,
            asset: match self.u8()? {
                0 => None,
                1 => {
                    let len = self.u16()?.into();
                    Some(String::from_utf8(self.take(len)?.to_vec()).ok()?)
                }
                _ => return None,
            },
        };
        Some((outpoint, info))
    }

    fn utxos(&mut self, bytes: usize) -> Option<Vec<(OutPoint, OutputInfo)>> {
        let count = self.usize()?;
        let mut utxos = Vec::with_capacity(count.min(bytes / MIN_UTXO_BYTES));
        for _ in 0..count {
            utxos.push(self.utxo()?);
        }
        Some(utxos)
    }

    fn journal_block(&mut self, bytes: usize) -> Option<JournalBlock> {
        Some(JournalBlock {
            hash: BlockHash::from_byte_array(self.array()?),
            prev: BlockHash::from_byte_array(self.array()?),
            height: self.usize()?,
            added: self.utxos(bytes)?,
            removed: self.utxos(bytes)?,
        })
    }
}

fn write_utxo(out: &mut Vec<u8>, outpoint: &OutPoint, info: &OutputInfo) {
    out.extend_from_slice(outpoint.txid.as_byte_array());
    out.extend_from_slice(&outpoint.vout.to_le_bytes());
    out.extend_from_slice(&(info.height as u64).to_le_bytes());
    out.extend_from_slice(&info.value.to_le_bytes());
    out.extend_from_slice(&(info.seq as u64).to_le_bytes());
    match &info.asset {
        None => out.push(0),
        Some(name) => {
            out.push(1);
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
    }
}

fn write_utxos<'a>(
    out: &mut Vec<u8>,
    utxos: impl ExactSizeIterator<Item = (&'a OutPoint, &'a OutputInfo)>,
) {
    out.extend_from_slice(&(utxos.len() as u64).to_le_bytes());
    for (outpoint, info) in utxos {
        write_utxo(out, outpoint, info);
    }
}

fn same_output(a: &OutputInfo, b: &OutputInfo) -> bool {
    a.height == b.height && a.value == b.value && a.asset == b.asset
}

/// Hash and number of the listed UTXOs of `outpoints`.
fn hash_and_count(outpoints: &HashMap<OutPoint, OutputInfo>) -> (Sum256, usize) {
    outpoints
        .par_iter()
        .filter(|(_, info)| listed(info))
        .map(|(outpoint, info)| (utxo_of(outpoint, info).hash(), 1))
        .reduce(
            || (Sum256::default(), 0),
            |(h1, n1), (h2, n2)| (h1.add(h2), n1 + n2),
        )
}

/// What the mempool does to the `confirmed` UTXOs of `scripthash`.
///
/// The mempool may be older than the confirmed UTXOs (a block indexed, the
/// mempool not polled yet): the outputs of its transactions that are already
/// confirmed are not listed, and their spends are not in `confirmed` anymore.
fn mempool_part(
    scripthash: ScriptHash,
    mempool: &Mempool,
    confirmed: &HashMap<OutPoint, OutputInfo>,
) -> MempoolPart {
    let mut added: HashMap<OutPoint, Utxo> = HashMap::new();
    for entry in mempool.filter_by_funding(&scripthash) {
        for output in filter_outputs(&entry.tx, scripthash, entry.fork) {
            let utxo = mempool_utxo(entry.txid, &output);
            if !confirmed.contains_key(&utxo.outpoint()) {
                added.insert(utxo.outpoint(), utxo);
            }
        }
    }
    let mut spent = Vec::new();
    let mut spend = |outpoint: &OutPoint, added: &mut HashMap<OutPoint, Utxo>| {
        if added.remove(outpoint).is_none() {
            if let Some(info) = confirmed.get(outpoint).filter(|info| listed(info)) {
                spent.push(utxo_of(outpoint, info));
            }
        }
    };
    // the fewest lookups: the spends of the mempool, or the outputs of the scripthash
    if confirmed.len() + added.len() > mempool.spends_count() {
        let spends: Vec<OutPoint> = mempool
            .spends()
            .map(|(outpoint, _txid)| *outpoint)
            .filter(|outpoint| confirmed.contains_key(outpoint) || added.contains_key(outpoint))
            .collect();
        for outpoint in spends {
            spend(&outpoint, &mut added);
        }
    } else {
        let candidates: Vec<OutPoint> = confirmed.keys().chain(added.keys()).copied().collect();
        for outpoint in candidates {
            if !mempool.filter_by_spending(&outpoint).is_empty() {
                spend(&outpoint, &mut added);
            }
        }
    }
    let mut part = MempoolPart {
        added: added.into_values().filter(|u| u.value > 0).collect(),
        spent,
    };
    part.sort();
    part
}

/// The UTXOs added and removed by a block, but those both added and spent in it.
#[derive(Clone, Debug)]
struct JournalBlock {
    hash: BlockHash,
    prev: BlockHash,
    height: usize,
    added: Vec<(OutPoint, OutputInfo)>,
    removed: Vec<(OutPoint, OutputInfo)>,
}

impl JournalBlock {
    fn len(&self) -> usize {
        self.added.len() + self.removed.len()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.hash.as_byte_array());
        out.extend_from_slice(self.prev.as_byte_array());
        out.extend_from_slice(&(self.height as u64).to_le_bytes());
        write_utxos(out, self.added.iter().map(|(o, i)| (o, i)));
        write_utxos(out, self.removed.iter().map(|(o, i)| (o, i)));
    }
}

/// The changes of several journal blocks put together.
#[derive(Default)]
struct NetChanges {
    removed: HashMap<OutPoint, OutputInfo>,
    added: HashMap<OutPoint, OutputInfo>,
}

impl NetChanges {
    fn remove(&mut self, outpoint: &OutPoint, info: &OutputInfo) {
        if self.added.remove(outpoint).is_none() {
            self.removed.insert(*outpoint, info.clone());
        }
    }

    fn add(&mut self, outpoint: &OutPoint, info: &OutputInfo) {
        match self.removed.get(outpoint) {
            Some(removed) if same_output(removed, info) => {
                self.removed.remove(outpoint);
            }
            _ => {
                self.added.insert(*outpoint, info.clone());
            }
        }
    }

    fn apply(&mut self, block: &JournalBlock) {
        block.removed.iter().for_each(|(o, i)| self.remove(o, i));
        block.added.iter().for_each(|(o, i)| self.add(o, i));
    }

    fn undo(&mut self, block: &JournalBlock) {
        block.added.iter().for_each(|(o, i)| self.remove(o, i));
        block.removed.iter().for_each(|(o, i)| self.add(o, i));
    }

    fn into_changes(self) -> Changes {
        let utxos = |map: HashMap<OutPoint, OutputInfo>| -> Vec<Utxo> {
            map.iter()
                .filter(|(_, info)| listed(info))
                .map(|(outpoint, info)| utxo_of(outpoint, info))
                .collect()
        };
        Changes {
            removed: utxos(self.removed),
            added: utxos(self.added),
        }
    }
}

/// Confirmed unspent outputs of a scripthash with a long history, kept between
/// queries so that `listunspent`, `get_balance` and `get_mempool` only read the
/// blocks after `tip` instead of every block of the history again. Its journal
/// tells `utxo_sync` what changed since one of its last blocks.
pub(crate) struct UtxoSnapshot {
    scripthash: ScriptHash,
    tip: BlockHash,
    /// Height of `tip`, as of the last `update` (0 before it, once read from the DB).
    tip_height: usize,
    unspent: Unspent,
    /// Blocks read to build it: past that many new blocks, rebuilding is cheaper.
    history_blocks: usize,
    /// New blocks applied since it was last saved in the DB.
    unsaved_blocks: usize,
    /// The last blocks applied, oldest first: `journal[0].prev` is where it
    /// starts, the last one is `tip`.
    journal: VecDeque<JournalBlock>,
    journal_utxos: usize,
    /// Blocks undone by reorgs, for the clients that synced on them.
    stale: Vec<JournalBlock>,
    /// Hash and number of the listed UTXOs, computed when first needed (by
    /// `utxo_sync` or `utxo_subscribe`), then kept up to date.
    hashed: Option<(Sum256, usize)>,
}

/// Whether the index shows `scripthash` paid in at least `LONG_HISTORY_BLOCKS`
/// blocks: then `UtxoSnapshot::build` is the way to get its UTXOs.
pub(crate) fn has_long_history(index: &Index, scripthash: ScriptHash) -> bool {
    let height = index.chain().height();
    index
        .funding_heights(scripthash)
        .filter(|&h| h <= height)
        .take(LONG_HISTORY_BLOCKS)
        .count()
        >= LONG_HISTORY_BLOCKS
}

impl UtxoSnapshot {
    fn new(
        scripthash: ScriptHash,
        tip: BlockHash,
        unspent: Unspent,
        history_blocks: usize,
    ) -> Self {
        Self {
            scripthash,
            tip,
            tip_height: 0,
            unspent,
            history_blocks,
            unsaved_blocks: 0,
            journal: VecDeque::new(),
            journal_utxos: 0,
            stale: Vec::new(),
            hashed: None,
        }
    }

    /// Reads the blocks of `scripthash` keeping only its outputs, then removes
    /// the spent ones: much less memory than a `ScriptHashStatus`, which keeps
    /// every transaction of the history (a ~950,000 one took ~700 MB).
    pub(crate) fn build(scripthash: ScriptHash, index: &Index, daemon: &Daemon) -> Result<Self> {
        let chain = index.chain();
        let params = chain.params();
        let tip = chain.tip();
        let mut heights = index.limit_result(index.funding_heights(scripthash))?;
        heights.sort_unstable();
        heights.dedup();
        let funding: Vec<BlockHash> = heights
            .into_iter()
            .filter_map(|h| chain.get_block_hash(h))
            .collect();
        let mut unspent = Unspent::default();
        // In chain order: `Unspent::insert` numbers the outputs in that order.
        daemon.for_blocks(funding.iter().copied(), |blockhash, block| {
            let height = chain.get_block_height(&blockhash).expect("requested block");
            let fork = params.fork_active(height);
            for funding in filter_block_txs_outputs(&block, scripthash, params, fork) {
                let entry = TxEntry {
                    txid: funding.txid,
                    outputs: funding.result,
                    spent: Vec::new(),
                };
                unspent.insert(&entry, height);
            }
        })?;
        let spending: HashSet<BlockHash> = unspent
            .outpoints
            .par_iter()
            .flat_map_iter(|(outpoint, _)| {
                // through the same chain as the blocks above
                index
                    .spending_heights(*outpoint)
                    .filter_map(|height| chain.get_block_hash(height))
            })
            .collect();
        let history_blocks = funding.len() + spending.len();
        daemon.for_blocks(spending, |_, block| {
            let spent =
                filter_block_txs_inputs(&block, |o| unspent.outpoints.contains_key(o), params);
            for outpoint in spent.iter().flat_map(|tx| &tx.result) {
                unspent.outpoints.remove(outpoint);
            }
        })?;
        unspent.outpoints.shrink_to_fit();
        debug!(
            "UTXO snapshot of {}: {} UTXOs from {} blocks",
            scripthash,
            unspent.outpoints.len(),
            history_blocks
        );
        let mut snapshot = Self::new(scripthash, tip, unspent, history_blocks);
        snapshot.tip_height = chain.height();
        Ok(snapshot)
    }

    /// Snapshot of a synced `status`, if its history is long enough to keep one.
    pub(crate) fn of_long_history(status: &ScriptHashStatus, chain: &Chain) -> Option<Self> {
        let history_blocks = status.confirmed_blocks();
        if history_blocks < LONG_HISTORY_BLOCKS {
            return None;
        }
        // its blocks must all be in `chain`
        let tip_height = chain.get_block_height(&status.tip)?;
        let unspent = Unspent::confirmed(status, chain);
        debug!(
            "UTXO snapshot of {}: {} UTXOs from {} blocks",
            status.scripthash,
            unspent.outpoints.len(),
            history_blocks
        );
        let mut snapshot = Self::new(status.scripthash, status.tip, unspent, history_blocks);
        snapshot.tip_height = tip_height;
        Some(snapshot)
    }

    /// Whether enough new blocks were applied since it was last saved: saving
    /// it then spares reading them again after a crash.
    pub(crate) fn save_due(&self) -> bool {
        self.unsaved_blocks >= UTXO_SNAPSHOT_SAVE_BLOCKS
    }

    pub(crate) fn mark_saved(&mut self) {
        self.unsaved_blocks = 0;
    }

    fn len(&self) -> usize {
        self.unspent.outpoints.len() + self.journal_utxos
    }

    pub(crate) fn scripthash(&self) -> ScriptHash {
        self.scripthash
    }

    pub(crate) fn tip(&self) -> BlockHash {
        self.tip
    }

    pub(crate) fn tip_height(&self) -> usize {
        self.tip_height
    }

    /// Hash and number of the listed UTXOs.
    fn hashes(&mut self) -> (Sum256, usize) {
        let outpoints = &self.unspent.outpoints;
        *self.hashed.get_or_insert_with(|| hash_and_count(outpoints))
    }

    pub(crate) fn set_hash(&mut self) -> Sum256 {
        self.hashes().0
    }

    pub(crate) fn count(&mut self) -> usize {
        self.hashes().1
    }

    /// Adds `info` to the hash and number, if they are computed.
    fn hash_in(&mut self, outpoint: &OutPoint, info: &OutputInfo) {
        if let (true, Some((hash, count))) = (listed(info), self.hashed.as_mut()) {
            *hash = hash.add(utxo_of(outpoint, info).hash());
            *count += 1;
        }
    }

    fn add_utxo(&mut self, outpoint: OutPoint, info: OutputInfo) {
        self.hash_in(&outpoint, &info);
        if let Some(previous) = self.unspent.outpoints.insert(outpoint, info) {
            self.forget(&outpoint, &previous);
        }
    }

    fn remove_utxo(&mut self, outpoint: &OutPoint) -> Option<OutputInfo> {
        let info = self.unspent.outpoints.remove(outpoint)?;
        self.forget(outpoint, &info);
        Some(info)
    }

    fn forget(&mut self, outpoint: &OutPoint, info: &OutputInfo) {
        if let (true, Some((hash, count))) = (listed(info), self.hashed.as_mut()) {
            *hash = hash.sub(utxo_of(outpoint, info).hash());
            *count -= 1;
        }
    }

    fn undo(&mut self, block: &JournalBlock) {
        for (outpoint, _) in &block.added {
            self.remove_utxo(outpoint);
        }
        for (outpoint, info) in &block.removed {
            self.add_utxo(*outpoint, info.clone());
        }
    }

    /// Where the journal starts.
    fn journal_start(&self) -> BlockHash {
        self.journal.front().map_or(self.tip, |block| block.prev)
    }

    /// Serialized to keep it in the DB (`from_bytes` reads it back).
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 3 * 8 + self.len() * MIN_UTXO_BYTES);
        out.push(UTXO_SNAPSHOT_FORMAT);
        out.extend_from_slice(self.tip.as_byte_array());
        out.extend_from_slice(&(self.history_blocks as u64).to_le_bytes());
        out.extend_from_slice(&(self.unspent.next_seq as u64).to_le_bytes());
        write_utxos(&mut out, self.unspent.outpoints.iter());
        out.extend_from_slice(&(self.journal.len() as u64).to_le_bytes());
        self.journal.iter().for_each(|block| block.write(&mut out));
        out.extend_from_slice(&(self.stale.len() as u64).to_le_bytes());
        self.stale.iter().for_each(|block| block.write(&mut out));
        out
    }

    /// `None` if `bytes` are not a snapshot of this format (or of format 1,
    /// read without a journal).
    pub(crate) fn from_bytes(scripthash: ScriptHash, bytes: &[u8]) -> Option<Self> {
        let mut r = Reader(bytes);
        let format = r.u8()?;
        if format != 1 && format != UTXO_SNAPSHOT_FORMAT {
            return None;
        }
        let tip = BlockHash::from_byte_array(r.array()?);
        let history_blocks = r.usize()?;
        let next_seq = r.usize()?;
        let utxos = r.utxos(bytes.len())?;
        let count = utxos.len();
        let outpoints: HashMap<OutPoint, OutputInfo> = utxos.into_iter().collect();
        if outpoints.len() != count {
            return None;
        }
        let mut journal = VecDeque::new();
        let mut stale = Vec::new();
        if format == UTXO_SNAPSHOT_FORMAT {
            for _ in 0..r.usize()? {
                journal.push_back(r.journal_block(bytes.len())?);
            }
            for _ in 0..r.usize()? {
                stale.push(r.journal_block(bytes.len())?);
            }
        }
        if !r.0.is_empty() {
            return None;
        }
        if journal
            .back()
            .is_some_and(|block: &JournalBlock| block.hash != tip)
        {
            return None;
        }
        let unspent = Unspent {
            outpoints,
            balance: Balance::default(),
            next_seq,
        };
        let mut snapshot = Self::new(scripthash, tip, unspent, history_blocks);
        snapshot.journal_utxos = journal.iter().map(JournalBlock::len).sum();
        snapshot.journal = journal;
        snapshot.stale = stale;
        Some(snapshot)
    }

    /// Applies the blocks after `tip`, undoing first those a reorg took out of
    /// the chain. Returns `false` when the snapshot must be rebuilt instead:
    /// its journal doesn't go back to the reorg, or there are more new blocks
    /// than the history had.
    pub(crate) fn update(&mut self, index: &Index, daemon: &Daemon) -> Result<bool> {
        let chain = index.chain();
        self.update_to(&chain, daemon)
    }

    fn update_to(&mut self, chain: &Chain, daemon: &Daemon) -> Result<bool> {
        if self.tip == chain.tip() {
            self.tip_height = chain.height();
            return Ok(true);
        }
        while chain.get_block_height(&self.tip).is_none() {
            match self.journal.pop_back() {
                Some(block) if block.hash == self.tip => {
                    debug!(
                        "UTXO snapshot of {}: undoing block {} (reorg)",
                        self.scripthash, block.hash
                    );
                    self.undo(&block);
                    self.journal_utxos -= block.len();
                    self.tip = block.prev;
                    self.unsaved_blocks += 1;
                    self.stale.push(block);
                }
                _ => return Ok(false), // reorg below the journal
            }
        }
        let height = chain.get_block_height(&self.tip).expect("in the chain");
        let new_blocks = chain.height() - height;
        if new_blocks > self.history_blocks {
            return Ok(false);
        }
        let blockhashes: Vec<BlockHash> = (height + 1..=chain.height())
            .map(|h| chain.get_block_hash(h).expect("height within the chain"))
            .collect();
        let params = chain.params();
        let scripthash = self.scripthash;
        let mut prev = self.tip;
        // Every new block, in chain order: its outputs to the scripthash first,
        // then its inputs spending them (a transaction can only spend outputs of
        // the transactions before it).
        daemon.for_blocks(blockhashes, |blockhash, block| {
            let height = chain.get_block_height(&blockhash).expect("requested block");
            let fork = params.fork_active(height);
            let mut added: HashMap<OutPoint, OutputInfo> = HashMap::new();
            for funding in filter_block_txs_outputs(&block, scripthash, params, fork) {
                let entry = TxEntry {
                    txid: funding.txid,
                    outputs: funding.result,
                    spent: Vec::new(),
                };
                self.unspent.insert(&entry, height);
                for outpoint in entry.funding_outpoints() {
                    let info = self.unspent.outpoints[&outpoint].clone();
                    // `Unspent::insert` doesn't hash: do it as `add_utxo` does
                    self.hash_in(&outpoint, &info);
                    added.insert(outpoint, info);
                }
            }
            let spent =
                filter_block_txs_inputs(&block, |o| self.unspent.outpoints.contains_key(o), params);
            let mut removed = Vec::new();
            for outpoint in spent.iter().flat_map(|tx| &tx.result) {
                if let Some(info) = self.remove_utxo(outpoint) {
                    if added.remove(outpoint).is_none() {
                        removed.push((*outpoint, info));
                    }
                }
            }
            let block = JournalBlock {
                hash: blockhash,
                prev,
                height,
                added: added.into_iter().collect(),
                removed,
            };
            prev = blockhash;
            self.journal_utxos += block.len();
            self.journal.push_back(block);
            // consistent even if a later block fails to come
            self.tip = blockhash;
            self.tip_height = height;
            self.unsaved_blocks += 1;
        })?;
        debug!(
            "UTXO snapshot of {}: {} UTXOs after {} new blocks",
            scripthash,
            self.unspent.outpoints.len(),
            new_blocks
        );
        debug_assert_eq!(self.tip, chain.tip());
        self.trim_journal(chain.height());
        Ok(true)
    }

    fn trim_journal(&mut self, tip_height: usize) {
        let old = |block: &JournalBlock| block.height + JOURNAL_BLOCKS <= tip_height;
        while let Some(front) = self.journal.front() {
            if !old(front) && self.journal_utxos <= MAX_JOURNAL_UTXOS {
                break;
            }
            let front = self.journal.pop_front().expect("not empty");
            self.journal_utxos -= front.len();
        }
        self.stale.retain(|block| !old(block));
        if self.stale.len() > MAX_STALE_BLOCKS {
            self.stale.drain(..self.stale.len() - MAX_STALE_BLOCKS);
        }
    }

    /// Position after `block` in the journal, if the journal starts at or
    /// goes through it.
    fn journal_position(&self, block: &BlockHash) -> Option<usize> {
        if *block == self.journal_start() {
            return Some(0);
        }
        self.journal
            .iter()
            .position(|b| b.hash == *block)
            .map(|i| i + 1)
    }

    /// How to go from block `from` to `tip`: the stale blocks to undo (from
    /// `from` back), then the journal from the returned position. `None` when
    /// the journal doesn't tell.
    fn path_from(&self, from: &BlockHash) -> Option<(Vec<&JournalBlock>, usize)> {
        let mut undone = Vec::new();
        let mut block = *from;
        loop {
            if let Some(start) = self.journal_position(&block) {
                return Some((undone, start));
            }
            // a stale block: undo it, then look for its parent
            let stale = self.stale.iter().rev().find(|b| b.hash == block)?;
            undone.push(stale);
            if undone.len() > MAX_STALE_BLOCKS {
                return None;
            }
            block = stale.prev;
        }
    }

    /// Whether `changes_since(from)` can tell.
    pub(crate) fn knows(&self, from: &BlockHash) -> bool {
        self.path_from(from).is_some()
    }

    /// What changed from block `from` to `tip`, if the journal tells: `from`
    /// is one of its blocks, where it starts, or a block it undid whose
    /// parents lead back to one of those.
    pub(crate) fn changes_since(&self, from: &BlockHash) -> Option<Changes> {
        let (undone, start) = self.path_from(from)?;
        let mut net = NetChanges::default();
        undone.iter().for_each(|stale| net.undo(stale));
        self.journal.range(start..).for_each(|b| net.apply(b));
        Some(net.into_changes())
    }

    /// The listed UTXOs, by outpoint.
    #[cfg(test)]
    pub(crate) fn utxos(&self) -> HashMap<OutPoint, Utxo> {
        super::listed_utxos(&self.unspent.outpoints)
    }

    /// The listed UTXOs.
    pub(crate) fn utxo_list(&self) -> Vec<Utxo> {
        self.unspent
            .outpoints
            .iter()
            .filter(|(_, info)| listed(info))
            .map(|(outpoint, info)| utxo_of(outpoint, info))
            .collect()
    }

    pub(crate) fn mempool_part(&self, mempool: &Mempool) -> MempoolPart {
        mempool_part(self.scripthash, mempool, &self.unspent.outpoints)
    }

    /// Unspent outputs, balance and mempool history, with the current mempool.
    pub(crate) fn unspent_status(&self, mempool: &Mempool, cache: &Cache) -> UnspentStatus {
        let mut outpoints: HashSet<OutPoint> = self.unspent.outpoints.keys().copied().collect();
        let entries = mempool_entries(self.scripthash, mempool, cache, &mut outpoints);
        UnspentStatus {
            unspent: self.unspent.clone().with_mempool(&entries),
            mempool_history: mempool_history(&entries, mempool),
        }
    }
}

/// A place for the `UtxoSnapshot` of a scripthash: whoever builds or updates
/// it holds its lock, so that the others asking for it wait for the result
/// instead of reading the same blocks too.
pub(crate) struct SnapshotSlot {
    pub(crate) snapshot: Mutex<Option<UtxoSnapshot>>,
    used: AtomicU64,
    /// UTXOs of the snapshot, as of its last `UtxoSnapshots::update`.
    size: AtomicUsize,
}

/// `UtxoSnapshot`s, the least recently used dropped first beyond
/// `max_snapshots` snapshots or `max_outpoints` UTXOs.
pub(crate) struct UtxoSnapshots {
    slots: Mutex<HashMap<ScriptHash, Arc<SnapshotSlot>>>,
    clock: AtomicU64,
    max_snapshots: usize,
    max_outpoints: usize,
}

impl Default for UtxoSnapshots {
    fn default() -> Self {
        Self::new(MAX_UTXO_SNAPSHOTS, MAX_UTXO_SNAPSHOT_OUTPOINTS)
    }
}

impl UtxoSnapshots {
    fn new(max_snapshots: usize, max_outpoints: usize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            clock: AtomicU64::new(0),
            max_snapshots,
            max_outpoints,
        }
    }

    /// The slot of `scripthash` (an empty one if it has no snapshot).
    pub(crate) fn slot(&self, scripthash: ScriptHash) -> Arc<SnapshotSlot> {
        let used = self.clock.fetch_add(1, Ordering::Relaxed) + 1;
        let mut slots = self.slots.lock();
        let slot = slots.entry(scripthash).or_insert_with(|| {
            Arc::new(SnapshotSlot {
                snapshot: Mutex::new(None),
                used: AtomicU64::new(0),
                size: AtomicUsize::new(0),
            })
        });
        slot.used.store(used, Ordering::Relaxed);
        Arc::clone(slot)
    }

    /// Whether `scripthash` has a snapshot (or one is being built).
    pub(crate) fn contains(&self, scripthash: &ScriptHash) -> bool {
        self.slots.lock().get(scripthash).is_some_and(|slot| {
            slot.size.load(Ordering::Relaxed) > 0
                || slot.snapshot.try_lock().is_none_or(|s| s.is_some())
        })
    }

    /// Records the size of the snapshot of `slot` (locked by the caller as
    /// `snapshot`), and drops the least recently used ones over the bounds.
    pub(crate) fn update(&self, slot: &SnapshotSlot, snapshot: &Option<UtxoSnapshot>) {
        let oversized = snapshot
            .as_ref()
            .is_some_and(|s| s.len() > self.max_outpoints);
        let size = match snapshot {
            Some(s) if !oversized => s.len(),
            _ => 0,
        };
        slot.size.store(size, Ordering::Relaxed);
        let mut slots = self.slots.lock();
        if let (true, Some(s)) = (oversized, snapshot) {
            // larger than the bound: used by its holder, then dropped
            if slots
                .get(&s.scripthash)
                .is_some_and(|kept| std::ptr::eq(Arc::as_ptr(kept), slot))
            {
                slots.remove(&s.scripthash);
            }
            return;
        }
        let mut total: usize = slots.values().map(|s| s.size.load(Ordering::Relaxed)).sum();
        // empty slots first, then the least recently used
        let mut order: Vec<(bool, u64, ScriptHash)> = slots
            .iter()
            .filter(|(_, s)| !std::ptr::eq(Arc::as_ptr(s), slot))
            .map(|(scripthash, s)| {
                let size = s.size.load(Ordering::Relaxed);
                (size > 0, s.used.load(Ordering::Relaxed), *scripthash)
            })
            .collect();
        order.sort_unstable();
        for (_, _, scripthash) in order {
            if total <= self.max_outpoints && slots.len() <= self.max_snapshots {
                break;
            }
            let candidate = &slots[&scripthash];
            // a slot in use stays
            if Arc::strong_count(candidate) > 1 || candidate.snapshot.try_lock().is_none() {
                continue;
            }
            total -= candidate.size.load(Ordering::Relaxed);
            slots.remove(&scripthash);
        }
    }

    /// Adds a snapshot read from the DB.
    pub(crate) fn insert(&self, snapshot: UtxoSnapshot) {
        let slot = self.slot(snapshot.scripthash);
        let mut guard = slot.snapshot.lock();
        *guard = Some(snapshot);
        self.update(&slot, &guard);
    }

    /// Runs `f` on every snapshot (waiting for those in use).
    pub(crate) fn for_each(&self, mut f: impl FnMut(&UtxoSnapshot)) {
        let slots: Vec<Arc<SnapshotSlot>> = self.slots.lock().values().cloned().collect();
        for slot in slots {
            if let Some(snapshot) = slot.snapshot.lock().as_ref() {
                f(snapshot);
            }
        }
    }

    #[cfg(test)]
    fn kept(&self, scripthash: &ScriptHash) -> bool {
        self.slots
            .lock()
            .get(scripthash)
            .is_some_and(|slot| slot.snapshot.lock().is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{native_entry, outpoint};
    use crate::types::ScriptHash;
    use bitcoin::hashes::Hash as _;
    use bitcoin::Amount;

    fn snapshot(n: u8, utxos: u32) -> super::UtxoSnapshot {
        use bitcoin::hashes::Hash;
        let mut unspent = super::super::Unspent::default();
        unspent.insert(&native_entry(n, &vec![1; utxos as usize], &[]), 1);
        super::UtxoSnapshot::new(
            ScriptHash::hash(&[n]),
            bitcoin::BlockHash::all_zeros(),
            unspent,
            super::super::LONG_HISTORY_BLOCKS,
        )
    }

    #[test]
    fn utxo_snapshots_drop_the_least_recently_used() {
        let key = |n: u8| ScriptHash::hash(&[n]);
        let snapshots = super::UtxoSnapshots::new(3, 10);
        for n in 1..=3 {
            snapshots.insert(snapshot(n, 2));
        }
        // using 1 makes 2 the least recently used
        drop(snapshots.slot(key(1)));
        snapshots.insert(snapshot(4, 2)); // 4 snapshots > 3
        assert!(!snapshots.kept(&key(2)));
        assert!(snapshots.kept(&key(1)) && snapshots.kept(&key(3)) && snapshots.kept(&key(4)));

        snapshots.insert(snapshot(5, 7)); // 13 UTXOs > 10: drops 3 and 1
        assert!(!snapshots.kept(&key(3)));
        assert!(!snapshots.kept(&key(1)));
        assert!(snapshots.kept(&key(4)) && snapshots.kept(&key(5)));

        snapshots.insert(snapshot(6, 11)); // larger than the bound: not kept
        assert!(!snapshots.kept(&key(6)));
        assert!(snapshots.kept(&key(4)) && snapshots.kept(&key(5)));
        assert!(snapshots.contains(&key(5)));
        assert!(!snapshots.contains(&key(6)));
    }

    #[test]
    fn utxo_snapshot_slots_are_shared() {
        let key = ScriptHash::hash(&[1]);
        let snapshots = super::UtxoSnapshots::default();
        let a = snapshots.slot(key);
        let b = snapshots.slot(key);
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        // a slot in use is never dropped
        let guard = a.snapshot.lock();
        drop(guard);
    }

    fn asset_entry(n: u8, index: u32, name: &str, amount: u64) -> super::super::TxEntry {
        super::super::TxEntry {
            outputs: vec![super::super::TxOutput {
                index,
                value: Amount::from_sat(0),
                asset: Some(super::super::AssetTxOutput {
                    name: name.to_owned(),
                    amount,
                }),
            }],
            ..native_entry(n, &[], &[])
        }
    }

    #[test]
    fn utxo_snapshot_bytes_round_trip() {
        use bitcoin::hashes::Hash;
        let mut original = snapshot(7, 3);
        original.tip = bitcoin::BlockHash::from_byte_array([9; 32]);
        original
            .unspent
            .insert(&asset_entry(8, 2, "TOKEN/SUB", 5 * 100_000_000), 1_870_000);
        let (hash, count) = super::hash_and_count(&original.unspent.outpoints);

        let bytes = original.to_bytes();
        let read = super::UtxoSnapshot::from_bytes(original.scripthash, &bytes).unwrap();
        assert_eq!(read.tip, original.tip);
        assert_eq!(read.history_blocks, original.history_blocks);
        assert_eq!(read.unspent.next_seq, original.unspent.next_seq);
        let mut read = read;
        assert_eq!((read.set_hash(), read.count()), (hash, count));
        assert_eq!(count, 4);
        let entries = |s: super::UtxoSnapshot| -> Vec<_> {
            s.unspent
                .with_mempool(&[])
                .into_entries()
                .into_iter()
                .map(|e| (e.tx_hash, e.tx_pos, e.height, e.value, e.asset))
                .collect()
        };
        let listed = entries(read);
        assert_eq!(listed.len(), 4);
        assert_eq!(listed[3].4.as_deref(), Some("TOKEN/SUB"));
        assert_eq!(listed, entries(original));

        // truncated, longer, or of another format
        let read = |b: &[u8]| super::UtxoSnapshot::from_bytes(ScriptHash::hash(&[7]), b);
        assert!(read(&bytes[..bytes.len() - 1]).is_none());
        assert!(read(&[&bytes[..], &[0]].concat()).is_none());
        let mut other = bytes.clone();
        other[0] = 3;
        assert!(read(&other).is_none());

        // format 1: the same without the journal and stale blocks
        let mut v1 = bytes[..bytes.len() - 16].to_vec();
        v1[0] = 1;
        let mut old = read(&v1).unwrap();
        assert_eq!((old.set_hash(), old.count()), (hash, count));
        assert!(old.journal.is_empty());
    }

    /// A block of the test journal: `added` outputs of a new transaction
    /// `n` and `removed` outpoints.
    fn apply_block(
        snapshot: &mut super::UtxoSnapshot,
        n: u8,
        height: usize,
        added: &[u64],
        removed: &[bitcoin::OutPoint],
    ) {
        use bitcoin::hashes::Hash;
        let hash = bitcoin::BlockHash::from_byte_array([n; 32]);
        let mut block = super::JournalBlock {
            hash,
            prev: snapshot.tip,
            height,
            added: vec![],
            removed: vec![],
        };
        for (vout, value) in (0u32..).zip(added) {
            let info = super::super::OutputInfo {
                height,
                value: *value,
                asset: None,
                seq: 0,
            };
            snapshot.add_utxo(outpoint(n, vout), info.clone());
            block.added.push((outpoint(n, vout), info));
        }
        for o in removed {
            let info = snapshot.remove_utxo(o).unwrap();
            block.removed.push((*o, info));
        }
        snapshot.journal_utxos += block.len();
        snapshot.journal.push_back(block);
        snapshot.tip = hash;
    }

    fn sorted(mut utxos: Vec<crate::utxo::Utxo>) -> Vec<(bitcoin::OutPoint, usize)> {
        utxos.sort_by_key(|u| (u.outpoint(), u.height));
        utxos
            .into_iter()
            .map(|u| (u.outpoint(), u.height))
            .collect()
    }

    #[test]
    fn utxo_snapshot_journal_changes() {
        use bitcoin::hashes::Hash;
        let block = |n: u8| bitcoin::BlockHash::from_byte_array([n; 32]);
        let mut s = snapshot(1, 2); // 1:0 and 1:1 at height 1, tip 000…
        s.hashes(); // kept up to date from now on
        let start = s.tip;
        let at_start = s.utxos();
        apply_block(&mut s, 2, 10, &[5, 6], &[outpoint(1, 0)]);
        let at_2 = s.utxos();
        apply_block(&mut s, 3, 11, &[7], &[outpoint(2, 1)]);
        apply_block(&mut s, 4, 12, &[0, 8], &[outpoint(3, 0)]); // a zero-value output
        let now = s.utxos();
        assert_eq!(s.count(), now.len());
        assert_eq!(s.set_hash(), crate::utxo::set_hash(now.values()));

        // from the tip: nothing
        let none = s.changes_since(&block(4)).unwrap();
        assert!(none.added.is_empty() && none.removed.is_empty());
        // from each block: the set differences
        for (from, set) in [(start, &at_start), (block(2), &at_2)] {
            let changes = s.changes_since(&from).unwrap();
            let expected = crate::utxo::Changes::between(set, &now);
            assert_eq!(sorted(changes.removed.clone()), sorted(expected.removed));
            assert_eq!(sorted(changes.added.clone()), sorted(expected.added));
            assert_eq!(
                crate::utxo::set_hash(set.values()).add(changes.hash()),
                s.set_hash()
            );
        }
        // 3:0 was added and spent after block 2: not listed at all
        let changes = s.changes_since(&block(2)).unwrap();
        assert!(changes.added.iter().all(|u| u.outpoint() != outpoint(3, 0)));
        assert!(changes
            .removed
            .iter()
            .all(|u| u.outpoint() != outpoint(3, 0)));
        // an unknown block
        assert!(s.changes_since(&block(99)).is_none());
        assert!(!s.knows(&block(99)));
        assert!(s.knows(&block(2)) && s.knows(&start));
    }

    #[test]
    fn utxo_snapshot_undoes_reorgs_and_serves_stale_blocks() {
        use bitcoin::hashes::Hash;
        let block = |n: u8| bitcoin::BlockHash::from_byte_array([n; 32]);
        let mut s = snapshot(1, 2);
        s.hashes();
        apply_block(&mut s, 2, 10, &[5], &[outpoint(1, 0)]);
        let at_2 = s.utxos();
        let hash_at_2 = s.set_hash();
        apply_block(&mut s, 3, 11, &[7], &[outpoint(2, 0)]);
        let at_3 = s.utxos();

        // a reorg replaces block 3 by block 4: undo 3 as `update_to` does
        let stale = s.journal.pop_back().unwrap();
        s.undo(&stale);
        s.journal_utxos -= stale.len();
        s.tip = stale.prev;
        s.stale.push(stale);
        assert_eq!(s.utxos(), at_2);
        assert_eq!(s.set_hash(), hash_at_2);
        apply_block(&mut s, 4, 11, &[9, 9], &[outpoint(1, 1)]);
        let now = s.utxos();
        assert_eq!(s.set_hash(), crate::utxo::set_hash(now.values()));

        // a client on the stale block 3 gets back to the active chain
        let changes = s.changes_since(&block(3)).unwrap();
        let expected = crate::utxo::Changes::between(&at_3, &now);
        assert_eq!(sorted(changes.removed.clone()), sorted(expected.removed));
        assert_eq!(sorted(changes.added.clone()), sorted(expected.added));
        assert!(s.knows(&block(3)));

        // the journal and stale blocks survive a restart
        let mut read = super::UtxoSnapshot::from_bytes(s.scripthash, &s.to_bytes()).unwrap();
        assert_eq!(read.journal.len(), 2);
        assert_eq!(read.stale.len(), 1);
        assert_eq!(read.set_hash(), s.set_hash());
        let again = read.changes_since(&block(3)).unwrap();
        assert_eq!(sorted(again.added), sorted(changes.added));
        assert_eq!(sorted(again.removed), sorted(changes.removed));
    }

    #[test]
    fn utxo_snapshot_stale_blocks_out_of_the_journal() {
        use bitcoin::hashes::Hash;
        let block = |n: u8| bitcoin::BlockHash::from_byte_array([n; 32]);
        let mut s = snapshot(1, 2);
        apply_block(&mut s, 2, 10, &[5], &[]);
        apply_block(&mut s, 3, 11, &[6], &[]);
        // undid long ago, from a parent the journal doesn't have anymore
        s.stale.push(super::JournalBlock {
            hash: block(9),
            prev: block(77),
            height: 5,
            added: vec![],
            removed: vec![],
        });
        assert!(!s.knows(&block(9)));
        assert!(s.changes_since(&block(9)).is_none());
        // a stale block on a stale block on the journal
        s.stale.push(super::JournalBlock {
            hash: block(20),
            prev: block(2),
            height: 11,
            added: vec![],
            removed: vec![],
        });
        s.stale.push(super::JournalBlock {
            hash: block(21),
            prev: block(20),
            height: 12,
            added: vec![],
            removed: vec![],
        });
        assert!(s.knows(&block(21)));
        let changes = s.changes_since(&block(21)).unwrap();
        assert_eq!(changes.added.len(), 1); // block 3's output
    }

    #[test]
    fn utxo_snapshot_journal_is_trimmed() {
        let mut s = snapshot(1, 1);
        for n in 2..10u8 {
            apply_block(&mut s, n, n as usize, &[1], &[]);
        }
        assert_eq!(s.journal.len(), 8);
        s.trim_journal(5 + super::JOURNAL_BLOCKS);
        // the blocks of heights up to 5 are too old
        assert_eq!(s.journal.front().unwrap().height, 6);
        assert_eq!(s.journal_utxos, 4);
        assert!(!s.knows(&s.journal_start().to_owned().clone()) || s.journal_start() != s.tip);
    }

    #[test]
    fn mempool_parts() {
        use std::collections::HashMap;
        let confirmed: HashMap<bitcoin::OutPoint, super::super::OutputInfo> = [
            (outpoint(1, 0), 100),
            (outpoint(1, 1), 0), // not listed
            (outpoint(2, 0), 200),
        ]
        .into_iter()
        .map(|(o, value)| {
            (
                o,
                super::super::OutputInfo {
                    height: 5,
                    value,
                    asset: None,
                    seq: 0,
                },
            )
        })
        .collect();
        let mempool = crate::mempool::Mempool::new(&crate::metrics::Metrics::dummy());
        let part = super::mempool_part(ScriptHash::hash(&[1]), &mempool, &confirmed);
        assert!(part.added.is_empty() && part.spent.is_empty());
    }
}
