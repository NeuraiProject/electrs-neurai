//! The last transactions of a scripthash with a long history, for
//! `blockchain.scripthash.get_recent_history` (`doc/utxo-chunks.md`): read
//! with its `UtxoSnapshot`, from the same blocks, and kept up to date by the
//! same new blocks.

use bitcoin::{hashes::Hash, BlockHash, Txid};

use std::collections::{btree_map, BTreeMap, VecDeque};

use super::{OutputInfo, TxOutput};

/// Version of `get_recent_history`, advertised in `server.features`.
pub(crate) const PROTOCOL_VERSION: u32 = 1;
/// Confirmed transactions kept per scripthash.
pub(crate) const RECENT_HISTORY_LEN: usize = 1_000;
/// Entries of a `get_recent_history` reply: by default, and at most (about
/// 60 KB, under 128 KiB unless its transactions move many assets).
pub(crate) const DEFAULT_PAGE: usize = 50;
pub(crate) const MAX_PAGE: usize = 500;

fn signed(amount: u64) -> i64 {
    i64::try_from(amount).unwrap_or(i64::MAX)
}

/// What a transaction changes in the balance of a scripthash: what it
/// receives minus what it spends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Delta {
    /// XNA satoshis.
    pub(crate) value: i64,
    /// Smallest units of each asset, without zeroes.
    pub(crate) assets: BTreeMap<String, i64>,
}

impl Delta {
    fn add(&mut self, asset: Option<&str>, amount: i64) {
        match asset {
            None => self.value = self.value.saturating_add(amount),
            Some(name) => {
                let total = self.assets.entry(name.to_owned()).or_insert(0);
                *total = total.saturating_add(amount);
                if *total == 0 {
                    self.assets.remove(name);
                }
            }
        }
    }

    /// An output to the scripthash, counted like its UTXO: the asset of an
    /// asset output, without its XNA.
    pub(super) fn receive(&mut self, output: &TxOutput) {
        match &output.asset {
            Some(a) => self.add(Some(&a.name), signed(a.amount)),
            None => self.add(None, signed(output.value.to_sat())),
        }
    }

    /// An output to the scripthash, spent.
    pub(super) fn spend_output(&mut self, output: &TxOutput) {
        match &output.asset {
            Some(a) => self.add(Some(&a.name), -signed(a.amount)),
            None => self.add(None, -signed(output.value.to_sat())),
        }
    }

    /// A UTXO of the scripthash, spent.
    pub(super) fn spend(&mut self, info: &OutputInfo) {
        self.add(info.asset.as_deref(), -signed(info.value));
    }

    fn merge(&mut self, other: Delta) {
        self.add(None, other.value);
        for (name, amount) in other.assets {
            self.add(Some(&name), amount);
        }
    }
}

/// A confirmed transaction of the scripthash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryItem {
    pub(crate) txid: Txid,
    pub(crate) height: usize,
    /// Its position in the block. Only the order matters: a snapshot made
    /// from a `ScriptHashStatus` numbers the transactions of the scripthash
    /// in each block instead.
    pub(crate) pos: usize,
    pub(crate) delta: Delta,
}

impl HistoryItem {
    pub(crate) fn new(txid: Txid, height: usize, pos: usize) -> Self {
        Self {
            txid,
            height,
            pos,
            delta: Delta::default(),
        }
    }

    fn key(&self) -> (usize, usize) {
        (self.height, self.pos)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.txid.as_byte_array());
        out.extend_from_slice(&(self.height as u64).to_le_bytes());
        out.extend_from_slice(&(self.pos as u64).to_le_bytes());
        out.extend_from_slice(&self.delta.value.to_le_bytes());
        out.extend_from_slice(&(self.delta.assets.len() as u32).to_le_bytes());
        for (name, amount) in &self.delta.assets {
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&amount.to_le_bytes());
        }
    }
}

/// The `limit` items of greatest `(height, pos)` among those pushed, in any
/// order, in at most twice that memory: a history of millions of
/// transactions is read without keeping them.
pub(crate) struct Latest {
    items: Vec<HistoryItem>,
    limit: usize,
    /// Whether some were left out.
    dropped: bool,
}

impl Latest {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            items: Vec::new(),
            limit,
            dropped: false,
        }
    }

    pub(crate) fn push(&mut self, item: HistoryItem) {
        self.items.push(item);
        if self.items.len() >= 2 * self.limit.max(1) {
            self.trim();
        }
    }

    fn trim(&mut self) {
        if self.items.len() <= self.limit {
            return;
        }
        if self.limit > 0 {
            // the `limit` greatest first
            self.items
                .select_nth_unstable_by(self.limit - 1, |a, b| b.key().cmp(&a.key()));
        }
        self.items.truncate(self.limit);
        self.dropped = true;
    }
}

/// The latest confirmed transactions of a scripthash, with what they change
/// in its balance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RecentHistory {
    /// By `(height, pos)`, oldest first.
    items: VecDeque<HistoryItem>,
    /// Whether they are all the transactions of the scripthash.
    complete: bool,
}

impl RecentHistory {
    /// The latest transactions among the latest funding ones and the latest
    /// spending ones, put together by transaction: one that spends coins of
    /// the scripthash and pays it change is both.
    ///
    /// The latest `limit` of each are enough. A transaction among the latest
    /// `limit` of the whole history has fewer than `limit` transactions after
    /// it, so fewer than `limit` funding ones and fewer than `limit` spending
    /// ones: if it funds the scripthash, it is among the latest `limit`
    /// funding transactions, and if it spends, among the latest `limit`
    /// spending ones. Both its parts are there. A transaction with only one
    /// of its parts there (say its spends are not among the latest `limit`)
    /// has `limit` transactions after it: it is not among the latest `limit`,
    /// and is left out below.
    pub(crate) fn combine(funding: Latest, spending: Latest) -> Self {
        let limit = funding.limit.min(spending.limit);
        let mut complete = !funding.dropped && !spending.dropped;
        let mut txs: BTreeMap<(usize, usize), HistoryItem> = BTreeMap::new();
        for item in funding.items.into_iter().chain(spending.items) {
            match txs.entry(item.key()) {
                btree_map::Entry::Vacant(e) => {
                    e.insert(item);
                }
                btree_map::Entry::Occupied(mut e) => {
                    debug_assert_eq!(e.get().txid, item.txid);
                    e.get_mut().delta.merge(item.delta);
                }
            }
        }
        while txs.len() > limit {
            txs.pop_first();
            complete = false;
        }
        Self {
            items: txs.into_values().collect(),
            complete,
        }
    }

    /// From items sorted by `(height, pos)`, `None` if they are not.
    pub(crate) fn from_sorted(items: Vec<HistoryItem>, complete: bool) -> Option<Self> {
        if items.windows(2).any(|w| w[0].key() >= w[1].key()) {
            return None;
        }
        let mut history = Self {
            items: items.into(),
            complete,
        };
        history.trim();
        Some(history)
    }

    fn trim(&mut self) {
        while self.items.len() > RECENT_HISTORY_LEN {
            self.items.pop_front();
            self.complete = false;
        }
    }

    /// Adds the transactions of a new block (by position), and drops the
    /// oldest beyond `RECENT_HISTORY_LEN`.
    pub(crate) fn push_block(&mut self, items: impl IntoIterator<Item = HistoryItem>) {
        for item in items {
            debug_assert!(self.items.back().is_none_or(|last| last.key() < item.key()));
            self.items.push_back(item);
        }
        self.trim();
    }

    /// Takes out the transactions of the blocks from `height` on, undone by
    /// a reorg. The ones dropped for them are not back: there are fewer.
    pub(crate) fn undo_from(&mut self, height: usize) {
        while self.items.back().is_some_and(|item| item.height >= height) {
            self.items.pop_back();
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn contains(&self, txid: &Txid) -> bool {
        self.items.iter().any(|item| item.txid == *txid)
    }

    pub(crate) fn newest_first(&self) -> impl Iterator<Item = &HistoryItem> {
        self.items.iter().rev()
    }

    /// Serialized in a `UtxoSnapshot` (read back by its `Reader`).
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.complete));
        out.extend_from_slice(&(self.items.len() as u64).to_le_bytes());
        self.items.iter().for_each(|item| item.write(out));
    }

    /// Approximate size in bytes of `write`.
    pub(crate) fn size(&self) -> usize {
        1 + 8 + self.items.len() * (32 + 8 + 8 + 8 + 4)
    }
}

/// An entry of `get_recent_history`.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub(crate) struct RecentEntry {
    pub(crate) tx_hash: Txid,
    /// Confirmed: its height; in the mempool: -1 when it spends unconfirmed
    /// outputs, else 0 (like `get_history`).
    pub(crate) height: i64,
    pub(crate) value: i64,
    pub(crate) assets: BTreeMap<String, i64>,
}

impl RecentEntry {
    pub(crate) fn confirmed(item: &HistoryItem) -> Self {
        Self {
            tx_hash: item.txid,
            height: i64::try_from(item.height).unwrap_or(i64::MAX),
            value: item.delta.value,
            assets: item.delta.assets.clone(),
        }
    }

    pub(crate) fn unconfirmed(txid: Txid, has_unconfirmed_inputs: bool, delta: Delta) -> Self {
        Self {
            tx_hash: txid,
            height: if has_unconfirmed_inputs { -1 } else { 0 },
            value: delta.value,
            assets: delta.assets,
        }
    }
}

/// The reply of `get_recent_history`.
#[derive(Serialize, Debug)]
pub(crate) struct RecentHistoryPage {
    /// The tip the confirmed entries are of.
    pub(crate) height: usize,
    pub(crate) block_hash: BlockHash,
    /// Entries in all: the mempool ones and the confirmed ones.
    pub(crate) total: usize,
    /// Whether they are all the transactions of the scripthash.
    pub(crate) complete: bool,
    /// From `offset`, newest first: the mempool ones, then the confirmed ones
    /// by (height, position in the block), descending.
    pub(crate) entries: Vec<RecentEntry>,
}

/// Page `offset`/`limit` of `mempool` (newest first) then `recent`.
pub(crate) fn page(
    mempool: Vec<RecentEntry>,
    recent: &RecentHistory,
    offset: usize,
    limit: usize,
) -> (usize, Vec<RecentEntry>) {
    let total = mempool.len() + recent.len();
    let confirmed_offset = offset.saturating_sub(mempool.len());
    let mut entries: Vec<RecentEntry> = mempool.into_iter().skip(offset).take(limit).collect();
    let left = limit - entries.len();
    entries.extend(
        recent
            .newest_first()
            .skip(confirmed_offset)
            .take(left)
            .map(RecentEntry::confirmed),
    );
    (total, entries)
}

#[cfg(test)]
mod tests {
    use super::{Delta, HistoryItem, Latest, RecentHistory, RECENT_HISTORY_LEN};
    use bitcoin::{hashes::Hash, Txid};
    use std::collections::BTreeMap;

    /// xorshift64*: deterministic test data without a dependency.
    pub(crate) struct Rng(pub(crate) u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        pub(crate) fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        pub(crate) fn shuffle<T>(&mut self, items: &mut [T]) {
            for i in (1..items.len()).rev() {
                items.swap(i, self.below(i as u64 + 1) as usize);
            }
        }
    }

    fn txid(height: usize, pos: usize) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(height as u64).to_le_bytes());
        bytes[8..16].copy_from_slice(&(pos as u64).to_le_bytes());
        Txid::from_byte_array(bytes)
    }

    fn item(height: usize, pos: usize, value: i64, assets: &[(&str, i64)]) -> HistoryItem {
        HistoryItem {
            txid: txid(height, pos),
            height,
            pos,
            delta: Delta {
                value,
                assets: assets.iter().map(|(n, a)| (n.to_string(), *a)).collect(),
            },
        }
    }

    #[test]
    fn deltas_drop_zeroes() {
        let mut d = Delta::default();
        d.add(Some("A"), 5);
        d.add(None, 7);
        d.merge(Delta {
            value: -7,
            assets: [("A".to_string(), -5), ("B".to_string(), 1)].into(),
        });
        assert_eq!(d.value, 0);
        assert_eq!(d.assets, BTreeMap::from([("B".to_string(), 1)]));
        // amounts beyond i64 saturate instead of wrapping
        d.add(None, i64::MAX);
        d.add(None, 1);
        assert_eq!(d.value, i64::MAX);
    }

    #[test]
    fn latest_keeps_the_greatest_keys_in_any_order() {
        let mut rng = Rng(7);
        let mut keys: Vec<(usize, usize)> = (0..500).map(|i| (i / 3, i % 3)).collect();
        rng.shuffle(&mut keys);
        let mut latest = Latest::new(10);
        for (h, p) in &keys {
            latest.push(item(*h, *p, 1, &[]));
        }
        assert!(latest.items.len() < 20);
        latest.trim();
        let mut kept: Vec<_> = latest.items.iter().map(HistoryItem::key).collect();
        kept.sort_unstable();
        keys.sort_unstable();
        assert_eq!(kept, keys[keys.len() - 10..]);
        assert!(latest.dropped);

        let mut few = Latest::new(10);
        few.push(item(1, 0, 1, &[]));
        few.trim();
        assert!(!few.dropped && few.items.len() == 1);
    }

    /// `combine` against the whole history put together, on random
    /// histories: funding pushed in chain order, spending in any order.
    #[test]
    fn combine_is_the_latest_of_the_whole_history() {
        for seed in 1..=200u64 {
            let mut rng = Rng(seed);
            let limit = 1 + rng.below(6) as usize;
            let count = rng.below(40) as usize;
            let mut whole: Vec<HistoryItem> = Vec::new();
            let mut funding = Vec::new();
            let mut spending = Vec::new();
            for i in 0..count {
                let (height, pos) = (i / 4 + 1, i % 4);
                let mut tx = item(height, pos, 0, &[]);
                let (funds, spends) = match rng.below(3) {
                    0 => (true, false),
                    1 => (false, true),
                    _ => (true, true),
                };
                if funds {
                    let mut part = item(height, pos, rng.below(1000) as i64, &[]);
                    if rng.below(2) == 0 {
                        part.delta.add(Some("TOKEN"), 5);
                    }
                    tx.delta.merge(part.delta.clone());
                    funding.push(part);
                }
                if spends {
                    let mut part = item(height, pos, -(rng.below(1000) as i64), &[]);
                    if rng.below(2) == 0 {
                        part.delta.add(Some("TOKEN"), -5);
                    }
                    tx.delta.merge(part.delta.clone());
                    spending.push(part);
                }
                whole.push(tx);
            }
            rng.shuffle(&mut spending);
            let (mut f, mut s) = (Latest::new(limit), Latest::new(limit));
            funding.into_iter().for_each(|i| f.push(i));
            spending.into_iter().for_each(|i| s.push(i));
            let combined = RecentHistory::combine(f, s);
            let expected = &whole[whole.len().saturating_sub(limit)..];
            assert_eq!(combined.items, expected, "seed {seed}");
            assert_eq!(combined.complete, whole.len() <= limit, "seed {seed}");
        }
    }

    #[test]
    fn combine_puts_spends_and_change_together() {
        let mut f = Latest::new(10);
        let mut s = Latest::new(10);
        f.push(item(5, 1, 300, &[("A", 2)])); // change
        s.push(item(5, 1, -1000, &[("A", -2)])); // the coins it spent
        s.push(item(4, 0, -50, &[]));
        let history = RecentHistory::combine(f, s);
        assert_eq!(
            history.items,
            [item(4, 0, -50, &[]), item(5, 1, -700, &[])],
            "the asset sent back nets to zero, the entry stays"
        );
        assert!(history.complete);
    }

    #[test]
    fn new_blocks_trim_to_the_limit_and_reorgs_undo() {
        let mut history = RecentHistory::from_sorted(vec![item(1, 0, 1, &[])], true).unwrap();
        history.push_block((0..RECENT_HISTORY_LEN - 1).map(|pos| item(2, pos, 1, &[])));
        assert_eq!(history.len(), RECENT_HISTORY_LEN);
        assert!(history.complete());
        history.push_block([item(3, 0, 1, &[]), item(3, 7, 1, &[])]);
        assert_eq!(history.len(), RECENT_HISTORY_LEN);
        assert!(!history.complete());
        // the oldest ones went out
        assert_eq!(history.items.front().unwrap().key(), (2, 1));
        assert_eq!(history.newest_first().next().unwrap().key(), (3, 7));
        // a reorg takes block 3 out
        history.undo_from(3);
        assert_eq!(history.len(), RECENT_HISTORY_LEN - 2);
        assert_eq!(
            history.newest_first().next().unwrap().key(),
            (2, RECENT_HISTORY_LEN - 2)
        );
        assert!(history.contains(&txid(2, 5)));
        assert!(!history.contains(&txid(3, 0)));
        // unsorted items are refused
        assert!(
            RecentHistory::from_sorted(vec![item(2, 0, 1, &[]), item(1, 0, 1, &[])], true)
                .is_none()
        );
        assert!(
            RecentHistory::from_sorted(vec![item(2, 0, 1, &[]), item(2, 0, 1, &[])], true)
                .is_none()
        );
    }

    #[test]
    fn pages() {
        let items: Vec<HistoryItem> = (1..=7).map(|h| item(h, 0, h as i64, &[])).collect();
        let history = RecentHistory::from_sorted(items, false).unwrap();
        let mempool = || {
            vec![
                super::RecentEntry::unconfirmed(txid(99, 1), true, Delta::default()),
                super::RecentEntry::unconfirmed(txid(99, 0), false, Delta::default()),
            ]
        };
        let heights = |offset, limit| -> (usize, Vec<i64>) {
            let (total, entries) = super::page(mempool(), &history, offset, limit);
            (total, entries.iter().map(|e| e.height).collect())
        };
        assert_eq!(heights(0, 3), (9, vec![-1, 0, 7]));
        assert_eq!(heights(1, 3), (9, vec![0, 7, 6]));
        assert_eq!(heights(2, 3), (9, vec![7, 6, 5]));
        assert_eq!(heights(6, 50), (9, vec![3, 2, 1]));
        assert_eq!(heights(9, 50), (9, vec![]));
        assert_eq!(heights(1000, 50), (9, vec![]));
        assert_eq!(heights(0, 0), (9, vec![]));
        // all the pages make the whole list
        let all: Vec<i64> = (0..9).step_by(2).flat_map(|o| heights(o, 2).1).collect();
        assert_eq!(all, [-1, 0, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn entries_json() {
        let entry = super::RecentEntry::confirmed(&item(1_872_099, 3, 300_000_000_000, &[]));
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "tx_hash": txid(1_872_099, 3).to_string(),
                "height": 1_872_099,
                "value": 300_000_000_000_i64,
                "assets": {},
            })
        );
        let mut delta = Delta::default();
        delta.add(None, -150_000_000);
        delta.add(Some("TOKEN"), 100_000_000);
        let entry = super::RecentEntry::unconfirmed(txid(1, 1), false, delta);
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            serde_json::json!({
                "tx_hash": txid(1, 1).to_string(),
                "height": 0,
                "value": -150_000_000,
                "assets": {"TOKEN": 100_000_000},
            })
        );
    }
}
