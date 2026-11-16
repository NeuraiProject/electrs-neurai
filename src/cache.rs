use bitcoin::Txid;
use parking_lot::RwLock;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use crate::metrics::{self, Histogram, Metrics};

/// Most memory used by the cached transactions: beyond it, the oldest go first.
/// It used to grow forever: one query of an address paid in ~926,000 blocks
/// kept ~950,000 transactions (430 MB) that nobody asks for one by one.
const MAX_CACHE_BYTES: usize = 128 << 20;
/// Approximate memory of an entry besides the transaction (map and queue).
const ENTRY_OVERHEAD: usize = 80;

/// Raw transactions of the scripthash statuses computed lately, to answer
/// `blockchain.transaction.get` without asking the daemon.
pub(crate) struct Cache {
    txs: Arc<RwLock<Txs>>,

    // stats
    txs_size: Histogram,
}

/// Transactions in the order they were added, with their total size.
#[derive(Default)]
struct Txs {
    map: HashMap<Txid, Box<[u8]>>,
    order: VecDeque<Txid>,
    bytes: usize,
}

impl Txs {
    fn insert(&mut self, txid: Txid, tx: Box<[u8]>, max_bytes: usize) {
        let size = tx.len() + ENTRY_OVERHEAD;
        if size > max_bytes {
            return;
        }
        self.bytes += size;
        self.map.insert(txid, tx);
        self.order.push_back(txid);
        while self.bytes > max_bytes {
            let oldest = self
                .order
                .pop_front()
                .expect("over the bound, so not empty");
            let tx = self
                .map
                .remove(&oldest)
                .expect("queued transactions are cached");
            self.bytes -= tx.len() + ENTRY_OVERHEAD;
        }
    }
}

impl Cache {
    pub fn new(metrics: &Metrics) -> Self {
        Cache {
            txs: Default::default(),
            txs_size: metrics.histogram_vec(
                "cache_txs_size",
                "Cached transactions' size (in bytes)",
                "type",
                metrics::default_size_buckets(),
            ),
        }
    }

    pub fn add_tx(&self, txid: Txid, f: impl FnOnce() -> Box<[u8]>) {
        let mut txs = self.txs.write();
        if txs.map.contains_key(&txid) {
            return;
        }
        let tx = f();
        self.txs_size.observe("serialized", tx.len() as f64);
        txs.insert(txid, tx, MAX_CACHE_BYTES);
    }

    pub fn get_tx<F, T>(&self, txid: &Txid, f: F) -> Option<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        self.txs.read().map.get(txid).map(|tx_bytes| f(tx_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::{Txs, ENTRY_OVERHEAD};
    use bitcoin::{hashes::Hash, Txid};

    fn txid(n: u8) -> Txid {
        Txid::from_byte_array([n; 32])
    }

    #[test]
    fn oldest_transactions_go_first() {
        let size = 100 + ENTRY_OVERHEAD;
        let mut txs = Txs::default();
        for n in 1..=3 {
            txs.insert(txid(n), vec![n; 100].into(), 3 * size);
        }
        assert_eq!((txs.map.len(), txs.bytes), (3, 3 * size));

        txs.insert(txid(4), vec![4; 100].into(), 3 * size);
        assert!(!txs.map.contains_key(&txid(1)));
        assert_eq!((txs.map.len(), txs.bytes), (3, 3 * size));

        // one transaction the size of two others
        txs.insert(txid(5), vec![5; 100 + size].into(), 3 * size);
        assert!(!txs.map.contains_key(&txid(2)) && !txs.map.contains_key(&txid(3)));
        assert_eq!(txs.map.len(), 2);
        assert_eq!(txs.bytes, 3 * size);

        // larger than the bound: not kept
        txs.insert(txid(6), vec![6; 3 * size].into(), 3 * size);
        assert!(!txs.map.contains_key(&txid(6)));
        assert_eq!(txs.map.len(), 2);
        assert_eq!(txs.order.len(), 2);
    }
}
