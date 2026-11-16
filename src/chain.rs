use std::collections::HashMap;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{BlockHash, TxMerkleNode};
use rayon::prelude::*;

use crate::neurai::block::NeuraiBlockHeader;
use crate::neurai::NetworkParams;

/// A new header found, to be added to the chain at specific height
pub(crate) struct NewHeader {
    header: NeuraiBlockHeader,
    hash: BlockHash,
    height: usize,
}

impl NewHeader {
    pub(crate) fn new(header: NeuraiBlockHeader, hash: BlockHash, height: usize) -> Self {
        Self { header, hash, height }
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn hash(&self) -> BlockHash {
        self.hash
    }
}

/// Current blockchain headers' list
pub struct Chain {
    headers: Vec<(BlockHash, NeuraiBlockHeader)>,
    heights: HashMap<BlockHash, usize>,
    params: &'static NetworkParams,
}

impl Chain {
    /// Build a chain with a specific genesis hash (used for testnet/regtest where the
    /// genesis is epoch-based and fetched from the daemon RPC at startup).
    pub fn new_with_genesis(params: &'static NetworkParams, genesis_hash: BlockHash) -> Self {
        let genesis_header = NeuraiBlockHeader::pre_kawpow(
            params.genesis_version,
            BlockHash::from_raw_hash(sha256d::Hash::all_zeros()),
            TxMerkleNode::from_raw_hash(sha256d::Hash::from_byte_array(
                params.genesis_merkle_root_le,
            )),
            params.genesis_time,
            params.genesis_bits,
            params.genesis_nonce,
        );
        Self {
            headers: vec![(genesis_hash, genesis_header)],
            heights: std::iter::once((genesis_hash, 0)).collect(),
            params,
        }
    }

    /// Build a chain using the genesis hash hardcoded in `params` (mainnet only).
    pub fn new(params: &'static NetworkParams) -> Self {
        let genesis_hash =
            BlockHash::from_raw_hash(sha256d::Hash::from_byte_array(params.genesis_hash_le));
        Self::new_with_genesis(params, genesis_hash)
    }

    pub(crate) fn params(&self) -> &'static NetworkParams {
        self.params
    }

    pub(crate) fn drop_last_headers(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let new_height = self.height().saturating_sub(n);
        let (hash, header) = self.headers[new_height];
        self.update(vec![NewHeader::new(header, hash, new_height)]);
    }

    /// Load the chain from a collection of headers, up to the given tip.
    ///
    /// The headers come in DB order, stale ones included, so they are indexed
    /// by hash to follow `prev_blockhash` back from the tip. Only their
    /// positions are indexed, and the chain is written once: on mainnet (1.87M
    /// headers) a map of the headers and two intermediate copies of the chain
    /// made the start peak at ~1.6 GB.
    pub(crate) fn load(
        &mut self,
        headers: impl Iterator<Item = NeuraiBlockHeader>,
        tip: BlockHash,
    ) {
        let genesis_hash = self.headers[0].0;
        let params = self.params;

        let headers: Vec<NeuraiBlockHeader> = headers.collect();
        let hashes: Vec<BlockHash> = headers
            .par_iter()
            .map(|h| {
                h.block_hash(params)
                    .expect("all stored headers must have a computable hash")
            })
            .collect();
        let mut positions: HashMap<BlockHash, u32> = HashMap::with_capacity(hashes.len());
        for (position, hash) in hashes.iter().enumerate() {
            let position = u32::try_from(position).expect("too many headers");
            positions.insert(*hash, position);
        }

        // positions from the tip down to the genesis
        let mut chain: Vec<u32> = Vec::new();
        let mut blockhash = tip;
        while blockhash != genesis_hash {
            let position = match positions.get(&blockhash) {
                Some(&position) => position,
                None => panic!("missing header {} while loading from DB", blockhash),
            };
            chain.push(position);
            blockhash = headers[position as usize].prev_blockhash;
        }
        drop(positions);
        info!("loading {} headers, tip={}", chain.len(), tip);

        for (hash, _header) in self.headers.drain(1..) {
            self.heights.remove(&hash);
        }
        self.headers.reserve_exact(chain.len());
        self.headers.extend(
            chain
                .iter()
                .rev()
                .map(|&position| (hashes[position as usize], headers[position as usize])),
        );
        drop((chain, hashes, headers));
        self.heights.reserve(self.headers.len());
        for (height, (hash, _header)) in self.headers.iter().enumerate().skip(1) {
            self.heights.insert(*hash, height);
        }
        info!(
            "chain updated: tip={}, height={}",
            self.tip(),
            self.height()
        );
    }

    /// Get the block hash at specified height (if exists)
    pub(crate) fn get_block_hash(&self, height: usize) -> Option<BlockHash> {
        self.headers.get(height).map(|(hash, _header)| *hash)
    }

    /// Get the block header at specified height (if exists)
    pub(crate) fn get_block_header(&self, height: usize) -> Option<&NeuraiBlockHeader> {
        self.headers.get(height).map(|(_hash, header)| header)
    }

    /// Get the block height given the specified hash (if exists)
    pub(crate) fn get_block_height(&self, blockhash: &BlockHash) -> Option<usize> {
        self.heights.get(blockhash).copied()
    }

    /// Update the chain with a list of new headers (possibly a reorg)
    pub(crate) fn update(&mut self, headers: Vec<NewHeader>) {
        if let Some(first_height) = headers.first().map(|h| h.height) {
            for (hash, _header) in self.headers.drain(first_height..) {
                assert!(self.heights.remove(&hash).is_some());
            }
            for (h, height) in headers.into_iter().zip(first_height..) {
                assert_eq!(h.height, height);
                assert!(self.heights.insert(h.hash, h.height).is_none());
                self.headers.push((h.hash, h.header));
            }
            info!(
                "chain updated: tip={}, height={}",
                self.headers.last().unwrap().0,
                self.headers.len() - 1
            );
        }
    }

    /// Best block hash
    pub(crate) fn tip(&self) -> BlockHash {
        self.headers.last().expect("empty chain").0
    }

    /// Number of blocks (excluding genesis block)
    pub(crate) fn height(&self) -> usize {
        self.headers.len() - 1
    }

    /// List of block hashes for efficient fork detection and block/header sync
    /// see https://en.bitcoin.it/wiki/Protocol_documentation#getblocks
    pub(crate) fn locator(&self) -> Vec<BlockHash> {
        let mut result = vec![];
        let mut index = self.headers.len() - 1;
        let mut step = 1;
        loop {
            if result.len() >= 10 {
                step *= 2;
            }
            result.push(self.headers[index].0);
            if index == 0 {
                break;
            }
            index = index.saturating_sub(step);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{Chain, NewHeader};
    use crate::neurai::block::NeuraiBlockHeader;
    use crate::neurai::{NeuraiNetwork, NetworkParams};
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::{BlockHash, TxMerkleNode};

    fn regtest_params() -> &'static NetworkParams {
        NetworkParams::for_network(NeuraiNetwork::Regtest)
    }

    fn make_header(prev: BlockHash, time: u32, nonce: u32) -> NeuraiBlockHeader {
        NeuraiBlockHeader::pre_kawpow(
            2,
            prev,
            TxMerkleNode::from_raw_hash(sha256d::Hash::all_zeros()),
            time,
            0x207fffff,
            nonce,
        )
    }

    #[test]
    fn test_genesis() {
        let params = regtest_params();
        let chain = Chain::new(params);
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn test_chain_update_and_load() {
        let params = regtest_params();
        let mut chain = Chain::new(params);
        let genesis_hash = chain.tip();

        // Build synthetic headers chaining off genesis
        let mut prev = genesis_hash;
        let mut hashes = vec![];
        let headers: Vec<NeuraiBlockHeader> = (1u32..=5).map(|i| {
            let h = make_header(prev, 1_700_000_000 + i, i);
            let hash = h.sha256d_hash();
            hashes.push(hash);
            prev = hash;
            h
        }).collect();

        for (i, (header, hash)) in headers.iter().zip(hashes.iter()).enumerate() {
            chain.update(vec![NewHeader::new(*header, *hash, i + 1)]);
        }
        assert_eq!(chain.height(), 5);
        assert_eq!(chain.tip(), *hashes.last().unwrap());

        // Load from headers iterator
        let mut chain2 = Chain::new(params);
        chain2.load(headers.into_iter(), chain.tip());
        assert_eq!(chain2.height(), 5);
        assert_eq!(chain2.tip(), chain.tip());
    }

    #[test]
    fn test_drop_last_headers() {
        let params = regtest_params();
        let mut chain = Chain::new(params);
        let genesis_hash = chain.tip();

        let mut prev = genesis_hash;
        for i in 1u32..=3 {
            let h = make_header(prev, 1_700_000_000 + i, i);
            let hash = h.sha256d_hash();
            chain.update(vec![NewHeader::new(h, hash, i as usize)]);
            prev = hash;
        }
        assert_eq!(chain.height(), 3);

        chain.drop_last_headers(2);
        assert_eq!(chain.height(), 1);

        chain.drop_last_headers(10); // safe to drop more than available
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.tip(), genesis_hash);
    }

    #[test]
    fn test_load_follows_the_tip_among_shuffled_and_stale_headers() {
        let params = regtest_params();
        let genesis_hash = Chain::new(params).tip();
        // a chain of 6 blocks, and a stale branch of 2 off block 3
        let mut main = vec![];
        let mut prev = genesis_hash;
        for i in 1u32..=6 {
            let h = make_header(prev, 1_700_000_000 + i, i);
            prev = h.sha256d_hash();
            main.push(h);
        }
        let mut stale = vec![];
        let mut prev = main[2].sha256d_hash();
        for i in 1u32..=2 {
            let h = make_header(prev, 1_800_000_000 + i, 100 + i);
            prev = h.sha256d_hash();
            stale.push(h);
        }
        let mut stored: Vec<NeuraiBlockHeader> = main.iter().chain(&stale).copied().collect();
        stored.reverse();
        stored.swap(0, 3);

        let mut chain = Chain::new(params);
        chain.load(stored.into_iter(), main[5].sha256d_hash());
        assert_eq!(chain.height(), 6);
        assert_eq!(chain.get_block_height(&genesis_hash), Some(0));
        for (i, header) in main.iter().enumerate() {
            let hash = header.sha256d_hash();
            assert_eq!(chain.get_block_hash(i + 1), Some(hash));
            assert_eq!(chain.get_block_height(&hash), Some(i + 1));
            let stored = chain.get_block_header(i + 1).map(|h| h.sha256d_hash());
            assert_eq!(stored, Some(hash));
        }
        for header in &stale {
            assert_eq!(chain.get_block_height(&header.sha256d_hash()), None);
        }
    }
}
