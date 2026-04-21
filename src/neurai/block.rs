//! Neurai block header with variable serialization based on KAWPOW activation time.
//!
//! Layout:
//!
//! ```text
//! pre-KAWPOW (nTime < kawpow_activation_time):  80 bytes (bitcoin-compatible)
//!     version (4) | prev (32) | merkle (32) | time (4) | bits (4) | nonce (4)
//!
//! post-KAWPOW (nTime >= kawpow_activation_time): 120 bytes
//!     version (4) | prev (32) | merkle (32) | time (4) | bits (4)
//!     | height (4) | nonce64 (8) | mix_hash (32)
//! ```
//!
//! The header-identifying hash is network-dependent:
//!   * testnet/regtest: SHA256d of the 80-byte serialization (bitcoin-style).
//!   * mainnet pre-KAWPOW: X16R/X16Rv2 (only the genesis block on mainnet falls in this
//!     range; its hash is hard-coded in [`NetworkParams::genesis_hash_le`] so we don't
//!     need to implement X16R in Rust).
//!   * mainnet post-KAWPOW: `KAWPOWHash_OnlyMix` — computed via [`hasherkawpow_sys`]:
//!     `SHA256d(version||prev||merkle||time||bits||height)` is fed to KAWPOW together
//!     with `nonce64` and `height` to produce the final block hash.

use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{BlockHash, TxMerkleNode};

use super::network::NetworkParams;

/// How Neurai identifies a block header on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockHashAlgo {
    /// `SHA256d(header_bytes)` — used on testnet/regtest (fSHA256Mining).
    Sha256d,
    /// Mainnet: pre-KAWPOW (genesis only) is X16R and is resolved via the hard-coded
    /// genesis hash; every subsequent block uses [`hash_kawpow_header`].
    X16rThenKawpow,
}

/// KAWPOW-specific header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KawpowFields {
    pub height: u32,
    pub nonce64: u64,
    pub mix_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeuraiBlockHeader {
    pub version: i32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: TxMerkleNode,
    pub time: u32,
    pub bits: u32,
    /// Pre-KAWPOW nonce (used when `kawpow` is `None`).
    pub nonce: u32,
    /// `Some` iff the header is post-KAWPOW (nTime >= activation time).
    pub kawpow: Option<KawpowFields>,
}

impl NeuraiBlockHeader {
    /// Build the pre-KAWPOW (80-byte) variant.
    pub fn pre_kawpow(
        version: i32,
        prev_blockhash: BlockHash,
        merkle_root: TxMerkleNode,
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> Self {
        Self {
            version,
            prev_blockhash,
            merkle_root,
            time,
            bits,
            nonce,
            kawpow: None,
        }
    }

    pub fn is_kawpow(&self) -> bool {
        self.kawpow.is_some()
    }

    /// Serialize to the exact wire bytes. Length is 80 or 120 depending on `kawpow`.
    pub fn serialize(&self) -> Vec<u8> {
        let cap = if self.kawpow.is_some() { 120 } else { 80 };
        let mut out = Vec::with_capacity(cap);
        self.consensus_encode(&mut out)
            .expect("in-memory writer can't fail");
        out
    }

    /// Compute the SHA256d block hash. Only correct on networks where
    /// `block_hash_algo == Sha256d`; for mainnet use [`Self::block_hash`] instead.
    pub fn sha256d_hash(&self) -> BlockHash {
        let bytes = self.serialize();
        BlockHash::from_raw_hash(sha256d::Hash::hash(&bytes))
    }

    /// Return the header-identifying hash using the algorithm appropriate for `params`.
    ///
    /// Returns `None` only in the single pathological case of a pre-KAWPOW header on
    /// mainnet that is not the genesis block — X16R/X16Rv2 is not implemented in Rust
    /// and this case does not occur in practice (mainnet's KAWPOW activates at
    /// `nGenesisTime + 1`, so only the genesis block is pre-KAWPOW).
    pub fn block_hash(&self, params: &NetworkParams) -> Option<BlockHash> {
        match params.block_hash_algo {
            BlockHashAlgo::Sha256d => Some(self.sha256d_hash()),
            BlockHashAlgo::X16rThenKawpow => match self.kawpow {
                Some(k) => Some(hash_kawpow_header(self, k)),
                None => {
                    // Only the genesis block sits here on mainnet — the caller already
                    // knows its hash from `NetworkParams::genesis_hash_le`.
                    None
                }
            },
        }
    }
}

/// KAWPOW header input: `SHA256d(version || prev || merkle || time || bits || height)`
/// — mirrors `CKAWPOWInput` in Neurai's `src/primitives/block.h`.
fn kawpow_input_hash(header: &NeuraiBlockHeader, height: u32) -> [u8; 32] {
    let mut buf = Vec::with_capacity(80);
    header
        .version
        .consensus_encode(&mut buf)
        .expect("in-memory");
    header
        .prev_blockhash
        .consensus_encode(&mut buf)
        .expect("in-memory");
    header
        .merkle_root
        .consensus_encode(&mut buf)
        .expect("in-memory");
    header.time.consensus_encode(&mut buf).expect("in-memory");
    header.bits.consensus_encode(&mut buf).expect("in-memory");
    height.consensus_encode(&mut buf).expect("in-memory");
    debug_assert_eq!(buf.len(), 80);
    let h = sha256d::Hash::hash(&buf);
    *h.as_byte_array()
}

/// Reverse 32 bytes in place — converts between Bitcoin-family "internal little-endian"
/// storage and the "display big-endian" byte order the progpow FFI expects.
///
/// Neurai core passes hashes through `.GetHex()` + `to_hash256(...)` before calling
/// `progpow::hash_no_verify` / `verify`, which effectively reverses the bytes; we have
/// to do the same thing to reach the same hash output from the FFI.
fn reverse32(b: &[u8; 32]) -> [u8; 32] {
    let mut r = *b;
    r.reverse();
    r
}

/// Compute the KAWPOW final hash of a post-activation header, matching
/// `KAWPOWHash_OnlyMix(*this)` in Neurai core.
///
/// Uses `kawpow_hash_no_verify`, which derives the final hash from the mix stored in
/// the header instead of re-running ProgPoW to recompute the mix. This is what
/// `CBlockHeader::GetHash()` in Neurai does for the on-chain block hash — using
/// the full `hash_kawpow` would produce a different (and wrong) value unless we
/// verified and re-hashed ourselves.
fn hash_kawpow_header(header: &NeuraiBlockHeader, k: KawpowFields) -> BlockHash {
    let input_le = kawpow_input_hash(header, k.height);
    // Neurai does `to_hash256(uint256.GetHex())` before calling progpow, which reverses
    // the bytes between internal LE and the BE layout progpow reads. Mirror that here.
    let input_be = reverse32(&input_le);
    let mix_be = reverse32(&k.mix_hash);
    let hash_be = hasherkawpow_sys::kawpow_hash_no_verify(
        &input_be,
        &k.nonce64,
        k.height as i32,
        &mix_be,
    );
    // Reverse back: BlockHash stores bytes in internal LE order.
    BlockHash::from_raw_hash(sha256d::Hash::from_byte_array(reverse32(&hash_be)))
}

/// Verify that the header's declared `mix_hash` is the one ProgPoW would compute for
/// this (header, nonce, height). Returns `true` for non-KAWPOW headers (nothing to
/// verify). The `claimed_hash` argument is accepted for symmetry with legacy callers
/// but isn't part of the check — the mix is what authenticates the PoW.
pub fn verify_kawpow_header(header: &NeuraiBlockHeader, _claimed_hash: &BlockHash) -> bool {
    let Some(k) = header.kawpow else {
        return true;
    };
    let input_be = reverse32(&kawpow_input_hash(header, k.height));
    let mix_be = reverse32(&k.mix_hash);
    let mut hash_out = [0u8; 32];
    hasherkawpow_sys::verify_kawpow(
        &input_be,
        &k.nonce64,
        k.height as i32,
        &mix_be,
        &mut hash_out,
    )
}

impl Encodable for NeuraiBlockHeader {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut n = 0;
        n += self.version.consensus_encode(w)?;
        n += self.prev_blockhash.consensus_encode(w)?;
        n += self.merkle_root.consensus_encode(w)?;
        n += self.time.consensus_encode(w)?;
        n += self.bits.consensus_encode(w)?;
        match self.kawpow {
            None => {
                n += self.nonce.consensus_encode(w)?;
            }
            Some(k) => {
                n += k.height.consensus_encode(w)?;
                n += k.nonce64.consensus_encode(w)?;
                n += k.mix_hash.consensus_encode(w)?;
            }
        }
        Ok(n)
    }
}

/// Decode a Neurai header from `reader`, using `params` to pick the layout based on `nTime`.
pub fn decode_header<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
    params: &NetworkParams,
) -> Result<NeuraiBlockHeader, encode::Error> {
    let version = i32::consensus_decode(reader)?;
    let prev_blockhash = BlockHash::consensus_decode(reader)?;
    let merkle_root = TxMerkleNode::consensus_decode(reader)?;
    let time = u32::consensus_decode(reader)?;
    let bits = u32::consensus_decode(reader)?;

    if time < params.kawpow_activation_time {
        let nonce = u32::consensus_decode(reader)?;
        Ok(NeuraiBlockHeader {
            version,
            prev_blockhash,
            merkle_root,
            time,
            bits,
            nonce,
            kawpow: None,
        })
    } else {
        let height = u32::consensus_decode(reader)?;
        let nonce64 = u64::consensus_decode(reader)?;
        let mix_hash = <[u8; 32]>::consensus_decode(reader)?;
        Ok(NeuraiBlockHeader {
            version,
            prev_blockhash,
            merkle_root,
            time,
            bits,
            nonce: 0,
            kawpow: Some(KawpowFields {
                height,
                nonce64,
                mix_hash,
            }),
        })
    }
}

/// Convert a Neurai block (with 80- or 120-byte header) into a form that
/// `bitcoin_slices::bsl::Block::visit` can process, by replacing the variable-size
/// header with an 80-byte all-zeros dummy followed by the original transaction bytes.
///
/// Returns `(neurai_header, synthetic_block)` on success, `None` if the block is
/// too short to contain a valid header.  Callers should use `neurai_header` directly
/// for header data and ignore any `visit_block_header` callbacks from bsl.
pub fn neurai_to_bsl_block(
    block: &[u8],
    params: &NetworkParams,
) -> Option<(NeuraiBlockHeader, Vec<u8>)> {
    let hdr_len = header_len(block, params)?;
    let header = decode_header(&mut &block[..hdr_len], params).ok()?;
    let tx_bytes = &block[hdr_len..];
    // 80-byte fake header (zeros) + original transaction bytes
    let mut synthetic = vec![0u8; 80];
    synthetic.extend_from_slice(tx_bytes);
    Some((header, synthetic))
}

/// Fixed-size slice at the beginning of a serialized block that covers the header.
/// Returns `None` if the buffer is shorter than the minimum 80-byte header.
pub fn header_len(block_bytes: &[u8], params: &NetworkParams) -> Option<usize> {
    if block_bytes.len() < 80 {
        return None;
    }
    // Time is at offset 68..72 in both layouts.
    let time = u32::from_le_bytes(block_bytes[68..72].try_into().ok()?);
    if time < params.kawpow_activation_time {
        Some(80)
    } else if block_bytes.len() >= 120 {
        Some(120)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::super::network::{NeuraiNetwork, NetworkParams};
    use super::*;

    #[test]
    fn roundtrip_pre_kawpow_header() {
        let h = NeuraiBlockHeader::pre_kawpow(
            2,
            BlockHash::from_raw_hash(sha256d::Hash::hash(b"prev")),
            TxMerkleNode::from_raw_hash(sha256d::Hash::hash(b"merkle")),
            1_700_000_000,
            0x1d00ffff,
            42,
        );
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 80);

        let params = NetworkParams::for_network(NeuraiNetwork::Testnet);
        let decoded = decode_header(&mut bytes.as_slice(), params).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn roundtrip_kawpow_header() {
        let h = NeuraiBlockHeader {
            version: 4,
            prev_blockhash: BlockHash::from_raw_hash(sha256d::Hash::hash(b"prev")),
            merkle_root: TxMerkleNode::from_raw_hash(sha256d::Hash::hash(b"merkle")),
            time: 1_700_000_000, // > mainnet activation
            bits: 0x1e00ffff,
            nonce: 0,
            kawpow: Some(KawpowFields {
                height: 42,
                nonce64: 0x0102_0304_0506_0708,
                mix_hash: [0xaa; 32],
            }),
        };
        let bytes = h.serialize();
        assert_eq!(bytes.len(), 120);

        let params = NetworkParams::for_network(NeuraiNetwork::Mainnet);
        let decoded = decode_header(&mut bytes.as_slice(), params).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn kawpow_hash_matches_verify() {
        // Build a KAWPOW header and check that computing its hash produces a value
        // that verify_kawpow_header accepts (round-trip through the FFI).
        let header = NeuraiBlockHeader {
            version: 4,
            prev_blockhash: BlockHash::from_raw_hash(sha256d::Hash::hash(b"prev")),
            merkle_root: TxMerkleNode::from_raw_hash(sha256d::Hash::hash(b"merkle")),
            time: 1_700_000_000,
            bits: 0x1e00ffff,
            nonce: 0,
            kawpow: Some(KawpowFields {
                height: 12345,
                nonce64: 0xdead_beef_cafe_babe,
                mix_hash: [0u8; 32], // will be filled in below
            }),
        };

        // First compute the expected (mix, hash) via the FFI directly.
        let k = header.kawpow.unwrap();
        let input = kawpow_input_hash(&header, k.height);
        let (mix, hash) =
            hasherkawpow_sys::hash_kawpow(&input, &k.nonce64, k.height as i32);

        // Rebuild the header with the computed mix, then verify.
        let mut with_mix = header;
        with_mix.kawpow = Some(KawpowFields { mix_hash: mix, ..k });
        let computed = with_mix.block_hash(
            NetworkParams::for_network(NeuraiNetwork::Mainnet),
        );
        assert_eq!(
            computed.unwrap().as_raw_hash().as_byte_array(),
            &hash,
            "block_hash() must return the KAWPOW hash"
        );
        assert!(
            verify_kawpow_header(&with_mix, &computed.unwrap()),
            "verify_kawpow_header must accept a self-consistent header"
        );
    }

    #[test]
    fn header_len_picks_the_right_layout() {
        let params = NetworkParams::for_network(NeuraiNetwork::Mainnet);
        // nTime = 1681720840 → equal to mainnet genesis time, pre-KAWPOW (kawpow_activation_time = genesis + 1)
        let mut pre = vec![0u8; 80];
        pre[68..72].copy_from_slice(&1_681_720_840u32.to_le_bytes());
        assert_eq!(header_len(&pre, params), Some(80));

        // nTime = activation time → post-KAWPOW
        let mut post = vec![0u8; 120];
        post[68..72].copy_from_slice(&1_681_720_841u32.to_le_bytes());
        assert_eq!(header_len(&post, params), Some(120));
    }
}
