use anyhow::{bail, Result};

use std::convert::TryFrom;

use bitcoin::{
    consensus::encode::{deserialize, Decodable, Encodable},
    hashes::{hash_newtype, sha256, Hash},
    io, OutPoint, Script, Txid,
};
use bitcoin_slices::bsl;

use crate::neurai::{block::{decode_header, NeuraiBlockHeader}, NetworkParams};

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl Encodable for $thing {
            #[inline]
            fn consensus_encode<S: io::Write + ?Sized>(
                &self,
                s: &mut S,
            ) -> Result<usize, io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(s)?;)+
                Ok(len)
            }
        }

        impl Decodable for $thing {
            #[inline]
            fn consensus_decode<D: io::Read + ?Sized>(
                d: &mut D,
            ) -> Result<$thing, bitcoin::consensus::encode::Error> {
                Ok($thing {
                    $($field: Decodable::consensus_decode(d)?),+
                })
            }
        }
    );
}

pub const HASH_PREFIX_LEN: usize = 8;
const HEIGHT_SIZE: usize = 4;

pub(crate) type HashPrefix = [u8; HASH_PREFIX_LEN];
pub(crate) type SerializedHashPrefixRow = [u8; HASH_PREFIX_ROW_SIZE];
type Height = u32;
pub(crate) type SerBlock = Vec<u8>;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct HashPrefixRow {
    prefix: HashPrefix,
    height: Height, // transaction confirmed height
}

pub const HASH_PREFIX_ROW_SIZE: usize = HASH_PREFIX_LEN + HEIGHT_SIZE;

impl HashPrefixRow {
    pub(crate) fn to_db_row(&self) -> SerializedHashPrefixRow {
        let mut row = [0; HASH_PREFIX_ROW_SIZE];
        let len = self
            .consensus_encode(&mut (&mut row as &mut [u8]))
            .expect("in-memory writers don't error");
        debug_assert_eq!(len, HASH_PREFIX_ROW_SIZE);
        row
    }

    pub(crate) fn from_db_row(row: SerializedHashPrefixRow) -> Self {
        deserialize(&row).expect("bad HashPrefixRow")
    }

    pub fn height(&self) -> usize {
        usize::try_from(self.height).expect("invalid height")
    }
}

impl_consensus_encoding!(HashPrefixRow, prefix, height);

hash_newtype! {
    /// https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#script-hashes
    #[hash_newtype(backward)]
    pub struct ScriptHash(sha256::Hash);
}

impl ScriptHash {
    pub fn new(script: &Script) -> Self {
        ScriptHash::hash(script.as_bytes())
    }

    pub(crate) fn prefix(&self) -> HashPrefix {
        let mut prefix = HashPrefix::default();
        prefix.copy_from_slice(&self.0[..HASH_PREFIX_LEN]);
        prefix
    }
}

pub(crate) struct ScriptHashRow;

impl ScriptHashRow {
    pub(crate) fn scan_prefix(scripthash: ScriptHash) -> HashPrefix {
        scripthash.0[..HASH_PREFIX_LEN].try_into().unwrap()
    }

    pub(crate) fn row(scripthash: ScriptHash, height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: scripthash.prefix(),
            height: Height::try_from(height).expect("invalid height"),
        }
    }
}

// ***************************************************************************

hash_newtype! {
    /// https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#status
    pub struct StatusHash(sha256::Hash);
}

// ***************************************************************************

fn spending_prefix(prev: OutPoint) -> HashPrefix {
    let txid_prefix = HashPrefix::try_from(&prev.txid[..HASH_PREFIX_LEN]).unwrap();
    let value = u64::from_be_bytes(txid_prefix);
    let value = value.wrapping_add(prev.vout.into());
    value.to_be_bytes()
}

pub(crate) struct SpendingPrefixRow;

impl SpendingPrefixRow {
    pub(crate) fn scan_prefix(outpoint: OutPoint) -> HashPrefix {
        spending_prefix(outpoint)
    }

    pub(crate) fn row(outpoint: OutPoint, height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: spending_prefix(outpoint),
            height: Height::try_from(height).expect("invalid height"),
        }
    }
}

// ***************************************************************************

fn txid_prefix(txid: &Txid) -> HashPrefix {
    let mut prefix = [0u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&txid[..HASH_PREFIX_LEN]);
    prefix
}

pub(crate) struct TxidRow;

impl TxidRow {
    pub(crate) fn scan_prefix(txid: Txid) -> HashPrefix {
        txid_prefix(&txid)
    }

    pub(crate) fn row(txid: Txid, height: usize) -> HashPrefixRow {
        HashPrefixRow {
            prefix: txid_prefix(&txid),
            height: Height::try_from(height).expect("invalid height"),
        }
    }
}

// ***************************************************************************

pub(crate) type SerializedHeaderRow = [u8; HEADER_ROW_SIZE];

#[derive(Debug)]
pub(crate) struct HeaderRow {
    pub(crate) header: NeuraiBlockHeader,
}

/// All headers are stored as 120 bytes. Pre-KAWPOW (80-byte) headers are padded
/// with zeros for the kawpow fields; the trailing zeros are ignored on decode
/// because `decode_header` only reads as many bytes as the nTime implies.
pub const HEADER_ROW_SIZE: usize = 120;

impl HeaderRow {
    pub(crate) fn new(header: NeuraiBlockHeader) -> Self {
        Self { header }
    }

    pub(crate) fn to_db_row(&self) -> SerializedHeaderRow {
        let mut row = [0u8; HEADER_ROW_SIZE];
        let serialized = self.header.serialize(); // 80 or 120 bytes
        row[..serialized.len()].copy_from_slice(&serialized);
        row
    }

    pub(crate) fn from_db_row(row: SerializedHeaderRow, params: &NetworkParams) -> Self {
        let header = decode_header(&mut &row[..], params).expect("bad HeaderRow");
        Self { header }
    }
}

pub(crate) fn bsl_txid(tx: &bsl::Transaction) -> Txid {
    bitcoin::Txid::from_slice(tx.txid_sha2().as_slice()).expect("invalid txid")
}

// ─── Asset index rows ─────────────────────────────────────────────────────────

/// 8-byte stable prefix for an asset name (first 8 bytes of SHA-256(name)).
///
/// The same hashing scheme as [`ScriptHash::prefix`] so RocksDB prefix scans are
/// uniformly 8 bytes across every column family.
pub fn asset_name_prefix(name: &[u8]) -> HashPrefix {
    let hash = sha256::Hash::hash(name);
    let mut prefix = [0u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&hash[..HASH_PREFIX_LEN]);
    prefix
}

pub const ASSET_HISTORY_ROW_SIZE: usize = HASH_PREFIX_LEN + HASH_PREFIX_LEN + HEIGHT_SIZE; // 20
pub const ASSET_FUNDING_ROW_SIZE: usize = HASH_PREFIX_LEN + HASH_PREFIX_LEN + HEIGHT_SIZE; // 20

pub(crate) type SerializedAssetHistoryRow = [u8; ASSET_HISTORY_ROW_SIZE];
pub(crate) type SerializedAssetFundingRow = [u8; ASSET_FUNDING_ROW_SIZE];

/// Key layout: `name_prefix(8) | txid_prefix(8) | height_le(4)`.
pub(crate) struct AssetHistoryRow;

impl AssetHistoryRow {
    pub(crate) fn scan_prefix(name: &[u8]) -> HashPrefix {
        asset_name_prefix(name)
    }

    pub(crate) fn row(name: &[u8], txid: Txid, height: usize) -> SerializedAssetHistoryRow {
        let mut row = [0u8; ASSET_HISTORY_ROW_SIZE];
        row[..HASH_PREFIX_LEN].copy_from_slice(&asset_name_prefix(name));
        row[HASH_PREFIX_LEN..2 * HASH_PREFIX_LEN]
            .copy_from_slice(&txid.as_byte_array()[..HASH_PREFIX_LEN]);
        let h = u32::try_from(height).expect("invalid height");
        row[2 * HASH_PREFIX_LEN..].copy_from_slice(&h.to_le_bytes());
        row
    }

    pub(crate) fn height(row: &SerializedAssetHistoryRow) -> usize {
        let bytes = &row[2 * HASH_PREFIX_LEN..];
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
    }
}

/// Key layout: `scripthash_prefix(8) | name_prefix(8) | height_le(4)`.
pub(crate) struct AssetFundingRow;

impl AssetFundingRow {
    pub(crate) fn scan_prefix_by_scripthash(scripthash: ScriptHash) -> HashPrefix {
        scripthash.prefix()
    }

    pub(crate) fn row(
        scripthash: ScriptHash,
        name: &[u8],
        height: usize,
    ) -> SerializedAssetFundingRow {
        let mut row = [0u8; ASSET_FUNDING_ROW_SIZE];
        row[..HASH_PREFIX_LEN].copy_from_slice(&scripthash.prefix());
        row[HASH_PREFIX_LEN..2 * HASH_PREFIX_LEN].copy_from_slice(&asset_name_prefix(name));
        let h = u32::try_from(height).expect("invalid height");
        row[2 * HASH_PREFIX_LEN..].copy_from_slice(&h.to_le_bytes());
        row
    }

    pub(crate) fn height(row: &SerializedAssetFundingRow) -> usize {
        let bytes = &row[2 * HASH_PREFIX_LEN..];
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
    }
}

/// Issuance event kind stored in the first byte of an `asset_meta` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AssetMetaEvent {
    New = 1,
    Reissue = 2,
}

/// Asset metadata persisted in the `asset_meta` column family (value side).
///
/// Key in the CF is the full asset name bytes.  Layout is fixed-size 80 bytes so
/// upgrades don't need a new format version for length changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMetadata {
    pub event: AssetMetaEvent,
    pub issuance_txid: Txid,
    pub issuance_height: u32,
    pub amount: i64,
    pub units: u8,
    pub reissuable: bool,
    /// `0` = no IPFS/TXID, `0x12` = IPFS SHA-256, `0x54` = TXID reference.
    pub ipfs_marker: u8,
    pub ipfs_hash: [u8; 32],
}

pub const ASSET_METADATA_SIZE: usize = 1 + 32 + 4 + 8 + 1 + 1 + 1 + 32;
pub(crate) type SerializedAssetMetadata = [u8; ASSET_METADATA_SIZE];

impl AssetMetadata {
    pub(crate) fn to_bytes(&self) -> SerializedAssetMetadata {
        let mut buf = [0u8; ASSET_METADATA_SIZE];
        buf[0] = self.event as u8;
        buf[1..33].copy_from_slice(self.issuance_txid.as_byte_array());
        buf[33..37].copy_from_slice(&self.issuance_height.to_le_bytes());
        buf[37..45].copy_from_slice(&self.amount.to_le_bytes());
        buf[45] = self.units;
        buf[46] = u8::from(self.reissuable);
        buf[47] = self.ipfs_marker;
        buf[48..80].copy_from_slice(&self.ipfs_hash);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ASSET_METADATA_SIZE {
            bail!(
                "asset metadata must be {} bytes, got {}",
                ASSET_METADATA_SIZE,
                bytes.len()
            );
        }
        let event = match bytes[0] {
            1 => AssetMetaEvent::New,
            2 => AssetMetaEvent::Reissue,
            other => bail!("unknown asset meta event tag: {}", other),
        };
        let issuance_txid =
            Txid::from_slice(&bytes[1..33]).expect("32-byte slice");
        let issuance_height = u32::from_le_bytes(bytes[33..37].try_into().unwrap());
        let amount = i64::from_le_bytes(bytes[37..45].try_into().unwrap());
        let units = bytes[45];
        let reissuable = bytes[46] != 0;
        let ipfs_marker = bytes[47];
        let mut ipfs_hash = [0u8; 32];
        ipfs_hash.copy_from_slice(&bytes[48..80]);
        Ok(Self {
            event,
            issuance_txid,
            issuance_height,
            amount,
            units,
            reissuable,
            ipfs_marker,
            ipfs_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{spending_prefix, HashPrefixRow, ScriptHash, ScriptHashRow, TxidRow};
    use bitcoin::{Address, OutPoint, Txid};
    use hex_lit::hex;
    use serde_json::{from_str, json};

    use std::str::FromStr;

    #[test]
    fn test_scripthash_serde() {
        let hex = "\"4b3d912c1523ece4615e91bf0d27381ca72169dbf6b1c2ffcc9f92381d4984a3\"";
        let scripthash: ScriptHash = from_str(hex).unwrap();
        assert_eq!(format!("\"{}\"", scripthash), hex);
        assert_eq!(json!(scripthash).to_string(), hex);
    }

    #[test]
    fn test_scripthash_row() {
        let hex = "\"4b3d912c1523ece4615e91bf0d27381ca72169dbf6b1c2ffcc9f92381d4984a3\"";
        let scripthash: ScriptHash = from_str(hex).unwrap();
        let row1 = ScriptHashRow::row(scripthash, 123456);
        let db_row = row1.to_db_row();
        assert_eq!(db_row, hex!("a384491d38929fcc40e20100"));
        let row2 = HashPrefixRow::from_db_row(db_row);
        assert_eq!(row1, row2);
    }

    #[test]
    fn test_scripthash() {
        let addr = Address::from_str("1KVNjD3AAnQ3gTMqoTKcWFeqSFujq9gTBT")
            .unwrap()
            .assume_checked();
        let scripthash = ScriptHash::new(&addr.script_pubkey());
        assert_eq!(
            scripthash,
            "00dfb264221d07712a144bda338e89237d1abd2db4086057573895ea2659766a"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_txid1_prefix() {
        // duplicate txids from BIP-30
        let hex = "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";
        let txid = Txid::from_str(hex).unwrap();

        let row1 = TxidRow::row(txid, 91812);
        let row2 = TxidRow::row(txid, 91842);

        assert_eq!(row1.to_db_row(), hex!("9985d82954e10f22a4660100"));
        assert_eq!(row2.to_db_row(), hex!("9985d82954e10f22c2660100"));
    }

    #[test]
    fn test_txid2_prefix() {
        // duplicate txids from BIP-30
        let hex = "e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468";
        let txid = Txid::from_str(hex).unwrap();

        let row1 = TxidRow::row(txid, 91722);
        let row2 = TxidRow::row(txid, 91880);

        // low-endian encoding => rows should be sorted according to block height
        assert_eq!(row1.to_db_row(), hex!("68b45f58b674e94e4a660100"));
        assert_eq!(row2.to_db_row(), hex!("68b45f58b674e94ee8660100"));
    }

    #[test]
    fn test_asset_name_prefix_is_stable() {
        use crate::types::asset_name_prefix;
        let a = asset_name_prefix(b"TOKEN");
        let b = asset_name_prefix(b"TOKEN");
        let c = asset_name_prefix(b"OTHER");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_asset_history_row_layout() {
        use crate::types::{asset_name_prefix, AssetHistoryRow};
        use bitcoin::hashes::Hash;
        let hex_txid = "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";
        let txid = Txid::from_str(hex_txid).unwrap();
        let row = AssetHistoryRow::row(b"TOKEN", txid, 100);
        assert_eq!(&row[..8], &asset_name_prefix(b"TOKEN"));
        assert_eq!(&row[8..16], &txid.to_byte_array()[..8]);
        assert_eq!(&row[16..20], &100u32.to_le_bytes());
        assert_eq!(AssetHistoryRow::height(&row), 100);
    }

    #[test]
    fn test_asset_funding_row_layout() {
        use crate::types::{asset_name_prefix, AssetFundingRow, ScriptHash};
        let hex = "\"4b3d912c1523ece4615e91bf0d27381ca72169dbf6b1c2ffcc9f92381d4984a3\"";
        let sh: ScriptHash = from_str(hex).unwrap();
        let row = AssetFundingRow::row(sh, b"TOKEN", 42);
        assert_eq!(&row[..8], &sh.prefix());
        assert_eq!(&row[8..16], &asset_name_prefix(b"TOKEN"));
        assert_eq!(&row[16..20], &42u32.to_le_bytes());
    }

    #[test]
    fn test_asset_metadata_roundtrip() {
        use crate::types::{AssetMetaEvent, AssetMetadata, ASSET_METADATA_SIZE};
        let hex_txid = "d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599";
        let meta = AssetMetadata {
            event: AssetMetaEvent::New,
            issuance_txid: Txid::from_str(hex_txid).unwrap(),
            issuance_height: 123_456,
            amount: 1_000_000_000,
            units: 8,
            reissuable: true,
            ipfs_marker: 0x12,
            ipfs_hash: [0xAA; 32],
        };
        let bytes = meta.to_bytes();
        assert_eq!(bytes.len(), ASSET_METADATA_SIZE);
        let decoded = AssetMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn test_asset_metadata_rejects_unknown_event() {
        use crate::types::{AssetMetadata, ASSET_METADATA_SIZE};
        let mut bytes = [0u8; ASSET_METADATA_SIZE];
        bytes[0] = 99; // unknown event tag
        assert!(AssetMetadata::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_spending_prefix() {
        let txid = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            .parse()
            .unwrap();

        assert_eq!(
            spending_prefix(OutPoint { txid, vout: 0 }),
            [31, 30, 29, 28, 27, 26, 25, 24]
        );
        assert_eq!(
            spending_prefix(OutPoint { txid, vout: 10 }),
            [31, 30, 29, 28, 27, 26, 25, 34]
        );
        assert_eq!(
            spending_prefix(OutPoint { txid, vout: 255 }),
            [31, 30, 29, 28, 27, 26, 26, 23]
        );
        assert_eq!(
            spending_prefix(OutPoint { txid, vout: 256 }),
            [31, 30, 29, 28, 27, 26, 26, 24]
        );
    }
}
