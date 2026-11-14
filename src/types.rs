use anyhow::{bail, Context, Result};

use std::convert::TryFrom;

use bitcoin::{
    consensus::encode::{deserialize, Decodable, Encodable},
    hashes::{hash_newtype, sha256, Hash},
    io, BlockHash, OutPoint, Script, Txid,
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
    /// Owner token (`NAME!`) creation: 1 unit, no decimals, not reissuable.
    Owner = 3,
}

/// One `New` or `Reissue` event, stored as its own row in the `asset_meta` CF.
///
/// Key:   `name_prefix(8) | height_be(4) | tx_pos_be(4) | vout_be(4)` — big-endian
///        so RocksDB returns an asset's events in chain order.
/// Value: `event(1) | txid(32) | block_hash(32) | amount_le(8) | units(1) |
///        reissuable(1) | ipfs_marker(1) | ipfs_hash(32) | name(..)`.
///
/// Rows are append-only. Readers fold them with [`AssetMetadata::fold`] after
/// dropping rows whose `block_hash` is no longer on the active chain, so events
/// from reorged blocks never leak into the reported state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMetaEventRow {
    pub name: Vec<u8>,
    pub event: AssetMetaEvent,
    pub txid: Txid,
    pub block_hash: BlockHash,
    pub height: u32,
    /// Position of the transaction inside its block.
    pub tx_pos: u32,
    pub vout: u32,
    /// `New`: initial supply. `Reissue`: supply added by this event.
    pub amount: i64,
    /// `New`: decimal places. `Reissue`: new decimal places, or `-1` = unchanged.
    pub units: i8,
    pub reissuable: bool,
    /// `0` = no IPFS/TXID, `0x12` = IPFS SHA-256, `0x54` = TXID reference.
    pub ipfs_marker: u8,
    pub ipfs_hash: [u8; 32],
}

pub const ASSET_META_KEY_SIZE: usize = HASH_PREFIX_LEN + 3 * 4;
const ASSET_META_VALUE_FIXED_SIZE: usize = 1 + 32 + 32 + 8 + 1 + 1 + 1 + 32;

impl AssetMetaEventRow {
    pub(crate) fn scan_prefix(name: &[u8]) -> HashPrefix {
        asset_name_prefix(name)
    }

    pub(crate) fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(ASSET_META_KEY_SIZE);
        key.extend_from_slice(&asset_name_prefix(&self.name));
        key.extend_from_slice(&self.height.to_be_bytes());
        key.extend_from_slice(&self.tx_pos.to_be_bytes());
        key.extend_from_slice(&self.vout.to_be_bytes());
        key
    }

    pub(crate) fn value(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(ASSET_META_VALUE_FIXED_SIZE + self.name.len());
        value.push(self.event as u8);
        value.extend_from_slice(self.txid.as_byte_array());
        value.extend_from_slice(self.block_hash.as_byte_array());
        value.extend_from_slice(&self.amount.to_le_bytes());
        value.push(self.units as u8);
        value.push(u8::from(self.reissuable));
        value.push(self.ipfs_marker);
        value.extend_from_slice(&self.ipfs_hash);
        value.extend_from_slice(&self.name);
        value
    }

    pub(crate) fn from_db(key: &[u8], value: &[u8]) -> Result<Self> {
        if key.len() != ASSET_META_KEY_SIZE {
            bail!("asset_meta key must be {} bytes, got {}", ASSET_META_KEY_SIZE, key.len());
        }
        if value.len() < ASSET_META_VALUE_FIXED_SIZE {
            bail!("asset_meta value too short: {} bytes", value.len());
        }
        let be_u32 = |b: &[u8]| u32::from_be_bytes(b.try_into().expect("4-byte slice"));
        let event = match value[0] {
            1 => AssetMetaEvent::New,
            2 => AssetMetaEvent::Reissue,
            3 => AssetMetaEvent::Owner,
            other => bail!("unknown asset meta event tag: {}", other),
        };
        let mut ipfs_hash = [0u8; 32];
        ipfs_hash.copy_from_slice(&value[76..108]);
        Ok(Self {
            name: value[ASSET_META_VALUE_FIXED_SIZE..].to_vec(),
            event,
            txid: Txid::from_slice(&value[1..33]).expect("32-byte slice"),
            block_hash: BlockHash::from_slice(&value[33..65]).expect("32-byte slice"),
            height: be_u32(&key[8..12]),
            tx_pos: be_u32(&key[12..16]),
            vout: be_u32(&key[16..20]),
            amount: i64::from_le_bytes(value[65..73].try_into().expect("8-byte slice")),
            units: value[73] as i8,
            reissuable: value[74] != 0,
            ipfs_marker: value[75],
            ipfs_hash,
        })
    }
}

/// Output that carried an issuance event (`get_meta` `source*` fields).
/// `height` is `-1` for mempool events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetSource {
    pub txid: Txid,
    pub vout: u32,
    pub height: i64,
}

/// Current state of an asset, as reported by `blockchain.asset.get_meta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMetadata {
    /// Kind of the latest issuance event applied.
    pub event: AssetMetaEvent,
    /// Transaction and height of the latest issuance event applied.
    pub issuance_txid: Txid,
    pub issuance_height: u32,
    /// Total supply: initial issuance plus every reissue.
    pub amount: i64,
    pub units: u8,
    pub reissuable: bool,
    /// `0` = no IPFS/TXID, `0x12` = IPFS SHA-256, `0x54` = TXID reference.
    pub ipfs_marker: u8,
    pub ipfs_hash: [u8; 32],
    /// Output of the latest event (`source`).
    pub source: AssetSource,
    /// Output of the event that last set the decimal places (`source_divisions`
    /// when it isn't `source`, i.e. the latest reissue sent units `-1`).
    pub divisions_source: AssetSource,
    /// Output of the event that last set the IPFS hash (`source_ipfs` when it
    /// isn't `source`, i.e. the latest reissue carried no IPFS).
    pub ipfs_source: Option<AssetSource>,
}

impl AssetMetadata {
    /// Fold an asset's issuance events (in chain order) into its current state,
    /// mirroring the daemon's `CAssetsCache::AddReissueAsset`: a reissue adds
    /// to the supply, always sets `reissuable`, changes `units` unless it is
    /// `-1`, and replaces the IPFS hash only when it carries one.
    pub(crate) fn fold<'a>(events: impl IntoIterator<Item = &'a AssetMetaEventRow>) -> Option<Self> {
        let mut state: Option<Self> = None;
        for e in events {
            Self::apply(&mut state, e, i64::from(e.height));
        }
        state
    }

    /// Apply one event (`height` is `-1` for a mempool event).
    pub(crate) fn apply(state: &mut Option<Self>, e: &AssetMetaEventRow, height: i64) {
        let source = AssetSource {
            txid: e.txid,
            vout: e.vout,
            height,
        };
        match e.event {
            AssetMetaEvent::New | AssetMetaEvent::Owner => {
                let has_ipfs = e.ipfs_marker != 0;
                *state = Some(Self {
                    event: e.event,
                    issuance_txid: e.txid,
                    issuance_height: e.height,
                    amount: e.amount,
                    units: u8::try_from(e.units).unwrap_or(0),
                    reissuable: e.reissuable,
                    ipfs_marker: e.ipfs_marker,
                    ipfs_hash: e.ipfs_hash,
                    source,
                    divisions_source: source,
                    ipfs_source: has_ipfs.then_some(source),
                })
            }
            AssetMetaEvent::Reissue => {
                // A reissue without a prior issuance can't be valid on chain.
                let Some(s) = state.as_mut() else { return };
                s.event = AssetMetaEvent::Reissue;
                s.issuance_txid = e.txid;
                s.issuance_height = e.height;
                s.amount = s.amount.saturating_add(e.amount);
                s.reissuable = e.reissuable;
                s.source = source;
                if let Ok(units) = u8::try_from(e.units) {
                    s.units = units;
                    s.divisions_source = source;
                }
                if e.ipfs_marker != 0 {
                    s.ipfs_marker = e.ipfs_marker;
                    s.ipfs_hash = e.ipfs_hash;
                    s.ipfs_source = Some(source);
                }
            }
        }
    }

    pub fn has_ipfs(&self) -> bool {
        self.ipfs_marker != 0
    }

    /// The 34 bytes ElectrumX base58-encodes: marker, `0x20`, 32-byte hash.
    pub fn ipfs_data(&self) -> [u8; 34] {
        let mut data = [0u8; 34];
        data[0] = self.ipfs_marker;
        data[1] = 0x20;
        data[2..].copy_from_slice(&self.ipfs_hash);
        data
    }
}

// ─── restricted-asset / qualifier / messaging events (`asset_events` CF) ──────

/// Kind of an `asset_events` row; also the domain byte of its key prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AssetEventKind {
    /// Qualifier tag / per-address restricted freeze, keyed by asset name.
    TagByAsset = b't',
    /// The same event, keyed by the tagged h160.
    TagByH160 = b'h',
    /// Global freeze of a restricted asset, keyed by `$NAME`.
    Freeze = b'f',
    /// Verifier string of a restricted asset, keyed by `$NAME`.
    Verifier = b'v',
    /// "verifier of `$R` mentions `#Q`", keyed by `#Q` (candidates; the
    /// association state is derived from `$R`'s verifier history).
    Association = b'a',
    /// Message on an owner token / message channel transfer, keyed by name.
    Broadcast = b'b',
}

impl AssetEventKind {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            b't' => Self::TagByAsset,
            b'h' => Self::TagByH160,
            b'f' => Self::Freeze,
            b'v' => Self::Verifier,
            b'a' => Self::Association,
            b'b' => Self::Broadcast,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetEventPayload {
    /// `c0 14 <h160> <push(name, flag)>`
    Tag { h160: [u8; 20], asset: String, flag: bool },
    /// `c0 50 50 <push(name, flag)>`
    Freeze { asset: String, flag: bool },
    /// `c0 50 <push(string)>` with `restricted_vout` = last `$` output of the tx.
    Verifier { asset: String, string: String, restricted_vout: u32 },
    Association { qualifier: String, restricted: String },
    /// `data` = 34-byte IPFS/TXID reference, `scripthash` = receiving script.
    Broadcast {
        asset: String,
        data: [u8; 34],
        expiration: Option<u64>,
        scripthash: ScriptHash,
    },
}

/// One row of the `asset_events` CF.
///
/// Key: `H(kind ‖ logical key)[..8] | height_be(4) | tx_pos_be(4) | vout_be(4)`.
/// Value: `kind(1) | txid(32) | block_hash(32) | logical key (u8 len + bytes) | payload`.
/// Like `asset_meta`, rows are append-only and filtered by block hash on read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetEventRow {
    pub kind: AssetEventKind,
    /// Asset name bytes, or the 20-byte h160 for [`AssetEventKind::TagByH160`].
    pub key: Vec<u8>,
    pub txid: Txid,
    pub block_hash: BlockHash,
    pub height: u32,
    pub tx_pos: u32,
    pub vout: u32,
    pub payload: AssetEventPayload,
}

pub(crate) fn asset_event_prefix(kind: AssetEventKind, key: &[u8]) -> HashPrefix {
    let mut engine = sha256::Hash::engine();
    bitcoin::hashes::HashEngine::input(&mut engine, &[kind as u8]);
    bitcoin::hashes::HashEngine::input(&mut engine, key);
    let hash = sha256::Hash::from_engine(engine);
    let mut prefix = [0u8; HASH_PREFIX_LEN];
    prefix.copy_from_slice(&hash[..HASH_PREFIX_LEN]);
    prefix
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&s[..usize::from(len)]);
}

fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if data.len() < n {
        bail!("truncated asset_events value");
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

fn take_str(data: &mut &[u8]) -> Result<String> {
    let len = u16::from_le_bytes(take(data, 2)?.try_into().expect("2 bytes"));
    let bytes = take(data, usize::from(len))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

impl AssetEventRow {
    pub(crate) fn key_bytes(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(ASSET_META_KEY_SIZE);
        key.extend_from_slice(&asset_event_prefix(self.kind, &self.key));
        key.extend_from_slice(&self.height.to_be_bytes());
        key.extend_from_slice(&self.tx_pos.to_be_bytes());
        key.extend_from_slice(&self.vout.to_be_bytes());
        key
    }

    pub(crate) fn value_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128);
        v.push(self.kind as u8);
        v.extend_from_slice(self.txid.as_byte_array());
        v.extend_from_slice(self.block_hash.as_byte_array());
        put_str(&mut v, &self.key);
        match &self.payload {
            AssetEventPayload::Tag { h160, asset, flag } => {
                v.extend_from_slice(h160);
                put_str(&mut v, asset.as_bytes());
                v.push(u8::from(*flag));
            }
            AssetEventPayload::Freeze { asset, flag } => {
                put_str(&mut v, asset.as_bytes());
                v.push(u8::from(*flag));
            }
            AssetEventPayload::Verifier {
                asset,
                string,
                restricted_vout,
            } => {
                put_str(&mut v, asset.as_bytes());
                put_str(&mut v, string.as_bytes());
                v.extend_from_slice(&restricted_vout.to_le_bytes());
            }
            AssetEventPayload::Association {
                qualifier,
                restricted,
            } => {
                put_str(&mut v, qualifier.as_bytes());
                put_str(&mut v, restricted.as_bytes());
            }
            AssetEventPayload::Broadcast {
                asset,
                data,
                expiration,
                scripthash,
            } => {
                put_str(&mut v, asset.as_bytes());
                v.extend_from_slice(data);
                match expiration {
                    Some(t) => {
                        v.push(1);
                        v.extend_from_slice(&t.to_le_bytes());
                    }
                    None => v.push(0),
                }
                v.extend_from_slice(scripthash.as_byte_array());
            }
        }
        v
    }

    pub(crate) fn from_db(key: &[u8], value: &[u8]) -> Result<Self> {
        if key.len() != ASSET_META_KEY_SIZE {
            bail!("asset_events key must be {} bytes, got {}", ASSET_META_KEY_SIZE, key.len());
        }
        let be_u32 = |b: &[u8]| u32::from_be_bytes(b.try_into().expect("4-byte slice"));
        let mut data = value;
        let kind = AssetEventKind::from_byte(take(&mut data, 1)?[0])
            .context("unknown asset_events kind")?;
        let txid = Txid::from_slice(take(&mut data, 32)?).expect("32 bytes");
        let block_hash = BlockHash::from_slice(take(&mut data, 32)?).expect("32 bytes");
        let len = u16::from_le_bytes(take(&mut data, 2)?.try_into().expect("2 bytes"));
        let logical_key = take(&mut data, usize::from(len))?.to_vec();
        let payload = match kind {
            AssetEventKind::TagByAsset | AssetEventKind::TagByH160 => {
                let h160: [u8; 20] = take(&mut data, 20)?.try_into().expect("20 bytes");
                let asset = take_str(&mut data)?;
                let flag = take(&mut data, 1)?[0] != 0;
                AssetEventPayload::Tag { h160, asset, flag }
            }
            AssetEventKind::Freeze => {
                let asset = take_str(&mut data)?;
                let flag = take(&mut data, 1)?[0] != 0;
                AssetEventPayload::Freeze { asset, flag }
            }
            AssetEventKind::Verifier => {
                let asset = take_str(&mut data)?;
                let string = take_str(&mut data)?;
                let restricted_vout =
                    u32::from_le_bytes(take(&mut data, 4)?.try_into().expect("4 bytes"));
                AssetEventPayload::Verifier {
                    asset,
                    string,
                    restricted_vout,
                }
            }
            AssetEventKind::Association => {
                let qualifier = take_str(&mut data)?;
                let restricted = take_str(&mut data)?;
                AssetEventPayload::Association {
                    qualifier,
                    restricted,
                }
            }
            AssetEventKind::Broadcast => {
                let asset = take_str(&mut data)?;
                let data34: [u8; 34] = take(&mut data, 34)?.try_into().expect("34 bytes");
                let expiration = match take(&mut data, 1)?[0] {
                    0 => None,
                    _ => Some(u64::from_le_bytes(take(&mut data, 8)?.try_into().expect("8 bytes"))),
                };
                let scripthash =
                    ScriptHash::from_slice(take(&mut data, 32)?).expect("32 bytes");
                AssetEventPayload::Broadcast {
                    asset,
                    data: data34,
                    expiration,
                    scripthash,
                }
            }
        };
        Ok(Self {
            kind,
            key: logical_key,
            txid,
            block_hash,
            height: be_u32(&key[8..12]),
            tx_pos: be_u32(&key[12..16]),
            vout: be_u32(&key[16..20]),
            payload,
        })
    }
}

/// ElectrumX's qualifier extraction from a verifier string:
/// `re.findall(r'([A-Z0-9_.]+)', string)`.
pub fn verifier_qualifiers(string: &str) -> Vec<String> {
    let mut out = vec![];
    let mut current = String::new();
    for c in string.chars() {
        if c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' || c == '.' {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
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

    fn meta_event(
        event: crate::types::AssetMetaEvent,
        height: u32,
        amount: i64,
        units: i8,
        reissuable: bool,
        ipfs: Option<u8>,
    ) -> crate::types::AssetMetaEventRow {
        use bitcoin::hashes::Hash;
        crate::types::AssetMetaEventRow {
            name: b"TOKEN".to_vec(),
            event,
            txid: Txid::from_byte_array([height as u8; 32]),
            block_hash: bitcoin::BlockHash::from_byte_array([0xBB; 32]),
            height,
            tx_pos: 1,
            vout: 0,
            amount,
            units,
            reissuable,
            ipfs_marker: if ipfs.is_some() { 0x12 } else { 0 },
            ipfs_hash: [ipfs.unwrap_or(0); 32],
        }
    }

    #[test]
    fn test_asset_meta_event_row_roundtrip() {
        use crate::types::{asset_name_prefix, AssetMetaEvent, AssetMetaEventRow, ASSET_META_KEY_SIZE};
        let row = meta_event(AssetMetaEvent::Reissue, 123_456, 1_000_000_000, -1, true, Some(0xAA));
        let key = row.key();
        assert_eq!(key.len(), ASSET_META_KEY_SIZE);
        assert_eq!(&key[..8], &asset_name_prefix(b"TOKEN"));
        let decoded = AssetMetaEventRow::from_db(&key, &row.value()).unwrap();
        assert_eq!(decoded, row);
    }

    #[test]
    fn test_asset_meta_event_keys_sort_in_chain_order() {
        use crate::types::AssetMetaEvent;
        // Big-endian height/tx_pos/vout: byte order == chain order, even across
        // a 256-block boundary where little-endian keys would misorder.
        let mut a = meta_event(AssetMetaEvent::Reissue, 0x01ff, 1, -1, true, None);
        let b = meta_event(AssetMetaEvent::Reissue, 0x0200, 1, -1, true, None);
        assert!(a.key() < b.key());
        let c = a.clone();
        a.tx_pos = 2;
        assert!(c.key() < a.key());
    }

    #[test]
    fn test_asset_meta_event_rejects_unknown_event() {
        use crate::types::{AssetMetaEvent, AssetMetaEventRow};
        let row = meta_event(AssetMetaEvent::New, 1, 1, 0, true, None);
        let mut value = row.value();
        value[0] = 99; // unknown event tag
        assert!(AssetMetaEventRow::from_db(&row.key(), &value).is_err());
    }

    #[test]
    fn test_asset_metadata_fold_mirrors_daemon_reissue() {
        use crate::types::{AssetMetaEvent, AssetMetadata};
        let new = meta_event(AssetMetaEvent::New, 10, 1_000, 8, true, Some(0x11));
        // units -1 and no IPFS: both must be kept from the previous state.
        let keep = meta_event(AssetMetaEvent::Reissue, 20, 50, -1, true, None);
        let change = meta_event(AssetMetaEvent::Reissue, 30, 7, 4, false, Some(0x22));

        let s = AssetMetadata::fold([&new, &keep]).unwrap();
        assert_eq!((s.amount, s.units, s.reissuable), (1_050, 8, true));
        assert_eq!((s.ipfs_marker, s.ipfs_hash), (0x12, [0x11; 32]));
        assert_eq!((s.event, s.issuance_height), (AssetMetaEvent::Reissue, 20));
        assert_eq!(s.issuance_txid, keep.txid);

        let s = AssetMetadata::fold([&new, &keep, &change]).unwrap();
        assert_eq!((s.amount, s.units, s.reissuable), (1_057, 4, false));
        assert_eq!(s.ipfs_hash, [0x22; 32]);

        // A reissue without a known issuance is ignored.
        assert_eq!(AssetMetadata::fold([&keep]), None);
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
