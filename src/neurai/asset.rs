//! Neurai asset opcode parser.
//!
//! A Neurai asset output extends a locking script by appending:
//!
//! ```text
//! <base_script>
//! OP_XNA_ASSET      (0xc0)
//! <script push: 1-byte length (< 76) or OP_PUSHDATA1 + 1-byte length>
//! <3 bytes: marker "rvn", or "xna" (NIP-040) from the unified fork>
//! <1 byte: type 'q'|'t'|'r'|'o'>
//! <type-specific payload>
//! OP_DROP           (0x75)
//! ```
//!
//! What counts as an asset output follows `CScript::IsAssetScript` of Neurai 2.0
//! (DePIN-Test), which keeps the 1.0.7 rules below the unified fork:
//!
//! | Form                                                   | Below the fork          | From the fork             |
//! |--------------------------------------------------------|-------------------------|---------------------------|
//! | `OP_XNA_ASSET` at byte 25, marker at byte 27 or 28     | any 25-byte prefix, "rvn" | P2PKH prefix, "rvn"/"xna" |
//! | `OP_1`/`OP_2`/`OP_3 <32 bytes>` (AuthScript), byte 34  | not an asset            | "rvn"/"xna", then `OP_DROP` |
//!
//! The payload is read from its first byte to the end of the script, like the
//! daemon's `*AssetFromScript` functions, so optional fields (IPFS hash,
//! message, expiry) are read on the same conditions.

use anyhow::{bail, Context, Result};

// ─── on-wire constants ────────────────────────────────────────────────────────

pub const OP_XNA_ASSET: u8 = 0xc0;
pub const OP_DROP: u8 = 0x75;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;

/// ASCII "rvn", retained from Ravencoin for protocol compatibility.
pub const ASSET_MAGIC: [u8; 3] = *b"rvn";
/// ASCII "xna": the NIP-040 marker of new asset outputs from the unified fork.
pub const XNA_MARKER: [u8; 3] = *b"xna";
/// `MAX_SIZE` of the daemon's `ReadCompactSize`.
const MAX_SIZE: u64 = 0x0200_0000;

pub const TYPE_NEW: u8 = b'q'; // 0x71 — new asset issuance
pub const TYPE_TRANSFER: u8 = b't'; // 0x74 — asset transfer
pub const TYPE_REISSUE: u8 = b'r'; // 0x72 — reissue
pub const TYPE_OWNER: u8 = b'o'; // 0x6f — owner (!-suffix) asset

// ─── name-prefix indicators ───────────────────────────────────────────────────

/// Restricted-asset name prefix (`$ABC`).
pub const RESTRICTED_PREFIX: u8 = b'$';
/// Qualifier-asset name prefix (`#ABC` or `#ABC/#XYZ`).
pub const QUALIFIER_PREFIX: u8 = b'#';
/// DePIN / Soulbound asset name prefix (`&ABC`). Testnet/regtest-only in the
/// daemon until a future mainnet activation height.
pub const DEPIN_PREFIX: u8 = b'&';
pub const OWNER_SUFFIX: u8 = b'!';
pub const UNIQUE_SEPARATOR: u8 = b'#';
pub const MSG_CHANNEL_SEPARATOR: u8 = b'~';
pub const VOTE_SEPARATOR: u8 = b'^';
pub const SUB_SEPARATOR: u8 = b'/';

/// Markers preceding a 32-byte reference in asset payloads (the daemon
/// accepts any marker byte when it reads them).
#[cfg(test)]
const IPFS_MARKER: u8 = 0x12; // IPFS SHA2-256 content hash
#[cfg(test)]
const TXID_MARKER: u8 = 0x54; // on-chain transaction reference

// ─── parsed output types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetData {
    New(NewAsset),
    Transfer(TransferAsset),
    Reissue(ReissueAsset),
    Owner(OwnerAsset),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAsset {
    pub name: String,
    pub amount: i64,
    pub units: u8,
    pub reissuable: bool,
    pub ipfs: Option<IpfsRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferAsset {
    pub name: String,
    pub amount: i64,
    pub message: Option<AssetMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetMessage {
    pub ipfs: IpfsRef,
    pub expire_time: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReissueAsset {
    pub name: String,
    pub amount: i64,
    /// New number of decimal places, or `-1` to keep the current ones
    /// (the daemon's `CReissueAsset::nUnits` is an `int8_t`).
    pub units: i8,
    pub reissuable: bool,
    pub ipfs: Option<IpfsRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAsset {
    /// Full owner name including the trailing `!` suffix.
    pub name: String,
}

/// 32-byte reference with a one-byte marker: either an IPFS SHA2-256 hash
/// (`0x12`) or a transaction ID (`0x54`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpfsRef {
    pub marker: u8,
    pub hash: [u8; 32],
}

/// Result of [`parse_asset_script`] — the standard locking part and the decoded asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetOutput {
    /// Bytes before `OP_XNA_ASSET` (P2PKH or OP_1 + 32-byte commitment).
    /// Used for scripthash / address lookup in the indexer.
    pub base_script: Vec<u8>,
    pub data: AssetData,
}

// ─── top-level parser ─────────────────────────────────────────────────────────

/// Parse an asset output from a raw `script_pubkey`, as the daemon reads it.
///
/// `fork`: whether the unified fork's rules apply at the height of the
/// transaction ([`NetworkParams::fork_active`](crate::neurai::NetworkParams::fork_active)).
/// Returns `None` if the script is not an asset output for the daemon; the
/// caller treats it as a plain output.
pub fn parse_asset_script(bytes: &[u8], fork: bool) -> Option<AssetOutput> {
    let (base_script, start, type_byte) = locate_asset_payload(bytes, fork)?;
    let payload = &bytes[start..];
    let data = match type_byte {
        TYPE_NEW => AssetData::New(parse_new(payload).ok()?),
        TYPE_TRANSFER => AssetData::Transfer(parse_transfer(payload).ok()?),
        TYPE_REISSUE => AssetData::Reissue(parse_reissue(payload).ok()?),
        TYPE_OWNER => AssetData::Owner(parse_owner(payload).ok()?),
        _ => return None,
    };
    Some(AssetOutput { base_script, data })
}

/// `(holder's script, first payload byte, type byte)` of an asset script, found
/// like `CScript::IsAssetScript` finds them.
fn locate_asset_payload(bytes: &[u8], fork: bool) -> Option<(Vec<u8>, usize, u8)> {
    let accepted_type = |t: u8| match t {
        TYPE_TRANSFER | TYPE_OWNER | TYPE_REISSUE => true,
        TYPE_NEW => bytes.len() > 39,
        _ => false,
    };

    // Classic form, OP_XNA_ASSET at byte 25. Below the fork the 25 bytes before
    // it are not checked, and the holder is the key hash at bytes 3..23 whatever
    // they are (`Solver`). Mainnet has scripts with a doubled OP_XNA_ASSET, where
    // the marker starts at byte 28 like after OP_PUSHDATA1.
    if bytes.len() > 31 && (!fork || is_p2pkh_base(bytes)) {
        if bytes[25] != OP_XNA_ASSET {
            return None;
        }
        let mut index = classic_marker_end(bytes, &ASSET_MAGIC);
        if index.is_none() && fork {
            index = classic_marker_end(bytes, &XNA_MARKER);
        }
        let index = index?;
        let type_byte = bytes[index];
        return accepted_type(type_byte).then(|| (p2pkh_script(&bytes[3..23]), index + 1, type_byte));
    }

    // AuthScript form, from the fork: OP_n <32 bytes> OP_XNA_ASSET <push> OP_DROP.
    if fork && bytes.len() > 40 && matches!(bytes[0], OP_1 | OP_2 | OP_3) && bytes[1] == 0x20 {
        if bytes[34] != OP_XNA_ASSET {
            return None;
        }
        let (data_start, data_len, next) = read_script_push(bytes, 35)?;
        let data = &bytes[data_start..data_start + data_len];
        if data.len() < 4 || (data[..3] != ASSET_MAGIC && data[..3] != XNA_MARKER) {
            return None;
        }
        if bytes[next..] != [OP_DROP] {
            return None;
        }
        let type_byte = data[3];
        return accepted_type(type_byte).then(|| (bytes[..34].to_vec(), data_start + 4, type_byte));
    }
    None
}

/// Index of the type byte after `marker` in a classic asset script: the marker
/// starts at byte 27 (direct push) or 28 (OP_PUSHDATA1, doubled OP_XNA_ASSET).
/// When byte 27 starts the marker but does not complete it, the daemon does
/// not try byte 28.
fn classic_marker_end(bytes: &[u8], marker: &[u8; 3]) -> Option<usize> {
    if bytes[27] == marker[0] {
        (bytes[28..30] == marker[1..]).then_some(30)
    } else {
        (bytes[28..31] == marker[..]).then_some(31)
    }
}

/// The opcode at `bytes[at]` as `CScript::GetOp` reads it: `(data start, data
/// length, next opcode)`. Non-push opcodes carry no data.
fn read_script_push(bytes: &[u8], at: usize) -> Option<(usize, usize, usize)> {
    let opcode = *bytes.get(at)?;
    let (len, header) = match opcode {
        0..=0x4b => (usize::from(opcode), 1),
        OP_PUSHDATA1 => (usize::from(*bytes.get(at + 1)?), 2),
        OP_PUSHDATA2 => (usize::from(u16::from_le_bytes(bytes.get(at + 1..at + 3)?.try_into().ok()?)), 3),
        OP_PUSHDATA4 => (u32::from_le_bytes(bytes.get(at + 1..at + 5)?.try_into().ok()?) as usize, 5),
        _ => (0, 1),
    };
    let start = at + header;
    let end = start.checked_add(len)?;
    (end <= bytes.len()).then_some((start, len, end))
}

fn is_p2pkh_base(bytes: &[u8]) -> bool {
    bytes.len() >= 25
        && bytes[0] == 0x76   // OP_DUP
        && bytes[1] == 0xa9   // OP_HASH160
        && bytes[2] == 0x14   // push 20 bytes
        && bytes[23] == 0x88  // OP_EQUALVERIFY
        && bytes[24] == 0xac  // OP_CHECKSIG
}

fn p2pkh_script(h160: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]);
    script.extend_from_slice(h160);
    script.extend_from_slice(&[0x88, 0xac]);
    script
}

// ─── unspendable null-asset scripts (OP_XNA_ASSET at front) ───────────────────

/// Address (or AuthScript program) being tagged/freed by a null-asset script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaggedDestination {
    /// Legacy 20-byte hash (P2PKH key-id or P2SH script-id).
    Legacy([u8; 20]),
    /// AuthScript witness program: version 1 (generic, NIP-025), 2 or 3 (strict).
    AuthScript { version: u8, program: [u8; 32] },
}

/// Parsed unspendable null-asset metadata script.
///
/// These outputs start with `OP_XNA_ASSET` and carry asset-system metadata
/// (qualifier tagging, restricted-asset freezing, verifier strings, DePIN
/// transfer states). They are unspendable — the daemon treats them as such in
/// `CScript::IsUnspendable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullAssetScript {
    /// Tag/untag a destination with a qualifier, or freeze/unfreeze a
    /// restricted (or DePIN) asset at a destination.
    AddressTag {
        destination: TaggedDestination,
        asset_name: String,
        flag: i8,
    },
    /// Globally freeze/unfreeze a restricted asset, or set the transfer state
    /// of a DePIN asset (`&NAME`: 0 closed, 1 open, 2 sealed).
    GlobalRestriction {
        asset_name: String,
        flag: i8,
    },
    /// Set/replace the verifier string for a restricted asset.
    Verifier {
        verifier_string: String,
    },
}

/// Returns `true` if the script is an unspendable null-asset script —
/// i.e. its first byte is `OP_XNA_ASSET`. Mirrors the daemon's
/// `CScript::IsUnspendable` check for OP_XNA_ASSET-prefixed scripts.
pub fn is_null_asset_script(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(&OP_XNA_ASSET))
}

/// The script an output is indexed under: the holder's script for an asset
/// output (so a wallet subscribed to the bare address sees its assets), the
/// script itself otherwise.
pub fn effective_script(bytes: &[u8], fork: bool) -> std::borrow::Cow<'_, [u8]> {
    match locate_asset_payload(bytes, fork) {
        Some((base, _, _)) if base == bytes[..base.len().min(bytes.len())] => {
            std::borrow::Cow::Borrowed(&bytes[..base.len()])
        }
        Some((base, _, _)) => std::borrow::Cow::Owned(base),
        None => std::borrow::Cow::Borrowed(bytes),
    }
}

/// Parse a null-asset script like the daemon's `AssetNullDataFromScript`,
/// `GlobalAssetNullDataFromScript` and `AssetNullVerifierDataFromScript`: the
/// data is read from a fixed offset (after a one-byte push opcode) to the end
/// of the script. Returns `None` if it is not one.
///
/// ```text
/// AddressTag (legacy):     OP_XNA_ASSET 0x14 <20-byte hash>            <push><asset_name varstr><flag i8>
/// AddressTag (AuthScript): OP_XNA_ASSET OP_1|2|3 0x20 <32 bytes>       <push><asset_name varstr><flag i8>   (from the fork)
/// GlobalRestriction:       OP_XNA_ASSET OP_RESERVED OP_RESERVED        <push><asset_name varstr><flag i8>
/// Verifier:                OP_XNA_ASSET OP_RESERVED                    <push><verifier varstr>
/// ```
pub fn parse_null_asset_script(bytes: &[u8], fork: bool) -> Option<NullAssetScript> {
    if !is_null_asset_script(bytes) {
        return None;
    }
    if bytes.len() > 23 && bytes[1] == 0x14 {
        let (asset_name, flag) = read_name_and_flag(&bytes[23..])?;
        return Some(NullAssetScript::AddressTag {
            destination: TaggedDestination::Legacy(bytes[2..22].try_into().expect("20 bytes")),
            asset_name,
            flag,
        });
    }
    if fork && bytes.len() > 36 && matches!(bytes[1], OP_1 | OP_2 | OP_3) && bytes[2] == 0x20 {
        let (asset_name, flag) = read_name_and_flag(&bytes[36..])?;
        return Some(NullAssetScript::AddressTag {
            destination: TaggedDestination::AuthScript {
                version: bytes[1] - OP_1 + 1,
                program: bytes[3..35].try_into().expect("32 bytes"),
            },
            asset_name,
            flag,
        });
    }
    if bytes.len() > 6 && bytes[1] == OP_RESERVED && bytes[2] == OP_RESERVED {
        let (asset_name, flag) = read_name_and_flag(&bytes[4..])?;
        return Some(NullAssetScript::GlobalRestriction { asset_name, flag });
    }
    if bytes.len() > 3 && bytes[1] == OP_RESERVED && bytes[2] != OP_RESERVED {
        let verifier_string = read_string(&mut &bytes[3..]).ok()?;
        return Some(NullAssetScript::Verifier { verifier_string });
    }
    None
}

// ─── asset-name classification ────────────────────────────────────────────────

/// Coarse category of an asset name, mirroring the daemon's `AssetType` enum.
///
/// This is a lightweight prefix/separator-based classifier — full validation
/// (character set, length limits, double-punctuation) is the daemon's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssetCategory {
    Root,
    Sub,
    Owner,
    Unique,
    MsgChannel,
    Vote,
    Qualifier,
    SubQualifier,
    Restricted,
    Depin,
    SubDepin,
}

/// Classify an asset name by its prefix/separator characters.
///
/// Returns `None` for empty names. DePIN names are returned regardless of
/// network gating — use [`is_category_active`] to check whether the daemon
/// would actually accept them at a given height.
pub fn classify_asset_name(name: &str) -> Option<AssetCategory> {
    if name.is_empty() {
        return None;
    }
    let first = name.as_bytes()[0];
    let last = *name.as_bytes().last().unwrap();
    let has_slash = name.as_bytes().contains(&SUB_SEPARATOR);

    Some(match first {
        QUALIFIER_PREFIX => {
            if has_slash {
                AssetCategory::SubQualifier
            } else {
                AssetCategory::Qualifier
            }
        }
        RESTRICTED_PREFIX => AssetCategory::Restricted,
        DEPIN_PREFIX => {
            if has_slash {
                AssetCategory::SubDepin
            } else {
                AssetCategory::Depin
            }
        }
        _ => {
            if last == OWNER_SUFFIX {
                AssetCategory::Owner
            } else if name.as_bytes().contains(&UNIQUE_SEPARATOR) {
                AssetCategory::Unique
            } else if name.as_bytes().contains(&MSG_CHANNEL_SEPARATOR) {
                AssetCategory::MsgChannel
            } else if name.as_bytes().contains(&VOTE_SEPARATOR) {
                AssetCategory::Vote
            } else if has_slash {
                AssetCategory::Sub
            } else {
                AssetCategory::Root
            }
        }
    })
}

/// Returns `true` if the asset category is enabled at `height` for the network
/// described by `depin_activation`. Only DePIN categories are network-gated;
/// every other category is always active.
pub fn is_category_active(
    cat: AssetCategory,
    depin_activation: Option<u32>,
    height: u32,
) -> bool {
    match cat {
        AssetCategory::Depin | AssetCategory::SubDepin => match depin_activation {
            Some(h) => height >= h,
            None => false,
        },
        _ => true,
    }
}

// ─── helpers for null-asset parsing ───────────────────────────────────────────

/// Read `CNullAssetTxData`: `<varstr asset_name><i8 flag>` (what follows is
/// ignored, as by the daemon's stream).
fn read_name_and_flag(mut data: &[u8]) -> Option<(String, i8)> {
    let name = read_string(&mut data).ok()?;
    let flag = *data.first()? as i8;
    Some((name, flag))
}

// ─── type-specific parsers (the daemon's `SerializationOp`s) ─────────────────

fn parse_new(mut data: &[u8]) -> Result<NewAsset> {
    let name = read_string(&mut data)?;
    let amount = read_i64_le(&mut data)?;
    let units = read_u8(&mut data)?;
    let reissuable = read_u8(&mut data)? != 0;
    let has_ipfs = read_u8(&mut data)? == 1;
    let ipfs = if has_ipfs { read_asset_hash(&mut data)? } else { None };
    Ok(NewAsset {
        name,
        amount,
        units,
        reissuable,
        ipfs,
    })
}

fn parse_transfer(mut data: &[u8]) -> Result<TransferAsset> {
    let name = read_string(&mut data)?;
    let amount = read_i64_le(&mut data)?;
    let message = match read_asset_hash(&mut data)? {
        Some(ipfs) => {
            let expire_time = if data.len() >= 8 { Some(read_i64_le(&mut data)?) } else { None };
            Some(AssetMessage { ipfs, expire_time })
        }
        None => None,
    };
    Ok(TransferAsset {
        name,
        amount,
        message,
    })
}

fn parse_reissue(mut data: &[u8]) -> Result<ReissueAsset> {
    let name = read_string(&mut data)?;
    let amount = read_i64_le(&mut data)?;
    let units = read_u8(&mut data)? as i8;
    let reissuable = read_u8(&mut data)? != 0;
    let ipfs = read_asset_hash(&mut data)?;
    Ok(ReissueAsset {
        name,
        amount,
        units,
        reissuable,
        ipfs,
    })
}

fn parse_owner(mut data: &[u8]) -> Result<OwnerAsset> {
    let name = read_string(&mut data)?;
    Ok(OwnerAsset { name })
}

// ─── low-level readers ────────────────────────────────────────────────────────

/// Bitcoin CompactSize reader (canonical, at most `MAX_SIZE`): returns
/// `(value, bytes_consumed)`.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let (value, used) = match first {
        0..=0xfc => (first as u64, 1),
        0xfd => {
            let v = u16::from_le_bytes(data.get(1..3)?.try_into().ok()?) as u64;
            (v >= 0xfd).then_some((v, 3))?
        }
        0xfe => {
            let v = u32::from_le_bytes(data.get(1..5)?.try_into().ok()?) as u64;
            (v >= 0x10000).then_some((v, 5))?
        }
        0xff => {
            let v = u64::from_le_bytes(data.get(1..9)?.try_into().ok()?);
            (v >= 0x1_0000_0000).then_some((v, 9))?
        }
    };
    (value <= MAX_SIZE).then_some((value, used))
}

fn read_string(data: &mut &[u8]) -> Result<String> {
    let (len, used) = read_varint(data).context("string length varint")?;
    *data = &data[used..];
    let len = len as usize;
    if data.len() < len {
        bail!("short string");
    }
    let bytes = &data[..len];
    *data = &data[len..];
    String::from_utf8(bytes.to_vec()).context("invalid utf-8 in asset name")
}

fn read_u8(data: &mut &[u8]) -> Result<u8> {
    if data.is_empty() {
        bail!("unexpected end reading u8");
    }
    let v = data[0];
    *data = &data[1..];
    Ok(v)
}

fn read_i64_le(data: &mut &[u8]) -> Result<i64> {
    if data.len() < 8 {
        bail!("short i64");
    }
    let v = i64::from_le_bytes(data[..8].try_into().unwrap());
    *data = &data[8..];
    Ok(v)
}

/// `ReadWriteAssetHash`: only when at least 33 bytes remain, a one-byte marker
/// (0x12 for an IPFS hash, 0x54 for a txid) then a string whose first 32 bytes
/// are the hash.
fn read_asset_hash(data: &mut &[u8]) -> Result<Option<IpfsRef>> {
    if data.len() < 33 {
        return Ok(None);
    }
    let marker = read_u8(data)?;
    let (len, used) = read_varint(data).context("hash length varint")?;
    *data = &data[used..];
    let len = len as usize;
    if data.len() < len {
        bail!("short hash");
    }
    let mut hash = [0u8; 32];
    let n = len.min(32);
    hash[..n].copy_from_slice(&data[..n]);
    *data = &data[len..];
    Ok(Some(IpfsRef { marker, hash }))
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const P2PKH_HASH: [u8; 20] = [0xAAu8; 20];

    fn p2pkh_prefix() -> Vec<u8> {
        let mut v = Vec::with_capacity(25);
        v.extend_from_slice(&[0x76, 0xa9, 0x14]);
        v.extend_from_slice(&P2PKH_HASH);
        v.extend_from_slice(&[0x88, 0xac]);
        v
    }

    fn op1_32_prefix() -> Vec<u8> {
        let mut v = Vec::with_capacity(34);
        v.push(0x51); // OP_1
        v.push(0x20); // push 32
        v.extend_from_slice(&[0xBBu8; 32]);
        v
    }

    /// Wrap a payload (after the 'rvn' magic + type byte) as a full asset script
    /// over a P2PKH base.
    fn wrap_p2pkh(type_byte: u8, tail: &[u8]) -> Vec<u8> {
        let mut payload = Vec::from(ASSET_MAGIC);
        payload.push(type_byte);
        payload.extend_from_slice(tail);
        assert!(payload.len() <= 0xff, "tests stay within OP_PUSHDATA1 range");
        let mut script = p2pkh_prefix();
        script.push(OP_XNA_ASSET);
        // Same encoding as the daemon's `CScript << std::vector<unsigned char>`.
        if payload.len() >= OP_PUSHDATA1 as usize {
            script.push(OP_PUSHDATA1);
        }
        script.push(payload.len() as u8);
        script.extend_from_slice(&payload);
        script.push(OP_DROP);
        script
    }

    #[test]
    fn parse_new_asset() {
        let mut body = Vec::new();
        body.push(5u8); // name length
        body.extend_from_slice(b"TOKEN");
        body.extend_from_slice(&1_000i64.to_le_bytes());
        body.push(0);   // units
        body.push(1);   // reissuable
        body.push(0);   // no ipfs
        let script = wrap_p2pkh(TYPE_NEW, &body);

        let out = parse_asset_script(&script, false).expect("parse");
        assert_eq!(out.base_script, p2pkh_prefix());
        match out.data {
            AssetData::New(a) => {
                assert_eq!(a.name, "TOKEN");
                assert_eq!(a.amount, 1_000);
                assert_eq!(a.units, 0);
                assert!(a.reissuable);
                assert!(a.ipfs.is_none());
            }
            _ => panic!("expected New"),
        }
    }

    #[test]
    fn parse_new_asset_with_ipfs() {
        let mut body = Vec::new();
        body.push(7u8);
        body.extend_from_slice(b"MYCOIN.");
        body.extend_from_slice(&0i64.to_le_bytes());
        body.push(2);   // units
        body.push(0);   // not reissuable
        body.push(1);   // has ipfs
        body.push(IPFS_MARKER);
        body.push(0x20);
        body.extend_from_slice(&[0x11u8; 32]);
        let script = wrap_p2pkh(TYPE_NEW, &body);

        let out = parse_asset_script(&script, false).expect("parse");
        let a = match out.data {
            AssetData::New(a) => a,
            _ => panic!(),
        };
        assert_eq!(a.name, "MYCOIN.");
        assert!(!a.reissuable);
        let ipfs = a.ipfs.expect("ipfs");
        assert_eq!(ipfs.marker, IPFS_MARKER);
        assert_eq!(ipfs.hash, [0x11u8; 32]);
    }

    #[test]
    fn parse_transfer_bare() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"COIN");
        body.extend_from_slice(&42i64.to_le_bytes());
        let script = wrap_p2pkh(TYPE_TRANSFER, &body);

        let out = parse_asset_script(&script, false).expect("parse");
        match out.data {
            AssetData::Transfer(t) => {
                assert_eq!(t.name, "COIN");
                assert_eq!(t.amount, 42);
                assert!(t.message.is_none());
            }
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn parse_transfer_with_message_and_expiry() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"COIN");
        body.extend_from_slice(&1i64.to_le_bytes());
        body.push(TXID_MARKER);
        body.push(0x20);
        body.extend_from_slice(&[0x77u8; 32]);
        body.extend_from_slice(&9_000_000_000i64.to_le_bytes()); // expire
        let script = wrap_p2pkh(TYPE_TRANSFER, &body);

        let out = parse_asset_script(&script, false).expect("parse");
        let t = match out.data {
            AssetData::Transfer(t) => t,
            _ => panic!(),
        };
        let msg = t.message.expect("message");
        assert_eq!(msg.ipfs.marker, TXID_MARKER);
        assert_eq!(msg.ipfs.hash, [0x77u8; 32]);
        assert_eq!(msg.expire_time, Some(9_000_000_000));
    }

    #[test]
    fn parse_reissue() {
        let mut body = Vec::new();
        body.push(5u8);
        body.extend_from_slice(b"REISS");
        body.extend_from_slice(&500i64.to_le_bytes());
        body.push(3);   // new units
        body.push(0);   // no longer reissuable
        let script = wrap_p2pkh(TYPE_REISSUE, &body);

        let out = parse_asset_script(&script, false).expect("parse");
        match out.data {
            AssetData::Reissue(r) => {
                assert_eq!(r.name, "REISS");
                assert_eq!(r.amount, 500);
                assert_eq!(r.units, 3);
                assert!(!r.reissuable);
                assert!(r.ipfs.is_none());
            }
            _ => panic!("expected Reissue"),
        }
    }

    #[test]
    fn parse_owner() {
        let mut body = Vec::new();
        body.push(6u8);
        body.extend_from_slice(b"TOKEN!");
        let script = wrap_p2pkh(TYPE_OWNER, &body);

        let out = parse_asset_script(&script, false).expect("parse");
        match out.data {
            AssetData::Owner(o) => assert_eq!(o.name, "TOKEN!"),
            _ => panic!("expected Owner"),
        }
    }

    #[test]
    fn parse_asset_with_op1_base() {
        let mut body = Vec::new();
        body.push(3u8);
        body.extend_from_slice(b"NEU");
        body.extend_from_slice(&1i64.to_le_bytes());

        let mut payload = Vec::from(ASSET_MAGIC);
        payload.push(TYPE_TRANSFER);
        payload.extend_from_slice(&body);

        let mut script = op1_32_prefix();
        script.push(OP_XNA_ASSET);
        script.push(payload.len() as u8);
        script.extend_from_slice(&payload);
        script.push(OP_DROP);

        assert!(parse_asset_script(&script, false).is_none(), "AuthScript form before the fork");
        let out = parse_asset_script(&script, true).expect("parse");
        assert_eq!(out.base_script, op1_32_prefix());
        match out.data {
            AssetData::Transfer(t) => assert_eq!(t.name, "NEU"),
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn plain_p2pkh_is_not_an_asset() {
        let script = p2pkh_prefix();
        assert!(parse_asset_script(&script, false).is_none());
    }

    /// `IsAssetScript` does not look past the type byte in the classic form,
    /// so the daemon reads a transfer without OP_DROP; the AuthScript form must
    /// end with it.
    #[test]
    fn op_drop_only_checked_in_the_authscript_form() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"TEST");
        body.extend_from_slice(&1i64.to_le_bytes());
        let mut script = wrap_p2pkh(TYPE_TRANSFER, &body);
        *script.last_mut().unwrap() = 0x00; // clobber OP_DROP
        for fork in [false, true] {
            match parse_asset_script(&script, fork).expect("classic form").data {
                AssetData::Transfer(t) => assert_eq!((t.name.as_str(), t.amount), ("TEST", 1)),
                other => panic!("expected Transfer, got {other:?}"),
            }
        }
        let mut script = authscript_wrap(OP_2, b"xna", TYPE_TRANSFER, &body);
        *script.last_mut().unwrap() = 0x00;
        assert!(parse_asset_script(&script, true).is_none());
    }

    #[test]
    fn wrong_magic_rejected() {
        let mut script = p2pkh_prefix();
        script.push(OP_XNA_ASSET);
        script.push(0x08);
        script.extend_from_slice(b"xyz"); // wrong magic
        script.push(TYPE_TRANSFER);
        script.extend_from_slice(&[0u8; 4]);
        script.push(OP_DROP);
        assert!(parse_asset_script(&script, false).is_none());
    }

    #[test]
    fn unknown_type_byte_rejected() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"TEST");
        body.extend_from_slice(&1i64.to_le_bytes());
        let script = wrap_p2pkh(b'z', &body); // 'z' is not a known type
        assert!(parse_asset_script(&script, false).is_none());
    }

    // ─── classify_asset_name ──────────────────────────────────────────────────

    #[test]
    fn classify_basic_names() {
        assert_eq!(classify_asset_name("TOKEN"), Some(AssetCategory::Root));
        assert_eq!(classify_asset_name("ROOT/SUB"), Some(AssetCategory::Sub));
        assert_eq!(classify_asset_name("TOKEN!"), Some(AssetCategory::Owner));
        assert_eq!(classify_asset_name("ROOT#TAG"), Some(AssetCategory::Unique));
        assert_eq!(classify_asset_name("ROOT~CHAN"), Some(AssetCategory::MsgChannel));
        assert_eq!(classify_asset_name("ROOT^VOTE"), Some(AssetCategory::Vote));
    }

    #[test]
    fn classify_qualifier_and_subqualifier() {
        assert_eq!(classify_asset_name("#KYC"), Some(AssetCategory::Qualifier));
        assert_eq!(classify_asset_name("#KYC/#REGION"), Some(AssetCategory::SubQualifier));
    }

    #[test]
    fn classify_restricted() {
        assert_eq!(classify_asset_name("$RESTRICTED"), Some(AssetCategory::Restricted));
    }

    #[test]
    fn classify_depin_and_subdepin() {
        assert_eq!(classify_asset_name("&NODE"), Some(AssetCategory::Depin));
        assert_eq!(classify_asset_name("&NODE/SENSOR"), Some(AssetCategory::SubDepin));
    }

    #[test]
    fn classify_empty_is_none() {
        assert_eq!(classify_asset_name(""), None);
    }

    // ─── is_category_active ───────────────────────────────────────────────────

    #[test]
    fn depin_inactive_on_mainnet_until_activation_set() {
        // Mainnet: activation = None → DePIN never active.
        assert!(!is_category_active(AssetCategory::Depin, None, 0));
        assert!(!is_category_active(AssetCategory::Depin, None, 1_000_000));
        assert!(!is_category_active(AssetCategory::SubDepin, None, 1_000_000));
    }

    #[test]
    fn depin_active_on_testnet_from_genesis() {
        // Testnet/regtest: activation = Some(0) → active from height 0.
        assert!(is_category_active(AssetCategory::Depin, Some(0), 0));
        assert!(is_category_active(AssetCategory::SubDepin, Some(0), 0));
    }

    #[test]
    fn depin_activates_at_fork_height() {
        // Once a mainnet fork height is set, DePIN becomes active only
        // at or after that height.
        assert!(!is_category_active(AssetCategory::Depin, Some(500_000), 499_999));
        assert!(is_category_active(AssetCategory::Depin, Some(500_000), 500_000));
        assert!(is_category_active(AssetCategory::Depin, Some(500_000), 500_001));
    }

    #[test]
    fn non_depin_categories_unaffected_by_gating() {
        // All non-DePIN categories are always active regardless of the gate.
        for cat in [
            AssetCategory::Root,
            AssetCategory::Sub,
            AssetCategory::Owner,
            AssetCategory::Unique,
            AssetCategory::MsgChannel,
            AssetCategory::Vote,
            AssetCategory::Qualifier,
            AssetCategory::SubQualifier,
            AssetCategory::Restricted,
        ] {
            assert!(is_category_active(cat, None, 0));
            assert!(is_category_active(cat, Some(0), 0));
        }
    }

    // ─── null-asset scripts ───────────────────────────────────────────────────

    /// Encode a string with bitcoin's compact-size length prefix.
    /// All test strings stay under 0xfd, so a single-byte length suffices.
    fn varstr(s: &str) -> Vec<u8> {
        assert!(s.len() < 0xfd);
        let mut out = Vec::with_capacity(s.len() + 1);
        out.push(s.len() as u8);
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn push_blob(blob: &[u8]) -> Vec<u8> {
        assert!(blob.len() <= 0x4b, "tests stay in direct-push range");
        let mut out = Vec::with_capacity(blob.len() + 1);
        out.push(blob.len() as u8);
        out.extend_from_slice(blob);
        out
    }

    #[test]
    fn is_null_asset_script_detects_op_xna_prefix() {
        assert!(is_null_asset_script(&[OP_XNA_ASSET, 0x14]));
        assert!(is_null_asset_script(&[OP_XNA_ASSET]));
        assert!(!is_null_asset_script(&[0x76, 0xa9]));
        assert!(!is_null_asset_script(&[]));
    }

    #[test]
    fn parse_null_legacy_address_tag() {
        let hash = [0x42u8; 20];
        let mut inner = varstr("#KYC");
        inner.push(1u8); // flag = 1 (add)

        let mut script = vec![OP_XNA_ASSET, 0x14];
        script.extend_from_slice(&hash);
        script.extend_from_slice(&push_blob(&inner));

        let parsed = parse_null_asset_script(&script, false).expect("parse");
        match parsed {
            NullAssetScript::AddressTag {
                destination: TaggedDestination::Legacy(h),
                asset_name,
                flag,
            } => {
                assert_eq!(h, hash);
                assert_eq!(asset_name, "#KYC");
                assert_eq!(flag, 1);
            }
            other => panic!("expected legacy AddressTag, got {other:?}"),
        }
    }

    #[test]
    fn parse_null_authscript_address_tag() {
        let commitment = [0x77u8; 32];
        let mut inner = varstr("$RESTRICT");
        inner.push((-1i8) as u8); // freeze flag

        let mut script = vec![OP_XNA_ASSET, OP_1, 0x20];
        script.extend_from_slice(&commitment);
        script.extend_from_slice(&push_blob(&inner));

        assert!(parse_null_asset_script(&script, false).is_none(), "before the fork");
        let parsed = parse_null_asset_script(&script, true).expect("parse");
        match parsed {
            NullAssetScript::AddressTag {
                destination: TaggedDestination::AuthScript { version, program },
                asset_name,
                flag,
            } => {
                assert_eq!(version, 1);
                assert_eq!(program, commitment);
                assert_eq!(asset_name, "$RESTRICT");
                assert_eq!(flag, -1);
            }
            other => panic!("expected AuthScript AddressTag, got {other:?}"),
        }
    }

    #[test]
    fn parse_null_global_restriction() {
        let mut inner = varstr("$GLOB");
        inner.push(1u8);

        let mut script = vec![OP_XNA_ASSET, OP_RESERVED, OP_RESERVED];
        script.extend_from_slice(&push_blob(&inner));

        let parsed = parse_null_asset_script(&script, false).expect("parse");
        match parsed {
            NullAssetScript::GlobalRestriction { asset_name, flag } => {
                assert_eq!(asset_name, "$GLOB");
                assert_eq!(flag, 1);
            }
            other => panic!("expected GlobalRestriction, got {other:?}"),
        }
    }

    #[test]
    fn parse_null_verifier() {
        let inner = varstr("#KYC&#REGION_EU");
        let mut script = vec![OP_XNA_ASSET, OP_RESERVED];
        script.extend_from_slice(&push_blob(&inner));

        let parsed = parse_null_asset_script(&script, false).expect("parse");
        match parsed {
            NullAssetScript::Verifier { verifier_string } => {
                assert_eq!(verifier_string, "#KYC&#REGION_EU");
            }
            other => panic!("expected Verifier, got {other:?}"),
        }
    }

    /// Verifier (1 OP_RESERVED) and GlobalRestriction (2 OP_RESERVED) must not
    /// be confused: a leading `c0 50 50` is global, `c0 50 <something else>`
    /// is a verifier.
    #[test]
    fn verifier_vs_global_restriction_disambiguation() {
        // Two OP_RESERVED → GlobalRestriction
        let mut inner = varstr("$X");
        inner.push(0u8);
        let mut script = vec![OP_XNA_ASSET, OP_RESERVED, OP_RESERVED];
        script.extend_from_slice(&push_blob(&inner));
        assert!(matches!(
            parse_null_asset_script(&script, false),
            Some(NullAssetScript::GlobalRestriction { .. })
        ));

        // One OP_RESERVED then a push → Verifier
        let inner = varstr("verifier");
        let mut script = vec![OP_XNA_ASSET, OP_RESERVED];
        script.extend_from_slice(&push_blob(&inner));
        assert!(matches!(
            parse_null_asset_script(&script, false),
            Some(NullAssetScript::Verifier { .. })
        ));
    }

    #[test]
    fn non_xna_script_not_null_asset() {
        // P2PKH script must not be confused with a null-asset.
        assert!(parse_null_asset_script(&p2pkh_prefix(), false).is_none());
    }

    // ─── effective_script ─────────────────────────────────────────────────────

    #[test]
    fn effective_script_non_asset_passes_through() {
        let p2pkh = p2pkh_prefix();
        assert_eq!(effective_script(&p2pkh, false), p2pkh.as_slice());

        let authscript = op1_32_prefix();
        assert_eq!(effective_script(&authscript, false), authscript.as_slice());

        // Random bytes (not a valid script) — also pass through unchanged.
        let junk = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(effective_script(&junk, false), junk.as_slice());

        // Empty input passes through.
        assert_eq!(effective_script(&[], false), &[] as &[u8]);
    }

    #[test]
    fn effective_script_strips_p2pkh_asset_wrapper() {
        // Build a valid P2PKH + OP_XNA_ASSET transfer wrapper.
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"COIN");
        body.extend_from_slice(&1i64.to_le_bytes());
        let wrapped = wrap_p2pkh(TYPE_TRANSFER, &body);

        // effective_script should return only the P2PKH base (25 bytes).
        let effective = effective_script(&wrapped, false);
        assert_eq!(effective, p2pkh_prefix().as_slice());
        assert_eq!(effective.len(), 25);
    }

    #[test]
    fn effective_script_strips_authscript_asset_wrapper() {
        // Build a valid AuthScript (OP_1 + 0x20 + 32 bytes) + asset wrapper.
        let mut body = Vec::new();
        body.push(3u8);
        body.extend_from_slice(b"NEU");
        body.extend_from_slice(&1i64.to_le_bytes());
        let mut payload = Vec::from(ASSET_MAGIC);
        payload.push(TYPE_TRANSFER);
        payload.extend_from_slice(&body);
        let mut wrapped = op1_32_prefix();
        wrapped.push(OP_XNA_ASSET);
        wrapped.push(payload.len() as u8);
        wrapped.extend_from_slice(&payload);
        wrapped.push(OP_DROP);

        assert_eq!(effective_script(&wrapped, false), wrapped.as_slice(), "before the fork");
        let effective = effective_script(&wrapped, true);
        assert_eq!(effective, op1_32_prefix().as_slice());
        assert_eq!(effective.len(), 34);
    }

    /// Core Fase-0 invariant: a wallet subscribed to `SHA256(bare_address_script)`
    /// must see asset transfers to that address, because the effective scripthash
    /// of an asset-wrapped output is the scripthash of its base script.
    #[test]
    fn effective_script_invariant_scripthash() {
        use bitcoin::hashes::{sha256, Hash};

        // Build a P2PKH + asset transfer.
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"COIN");
        body.extend_from_slice(&1i64.to_le_bytes());
        let wrapped = wrap_p2pkh(TYPE_TRANSFER, &body);

        let bare_hash = sha256::Hash::hash(&p2pkh_prefix());
        let wrapped_full_hash = sha256::Hash::hash(&wrapped);
        let wrapped_effective_hash = sha256::Hash::hash(&effective_script(&wrapped, false));

        assert_ne!(
            bare_hash, wrapped_full_hash,
            "sanity: full-script hash should differ from base-script hash"
        );
        assert_eq!(
            bare_hash, wrapped_effective_hash,
            "effective scripthash of an asset-wrapped output must equal the bare-address scripthash"
        );
    }

    #[test]
    fn effective_script_does_not_strip_null_asset() {
        // Null-asset scripts (OP_XNA_ASSET at byte 0) are NOT asset-wrapped
        // outputs — they are unspendable metadata. effective_script returns
        // them unchanged.
        let mut inner = vec![3u8];
        inner.extend_from_slice(b"#KY");
        inner.push(1u8);
        let mut script = vec![OP_XNA_ASSET, 0x14];
        script.extend_from_slice(&[0u8; 20]);
        script.push(inner.len() as u8);
        script.extend_from_slice(&inner);
        assert_eq!(effective_script(&script, false), script.as_slice());
    }

    // ─── real scripts produced by neuraid v1.0.7 (regtest) ────────────────────
    //
    // Captured from `getblock <hash> 2` after running the wallet RPCs named in
    // each constant. They pin the exact on-chain encoding of the mainnet
    // release, including the OP_PUSHDATA1 form used for payloads >= 76 bytes.

    const IPFS_FIXTURE: &str = "51c87ba0b5f1bc07f19513007f22f4a9dd9211560d416094cd15de1e5080f311";

    fn unhex(s: &str) -> Vec<u8> {
        use bitcoin::hashes::hex::FromHex;
        Vec::from_hex(s).expect("valid hex fixture")
    }

    fn ipfs_fixture() -> [u8; 32] {
        unhex(IPFS_FIXTURE).try_into().unwrap()
    }

    /// `issue ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 1000 <addr> "" 8 true true <ipfs>`
    /// — 80-byte payload, encoded as `c0 4c 50 ...`.
    const V107_NEW_LONG_NAME_IPFS: &str =
        "76a914a2825ed4fefe6440124cdb0514483504fa9701fa88acc04c5072766e711e4142434445464748494a4b4c4d4e4f505152535455565758595a3031323300e8764817000000080101122051c87ba0b5f1bc07f19513007f22f4a9dd9211560d416094cd15de1e5080f31175";

    /// `transfer LONGTRANSFERNAME12345 7 <addr> <ipfs> 9999999999`
    /// — message + expire time, 76-byte payload.
    const V107_TRANSFER_MESSAGE_EXPIRE: &str =
        "76a9149b312db54c03455177cc6bf4e5364f5191b7a30888acc04c4c72766e74154c4f4e475452414e534645524e414d4531323334350027b92900000000122051c87ba0b5f1bc07f19513007f22f4a9dd9211560d416094cd15de1e5080f311ffe30b540200000075";

    /// `transfer ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 1.5 <addr> <ipfs> 1999999999`
    const V107_TRANSFER_LONG_NAME_MESSAGE: &str =
        "76a9149b312db54c03455177cc6bf4e5364f5191b7a30888acc04c5572766e741e4142434445464748494a4b4c4d4e4f505152535455565758595a3031323380d1f00800000000122051c87ba0b5f1bc07f19513007f22f4a9dd9211560d416094cd15de1e5080f311ff9335770000000075";

    /// `reissue ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 50 <addr> "" true -1`
    /// — units byte is 0xff (= keep current units), no IPFS.
    const V107_REISSUE_KEEP_UNITS: &str =
        "76a914a2825ed4fefe6440124cdb0514483504fa9701fa88acc02d72766e721e4142434445464748494a4b4c4d4e4f505152535455565758595a3031323300f2052a01000000ff0175";

    /// `reissue SHORT 10 <addr> "" true 4 <ipfs>`
    const V107_REISSUE_UNITS_IPFS: &str =
        "76a914a2825ed4fefe6440124cdb0514483504fa9701fa88acc03672766e720553484f525400ca9a3b000000000401122051c87ba0b5f1bc07f19513007f22f4a9dd9211560d416094cd15de1e5080f31175";

    #[test]
    fn v107_new_asset_with_pushdata1_payload() {
        let script = unhex(V107_NEW_LONG_NAME_IPFS);
        let out = parse_asset_script(&script, false).expect("parse");
        assert_eq!(out.base_script, script[..25].to_vec());
        assert_eq!(
            out.data,
            AssetData::New(NewAsset {
                name: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123".into(),
                amount: 1000 * 100_000_000,
                units: 8,
                reissuable: true,
                ipfs: Some(IpfsRef { marker: IPFS_MARKER, hash: ipfs_fixture() }),
            })
        );
        assert_eq!(effective_script(&script, false), &script[..25]);
    }

    #[test]
    fn v107_transfers_with_message_use_pushdata1() {
        let out = parse_asset_script(&unhex(V107_TRANSFER_MESSAGE_EXPIRE), false).expect("parse");
        assert_eq!(
            out.data,
            AssetData::Transfer(TransferAsset {
                name: "LONGTRANSFERNAME12345".into(),
                amount: 7 * 100_000_000,
                message: Some(AssetMessage {
                    ipfs: IpfsRef { marker: IPFS_MARKER, hash: ipfs_fixture() },
                    expire_time: Some(9_999_999_999),
                }),
            })
        );

        let out = parse_asset_script(&unhex(V107_TRANSFER_LONG_NAME_MESSAGE), false).expect("parse");
        match out.data {
            AssetData::Transfer(t) => {
                assert_eq!(t.name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123");
                assert_eq!(t.amount, 150_000_000);
                assert_eq!(t.message.unwrap().expire_time, Some(1_999_999_999));
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn v107_reissue_units_minus_one_means_unchanged() {
        let out = parse_asset_script(&unhex(V107_REISSUE_KEEP_UNITS), false).expect("parse");
        assert_eq!(
            out.data,
            AssetData::Reissue(ReissueAsset {
                name: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123".into(),
                amount: 50 * 100_000_000,
                units: -1,
                reissuable: true,
                ipfs: None,
            })
        );

        let out = parse_asset_script(&unhex(V107_REISSUE_UNITS_IPFS), false).expect("parse");
        assert_eq!(
            out.data,
            AssetData::Reissue(ReissueAsset {
                name: "SHORT".into(),
                amount: 10 * 100_000_000,
                units: 4,
                reissuable: true,
                ipfs: Some(IpfsRef { marker: IPFS_MARKER, hash: ipfs_fixture() }),
            })
        );
    }

    #[test]
    fn v107_null_asset_verifier_and_global_freeze() {
        // issuerestrictedasset '$SHORT' 1000 "#KYC" <addr>
        assert_eq!(
            parse_null_asset_script(&unhex("c05004034b5943"), false),
            Some(NullAssetScript::Verifier { verifier_string: "KYC".into() })
        );
        // freezerestrictedasset '$SHORT'
        assert_eq!(
            parse_null_asset_script(&unhex("c0505008062453484f525401"), false),
            Some(NullAssetScript::GlobalRestriction { asset_name: "$SHORT".into(), flag: 1 })
        );
    }

    #[test]
    fn pushdata2_payload_is_not_an_asset() {
        // `IsAssetScript` only finds "rvn" at offset 27 or 28, so an
        // OP_PUSHDATA2-encoded payload is not an asset script for the daemon.
        let mut script = p2pkh_prefix();
        script.extend_from_slice(&[OP_XNA_ASSET, 0x4d, 0x11, 0x00]);
        script.extend_from_slice(b"rvnt");
        script.push(4);
        script.extend_from_slice(b"COIN");
        script.extend_from_slice(&1i64.to_le_bytes());
        script.push(OP_DROP);
        assert!(parse_asset_script(&script, false).is_none());
    }

    #[test]
    fn null_asset_trailing_bytes_are_ignored() {
        // The daemon's stream stops after `flag`.
        let hash = [0u8; 20];
        let mut inner = varstr("#X");
        inner.push(1u8);
        inner.push(0xff);
        let mut script = vec![OP_XNA_ASSET, 0x14];
        script.extend_from_slice(&hash);
        script.extend_from_slice(&push_blob(&inner));
        assert_eq!(
            parse_null_asset_script(&script, false),
            Some(NullAssetScript::AddressTag {
                destination: TaggedDestination::Legacy(hash),
                asset_name: "#X".into(),
                flag: 1,
            })
        );
    }

    // ─── Neurai 2.0 (unified fork, DePIN-Test) ────────────────────────────────

    /// `<OP_n> <32 bytes> OP_XNA_ASSET <push(marker type tail)> OP_DROP`
    fn authscript_wrap(version_op: u8, marker: &[u8; 3], type_byte: u8, tail: &[u8]) -> Vec<u8> {
        let mut payload = marker.to_vec();
        payload.push(type_byte);
        payload.extend_from_slice(tail);
        let mut script = vec![version_op, 0x20];
        script.extend_from_slice(&[0xCCu8; 32]);
        script.push(OP_XNA_ASSET);
        if payload.len() >= OP_PUSHDATA1 as usize {
            script.push(OP_PUSHDATA1);
        }
        script.push(payload.len() as u8);
        script.extend_from_slice(&payload);
        script.push(OP_DROP);
        script
    }

    fn transfer_body(name: &str, amount: i64) -> Vec<u8> {
        let mut body = varstr(name);
        body.extend_from_slice(&amount.to_le_bytes());
        body
    }

    #[test]
    fn xna_marker_from_the_fork() {
        let mut script = wrap_p2pkh(TYPE_TRANSFER, &transfer_body("COIN", 5));
        script[27..30].copy_from_slice(b"xna");
        assert!(parse_asset_script(&script, false).is_none(), "1.0.7 rules");
        let out = parse_asset_script(&script, true).expect("xna transfer");
        assert_eq!(out.base_script, p2pkh_prefix());
        assert!(matches!(out.data, AssetData::Transfer(ref t) if t.name == "COIN" && t.amount == 5));
    }

    #[test]
    fn strict_authscript_asset_outputs() {
        for (op, marker) in [(OP_1, b"rvn"), (OP_2, b"xna"), (OP_3, b"xna"), (OP_3, b"rvn")] {
            let script = authscript_wrap(op, marker, TYPE_TRANSFER, &transfer_body("&DEVICE", 1));
            assert!(parse_asset_script(&script, false).is_none());
            let out = parse_asset_script(&script, true).expect("AuthScript transfer");
            assert_eq!(out.base_script, script[..34].to_vec());
            assert_eq!(effective_script(&script, true), &script[..34]);
            assert!(matches!(out.data, AssetData::Transfer(ref t) if t.name == "&DEVICE"));
        }
        let script = authscript_wrap(0x54, b"xna", TYPE_TRANSFER, &transfer_body("COIN", 1));
        assert!(parse_asset_script(&script, true).is_none(), "OP_4 is not an AuthScript family");
        let script = authscript_wrap(OP_2, b"xnb", TYPE_TRANSFER, &transfer_body("COIN", 1));
        assert!(parse_asset_script(&script, true).is_none(), "unknown marker");
    }

    /// Mainnet has transfers with a doubled OP_XNA_ASSET (`c0 c0 <len> rvn...`):
    /// the marker starts at byte 28, as after OP_PUSHDATA1.
    #[test]
    fn doubled_op_xna_asset() {
        let mut payload = ASSET_MAGIC.to_vec();
        payload.push(TYPE_TRANSFER);
        payload.extend(transfer_body("COIN", 9));
        let mut script = p2pkh_prefix();
        script.extend([OP_XNA_ASSET, OP_XNA_ASSET, payload.len() as u8]);
        script.extend(&payload);
        script.push(OP_DROP);
        for fork in [false, true] {
            let out = parse_asset_script(&script, fork).expect("doubled OP_XNA_ASSET");
            assert!(matches!(out.data, AssetData::Transfer(ref t) if t.name == "COIN" && t.amount == 9));
        }
    }

    /// Below the fork the 25 bytes before OP_XNA_ASSET are not checked and the
    /// holder is P2PKH(bytes 3..23); from the fork they must be P2PKH.
    #[test]
    fn non_p2pkh_prefix() {
        let mut script = wrap_p2pkh(TYPE_TRANSFER, &transfer_body("COIN", 3));
        script[0] = 0x00;
        script[24] = 0x00;
        let out = parse_asset_script(&script, false).expect("1.0.7 reads it");
        assert_eq!(out.base_script, p2pkh_prefix());
        assert_eq!(effective_script(&script, false), p2pkh_prefix().as_slice());
        assert!(parse_asset_script(&script, true).is_none());
    }

    /// Optional fields are read like `ReadWriteAssetHash`: only when at least
    /// 33 bytes remain, counting the final OP_DROP.
    #[test]
    fn optional_fields_follow_the_daemon_stream() {
        // 32 bytes after the amount + OP_DROP = 33: the daemon reads a "message"
        let mut body = transfer_body("COIN", 1);
        body.push(IPFS_MARKER);
        body.push(0x1e); // a 30-byte string
        body.extend([0x42; 30]);
        let out = parse_asset_script(&wrap_p2pkh(TYPE_TRANSFER, &body), false).expect("transfer");
        let message = match out.data {
            AssetData::Transfer(t) => t.message.expect("message"),
            other => panic!("expected Transfer, got {other:?}"),
        };
        assert_eq!(message.ipfs.hash[..30], [0x42; 30]);
        assert_eq!(message.expire_time, None);

        // nHasIPFS must be exactly 1
        let mut body = varstr("TOKEN");
        body.extend_from_slice(&1i64.to_le_bytes());
        body.extend([0, 1, 2]); // units, reissuable, nHasIPFS = 2
        body.extend([IPFS_MARKER, 0x20]);
        body.extend([0x11; 32]);
        match parse_asset_script(&wrap_p2pkh(TYPE_NEW, &body), false).expect("new").data {
            AssetData::New(a) => assert!(a.ipfs.is_none()),
            other => panic!("expected New, got {other:?}"),
        }
    }

    #[test]
    fn authscript_tags_by_family() {
        for (op, version) in [(OP_1, 1), (OP_2, 2), (OP_3, 3)] {
            let mut inner = varstr("#KYC");
            inner.push(1);
            let mut script = vec![OP_XNA_ASSET, op, 0x20];
            script.extend([0x5A; 32]);
            script.extend(push_blob(&inner));
            assert_eq!(
                parse_null_asset_script(&script, true),
                Some(NullAssetScript::AddressTag {
                    destination: TaggedDestination::AuthScript { version, program: [0x5A; 32] },
                    asset_name: "#KYC".into(),
                    flag: 1,
                })
            );
        }
    }

    #[test]
    fn depin_transfer_state_is_a_global_restriction_script() {
        let mut inner = varstr("&DEVICE");
        inner.push(2); // sealed
        let mut script = vec![OP_XNA_ASSET, OP_RESERVED, OP_RESERVED];
        script.extend(push_blob(&inner));
        assert_eq!(
            parse_null_asset_script(&script, true),
            Some(NullAssetScript::GlobalRestriction { asset_name: "&DEVICE".into(), flag: 2 })
        );
    }
}
