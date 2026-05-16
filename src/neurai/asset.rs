//! Neurai asset opcode parser.
//!
//! A Neurai asset output extends a standard locking script by appending:
//!
//! ```text
//! <base_script>
//! OP_XNA_ASSET      (0xc0)
//! <varint length>
//! <3 bytes: magic "rvn">     — retained for Ravencoin protocol compatibility
//! <1 byte: type 'q'|'t'|'r'|'o'>
//! <type-specific payload>
//! OP_DROP           (0x75)
//! ```
//!
//! Two base scripts are recognised:
//!
//! | Base                                                        | Prefix length | Marker at byte |
//! |-------------------------------------------------------------|---------------|----------------|
//! | P2PKH  `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`  | 25            | 25             |
//! | OP_1   `OP_1 <32-byte commitment>`                          | 34            | 34             |

use anyhow::{bail, Context, Result};

// ─── on-wire constants ────────────────────────────────────────────────────────

pub const OP_XNA_ASSET: u8 = 0xc0;
pub const OP_DROP: u8 = 0x75;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;

/// ASCII "rvn", retained from Ravencoin for protocol compatibility.
pub const ASSET_MAGIC: [u8; 3] = *b"rvn";

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

/// Markers preceding a 32-byte reference in asset payloads.
const IPFS_MARKER: u8 = 0x12; // IPFS SHA2-256 content hash
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
    pub units: u8,
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

/// Parse an asset output from a raw `script_pubkey`.
///
/// Returns `None` if the script is not a well-formed Neurai asset output; the caller
/// can treat that as a plain non-asset output.
pub fn parse_asset_script(bytes: &[u8]) -> Option<AssetOutput> {
    let asset_start = find_asset_marker(bytes)?;
    if bytes.last().copied() != Some(OP_DROP) {
        return None;
    }

    let mut cursor = &bytes[asset_start + 1..bytes.len() - 1]; // between OP_XNA_ASSET and OP_DROP
    let (payload_len, used) = read_varint(cursor)?;
    cursor = &cursor[used..];
    if cursor.len() != payload_len as usize {
        return None;
    }
    if cursor.len() < 4 || cursor[..3] != ASSET_MAGIC {
        return None;
    }
    let type_byte = cursor[3];
    let payload = &cursor[4..];
    let data = match type_byte {
        TYPE_NEW => AssetData::New(parse_new(payload).ok()?),
        TYPE_TRANSFER => AssetData::Transfer(parse_transfer(payload).ok()?),
        TYPE_REISSUE => AssetData::Reissue(parse_reissue(payload).ok()?),
        TYPE_OWNER => AssetData::Owner(parse_owner(payload).ok()?),
        _ => return None,
    };
    Some(AssetOutput {
        base_script: bytes[..asset_start].to_vec(),
        data,
    })
}

fn find_asset_marker(bytes: &[u8]) -> Option<usize> {
    if bytes.len() >= 27 && is_p2pkh_base(bytes) && bytes[25] == OP_XNA_ASSET {
        return Some(25);
    }
    if bytes.len() >= 36 && is_op1_32_base(bytes) && bytes[34] == OP_XNA_ASSET {
        return Some(34);
    }
    None
}

fn is_p2pkh_base(bytes: &[u8]) -> bool {
    bytes.len() >= 25
        && bytes[0] == 0x76   // OP_DUP
        && bytes[1] == 0xa9   // OP_HASH160
        && bytes[2] == 0x14   // push 20 bytes
        && bytes[23] == 0x88  // OP_EQUALVERIFY
        && bytes[24] == 0xac  // OP_CHECKSIG
}

fn is_op1_32_base(bytes: &[u8]) -> bool {
    bytes.len() >= 34
        && bytes[0] == OP_1
        && bytes[1] == 0x20   // push 32 bytes
}

// ─── unspendable null-asset scripts (OP_XNA_ASSET at front) ───────────────────

/// Address (or AuthScript commitment) being tagged/freed by a null-asset
/// script. Mirrors the daemon's `CTxDestination` minus AuthScript-vs-script-hash
/// disambiguation, which the indexer doesn't need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaggedDestination {
    /// Legacy 20-byte hash (P2PKH key-id or P2SH script-id).
    Legacy([u8; 20]),
    /// NIP-025 AuthScript v1 32-byte commitment.
    AuthScript([u8; 32]),
}

/// Parsed unspendable null-asset metadata script.
///
/// These outputs start with `OP_XNA_ASSET` and carry asset-system metadata
/// (qualifier tagging, restricted-asset freezing, verifier strings). They are
/// unspendable — the daemon treats them as such in `CScript::IsUnspendable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullAssetScript {
    /// Tag/untag a destination with a qualifier, freeze/unfreeze a restricted
    /// asset at a destination, or assign DePIN ownership.
    AddressTag {
        destination: TaggedDestination,
        asset_name: String,
        flag: i8,
    },
    /// Globally freeze/unfreeze a restricted asset.
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

/// Parse a null-asset script. Returns `None` if the script is not a
/// well-formed null-asset script.
///
/// Recognised shapes:
/// ```text
/// AddressTag (legacy):    OP_XNA_ASSET 0x14 <20-byte hash>      <push><asset_name varstr><flag i8>
/// AddressTag (AuthScript): OP_XNA_ASSET OP_1 0x20 <32-byte cmt>  <push><asset_name varstr><flag i8>
/// GlobalRestriction:      OP_XNA_ASSET OP_RESERVED OP_RESERVED  <push><asset_name varstr><flag i8>
/// Verifier:               OP_XNA_ASSET OP_RESERVED              <push><verifier varstr>
/// ```
pub fn parse_null_asset_script(bytes: &[u8]) -> Option<NullAssetScript> {
    if !is_null_asset_script(bytes) {
        return None;
    }

    // Global restriction: OP_XNA_ASSET OP_RESERVED OP_RESERVED <push><data>
    if bytes.len() > 3 && bytes[1] == OP_RESERVED && bytes[2] == OP_RESERVED {
        let inner = read_push(&bytes[3..])?;
        let (asset_name, flag) = read_name_and_flag(inner)?;
        return Some(NullAssetScript::GlobalRestriction { asset_name, flag });
    }

    // Verifier: OP_XNA_ASSET OP_RESERVED <push><data>   (byte 2 must NOT be OP_RESERVED)
    if bytes.len() > 2 && bytes[1] == OP_RESERVED {
        let inner = read_push(&bytes[2..])?;
        let verifier_string = read_varstr(inner)?;
        return Some(NullAssetScript::Verifier { verifier_string });
    }

    // AuthScript address tag: OP_XNA_ASSET OP_1 0x20 <32 bytes> <push><data>
    if bytes.len() > 35 && bytes[1] == OP_1 && bytes[2] == 0x20 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[3..35]);
        let inner = read_push(&bytes[35..])?;
        let (asset_name, flag) = read_name_and_flag(inner)?;
        return Some(NullAssetScript::AddressTag {
            destination: TaggedDestination::AuthScript(hash),
            asset_name,
            flag,
        });
    }

    // Legacy address tag: OP_XNA_ASSET 0x14 <20 bytes> <push><data>
    if bytes.len() > 22 && bytes[1] == 0x14 {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[2..22]);
        let inner = read_push(&bytes[22..])?;
        let (asset_name, flag) = read_name_and_flag(inner)?;
        return Some(NullAssetScript::AddressTag {
            destination: TaggedDestination::Legacy(hash),
            asset_name,
            flag,
        });
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

/// Read a single push opcode (direct-push `0x01..=0x4b` or `OP_PUSHDATA1..4`)
/// and return the pushed bytes.
fn read_push(bytes: &[u8]) -> Option<&[u8]> {
    let op = *bytes.first()?;
    match op {
        1..=0x4b => {
            let n = op as usize;
            let rest = &bytes[1..];
            if rest.len() < n { return None; }
            Some(&rest[..n])
        }
        0x4c => {
            // OP_PUSHDATA1: next 1 byte is length
            let rest = &bytes[1..];
            let n = *rest.first()? as usize;
            let rest = &rest[1..];
            if rest.len() < n { return None; }
            Some(&rest[..n])
        }
        0x4d => {
            // OP_PUSHDATA2: next 2 bytes LE are length
            if bytes.len() < 3 { return None; }
            let n = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            let rest = &bytes[3..];
            if rest.len() < n { return None; }
            Some(&rest[..n])
        }
        _ => None,
    }
}

/// Read a `<varstr asset_name><i8 flag>` blob, exactly as `CNullAssetTxData`
/// serializes itself.
fn read_name_and_flag(mut data: &[u8]) -> Option<(String, i8)> {
    let name = read_string(&mut data).ok()?;
    if data.len() != 1 {
        return None;
    }
    Some((name, data[0] as i8))
}

/// Read just a varstr (compact-size length + UTF-8 bytes), used for the
/// verifier-string null-asset payload.
fn read_varstr(mut data: &[u8]) -> Option<String> {
    let s = read_string(&mut data).ok()?;
    if !data.is_empty() {
        return None;
    }
    Some(s)
}

// ─── type-specific parsers ────────────────────────────────────────────────────

fn parse_new(mut data: &[u8]) -> Result<NewAsset> {
    let name = read_string(&mut data)?;
    let amount = read_i64_le(&mut data)?;
    let units = read_u8(&mut data)?;
    let reissuable = read_u8(&mut data)? != 0;
    let has_ipfs = read_u8(&mut data)? != 0;
    let ipfs = if has_ipfs { Some(read_ipfs(&mut data)?) } else { None };
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
    let message = if data.is_empty() {
        None
    } else {
        let ipfs = read_ipfs(&mut data)?;
        let expire_time = if data.is_empty() {
            None
        } else {
            Some(read_i64_le(&mut data)?)
        };
        Some(AssetMessage { ipfs, expire_time })
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
    let units = read_u8(&mut data)?;
    let reissuable = read_u8(&mut data)? != 0;
    let ipfs = if data.is_empty() {
        None
    } else {
        Some(read_ipfs(&mut data)?)
    };
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

/// Bitcoin CompactSize / varint reader: returns `(value, bytes_consumed)`.
fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    match first {
        0..=0xfc => Some((first as u64, 1)),
        0xfd => {
            if data.len() < 3 {
                return None;
            }
            let v = u16::from_le_bytes([data[1], data[2]]) as u64;
            if v < 0xfd {
                return None; // non-canonical
            }
            Some((v, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return None;
            }
            let v = u32::from_le_bytes(data[1..5].try_into().ok()?) as u64;
            if v < 0x10000 {
                return None;
            }
            Some((v, 5))
        }
        0xff => {
            if data.len() < 9 {
                return None;
            }
            let v = u64::from_le_bytes(data[1..9].try_into().ok()?);
            if v < 0x1_0000_0000 {
                return None;
            }
            Some((v, 9))
        }
    }
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

fn read_ipfs(data: &mut &[u8]) -> Result<IpfsRef> {
    let marker = read_u8(data)?;
    if marker != IPFS_MARKER && marker != TXID_MARKER {
        bail!("unexpected IPFS/TXID marker {marker:#x}");
    }
    let push_len = read_u8(data)?;
    if push_len != 0x20 {
        bail!("expected 0x20 push length, got {push_len:#x}");
    }
    if data.len() < 32 {
        bail!("short IPFS hash");
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&data[..32]);
    *data = &data[32..];
    Ok(IpfsRef { marker, hash })
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
        assert!(payload.len() < 0xfd, "tests stay under the varint single-byte range");
        let mut script = p2pkh_prefix();
        script.push(OP_XNA_ASSET);
        script.push(payload.len() as u8); // 1-byte varint
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

        let out = parse_asset_script(&script).expect("parse");
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

        let out = parse_asset_script(&script).expect("parse");
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

        let out = parse_asset_script(&script).expect("parse");
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

        let out = parse_asset_script(&script).expect("parse");
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

        let out = parse_asset_script(&script).expect("parse");
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

        let out = parse_asset_script(&script).expect("parse");
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

        let out = parse_asset_script(&script).expect("parse");
        assert_eq!(out.base_script, op1_32_prefix());
        match out.data {
            AssetData::Transfer(t) => assert_eq!(t.name, "NEU"),
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn plain_p2pkh_is_not_an_asset() {
        let script = p2pkh_prefix();
        assert!(parse_asset_script(&script).is_none());
    }

    #[test]
    fn missing_op_drop_rejected() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"TEST");
        body.extend_from_slice(&1i64.to_le_bytes());
        let mut script = wrap_p2pkh(TYPE_TRANSFER, &body);
        *script.last_mut().unwrap() = 0x00; // clobber OP_DROP
        assert!(parse_asset_script(&script).is_none());
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
        assert!(parse_asset_script(&script).is_none());
    }

    #[test]
    fn unknown_type_byte_rejected() {
        let mut body = Vec::new();
        body.push(4u8);
        body.extend_from_slice(b"TEST");
        body.extend_from_slice(&1i64.to_le_bytes());
        let script = wrap_p2pkh(b'z', &body); // 'z' is not a known type
        assert!(parse_asset_script(&script).is_none());
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

        let parsed = parse_null_asset_script(&script).expect("parse");
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

        let parsed = parse_null_asset_script(&script).expect("parse");
        match parsed {
            NullAssetScript::AddressTag {
                destination: TaggedDestination::AuthScript(c),
                asset_name,
                flag,
            } => {
                assert_eq!(c, commitment);
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

        let parsed = parse_null_asset_script(&script).expect("parse");
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

        let parsed = parse_null_asset_script(&script).expect("parse");
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
            parse_null_asset_script(&script),
            Some(NullAssetScript::GlobalRestriction { .. })
        ));

        // One OP_RESERVED then a push → Verifier
        let inner = varstr("verifier");
        let mut script = vec![OP_XNA_ASSET, OP_RESERVED];
        script.extend_from_slice(&push_blob(&inner));
        assert!(matches!(
            parse_null_asset_script(&script),
            Some(NullAssetScript::Verifier { .. })
        ));
    }

    #[test]
    fn non_xna_script_not_null_asset() {
        // P2PKH script must not be confused with a null-asset.
        assert!(parse_null_asset_script(&p2pkh_prefix()).is_none());
    }

    #[test]
    fn null_asset_with_trailing_garbage_rejected() {
        // Extra byte after `flag` must be rejected — read_name_and_flag enforces
        // that the inner blob ends after the flag byte.
        let hash = [0u8; 20];
        let mut inner = varstr("#X");
        inner.push(1u8);
        inner.push(0xff); // garbage
        let mut script = vec![OP_XNA_ASSET, 0x14];
        script.extend_from_slice(&hash);
        script.extend_from_slice(&push_blob(&inner));
        assert!(parse_null_asset_script(&script).is_none());
    }
}
