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

/// ASCII "rvn", retained from Ravencoin for protocol compatibility.
pub const ASSET_MAGIC: [u8; 3] = *b"rvn";

pub const TYPE_NEW: u8 = b'q'; // 0x71 — new asset issuance
pub const TYPE_TRANSFER: u8 = b't'; // 0x74 — asset transfer
pub const TYPE_REISSUE: u8 = b'r'; // 0x72 — reissue
pub const TYPE_OWNER: u8 = b'o'; // 0x6f — owner (!-suffix) asset

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
        && bytes[0] == 0x51   // OP_1
        && bytes[1] == 0x20   // push 32 bytes
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
}
