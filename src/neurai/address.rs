//! Neurai address encoding and decoding.
//!
//! Supports:
//! - Legacy P2PKH:  base58check, version byte from `NetworkParams::pkh_prefix`
//!                  (mainnet: 53 → 'N', testnet/regtest: 127 → 't')
//! - Legacy P2SH:   base58check, version byte from `NetworkParams::sh_prefix`
//! - SegWit v0:     bech32  with HRP from `NetworkParams::bech32_hrp` (P2WPKH, P2WSH)
//! - SegWit v1+:    bech32m with HRP from `NetworkParams::bech32_hrp` (P2TR, future PQ witness)

use anyhow::{bail, Result};
use bech32::{segwit, Fe32, Hrp};
use bitcoin::{
    hashes::{sha256d, Hash},
    PubkeyHash, ScriptBuf, WPubkeyHash, WScriptHash,
};

use super::NetworkParams;

// Alias bitcoin's ScriptHash to avoid ambiguity with crate::types::ScriptHash.
use bitcoin::ScriptHash as BitcoinScriptHash;

const LEGACY_PAYLOAD_LEN: usize = 21; // 1-byte version + 20-byte hash160
const CHECKSUM_LEN: usize = 4;
const LEGACY_ENCODED_LEN: usize = LEGACY_PAYLOAD_LEN + CHECKSUM_LEN;

// ─── base58check primitives ───────────────────────────────────────────────────

/// Encode `(version, hash160)` as a base58check string.
pub fn base58check_encode(version: u8, hash160: &[u8; 20]) -> String {
    let mut buf = [0u8; LEGACY_ENCODED_LEN];
    buf[0] = version;
    buf[1..21].copy_from_slice(hash160);
    let checksum = sha256d::Hash::hash(&buf[..LEGACY_PAYLOAD_LEN]);
    buf[21..25].copy_from_slice(&checksum.as_byte_array()[..CHECKSUM_LEN]);
    bitcoin::base58::encode(&buf)
}

/// Decode a base58check string into `(version, hash160)`.
pub fn base58check_decode(addr: &str) -> Result<(u8, [u8; 20])> {
    let raw = bitcoin::base58::decode(addr).map_err(|e| anyhow::anyhow!("{e}"))?;
    if raw.len() != LEGACY_ENCODED_LEN {
        bail!("expected {} bytes, got {}", LEGACY_ENCODED_LEN, raw.len());
    }
    let checksum = sha256d::Hash::hash(&raw[..LEGACY_PAYLOAD_LEN]);
    if raw[LEGACY_PAYLOAD_LEN..] != checksum.as_byte_array()[..CHECKSUM_LEN] {
        bail!("invalid base58check checksum");
    }
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&raw[1..21]);
    Ok((raw[0], hash))
}

// ─── high-level API ───────────────────────────────────────────────────────────

fn hrp(params: &NetworkParams) -> Hrp {
    Hrp::parse(params.bech32_hrp).expect("static HRP is valid")
}

/// Inspect a raw script and, if it is a well-formed segwit witness program,
/// return `(witness_version 0..=16, program_bytes)`.
///
/// Layout accepted:
///   `<OP_0|OP_1..=OP_16> <push_len 2..=40> <program>`   (length 4..=42 bytes)
fn parse_witness_program(bytes: &[u8]) -> Option<(u8, &[u8])> {
    if bytes.len() < 4 || bytes.len() > 42 {
        return None;
    }
    let version = match bytes[0] {
        0x00 => 0,
        v @ 0x51..=0x60 => v - 0x50,
        _ => return None,
    };
    let push_len = bytes[1] as usize;
    if push_len != bytes.len() - 2 || push_len < 2 || push_len > 40 {
        return None;
    }
    // v0 may only be 20 (P2WPKH) or 32 (P2WSH) — the canonical consensus rule.
    if version == 0 && push_len != 20 && push_len != 32 {
        return None;
    }
    Some((version, &bytes[2..]))
}

/// Convert a `script_pubkey` to a Neurai address string.
///
/// Returns `None` for script types that have no standard address representation.
pub fn script_to_address(script: &bitcoin::Script, params: &NetworkParams) -> Option<String> {
    let bytes = script.as_bytes();

    // P2PKH  → OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG  (25 bytes)
    if script.is_p2pkh() {
        let mut h = [0u8; 20];
        h.copy_from_slice(&bytes[3..23]);
        return Some(base58check_encode(params.pkh_prefix, &h));
    }
    // P2SH   → OP_HASH160 <20> OP_EQUAL  (23 bytes)
    if script.is_p2sh() {
        let mut h = [0u8; 20];
        h.copy_from_slice(&bytes[2..22]);
        return Some(base58check_encode(params.sh_prefix, &h));
    }
    // Any witness version 0..=16. `segwit::encode` picks the correct variant
    // (bech32 for v0, bech32m for v1+).
    if let Some((version, program)) = parse_witness_program(bytes) {
        let fe32 = Fe32::try_from(version).expect("witness version in 0..=16");
        return segwit::encode(hrp(params), fe32, program).ok();
    }
    None
}

/// Parse a Neurai address string and return the corresponding `ScriptBuf`.
pub fn address_to_script(addr: &str, params: &NetworkParams) -> Result<ScriptBuf> {
    let expected_hrp = params.bech32_hrp;
    let lower = addr.to_lowercase();
    // Bech32/bech32m: HRP followed immediately by the separator '1'.
    let is_bech32 = lower.starts_with(expected_hrp)
        && lower.as_bytes().get(expected_hrp.len()) == Some(&b'1');
    if is_bech32 {
        let (got_hrp, version, program) =
            segwit::decode(addr).map_err(|e| anyhow::anyhow!("bech32 decode: {e}"))?;
        let expected = hrp(params);
        if got_hrp != expected {
            bail!("wrong bech32 HRP: expected {expected_hrp}, got {got_hrp}");
        }
        return witness_to_script(version, &program);
    }

    // Legacy base58check
    let (version, hash160) = base58check_decode(addr)?;
    if version == params.pkh_prefix {
        return Ok(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash160)));
    }
    if version == params.sh_prefix {
        return Ok(ScriptBuf::new_p2sh(&BitcoinScriptHash::from_byte_array(hash160)));
    }
    bail!(
        "address version byte {version} does not match network \
         (pkh={}, sh={})",
        params.pkh_prefix,
        params.sh_prefix,
    )
}

fn witness_to_script(version: Fe32, program: &[u8]) -> Result<ScriptBuf> {
    let v = version.to_u8();
    if v > 16 {
        bail!("invalid witness version {v}");
    }
    if program.len() < 2 || program.len() > 40 {
        bail!("invalid witness program length: {}", program.len());
    }
    if v == 0 {
        // v0 uses the canonical `bitcoin` crate helpers so the resulting script
        // is byte-identical to what miners produce.
        return match program.len() {
            20 => Ok(ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
                program.try_into().expect("20-byte program"),
            ))),
            32 => Ok(ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(
                program.try_into().expect("32-byte program"),
            ))),
            n => bail!("invalid v0 witness program length: {n}"),
        };
    }
    // v1..=v16: `OP_1..OP_16 <push_len> <program>`. This covers P2TR (v1) and
    // any future witness version (e.g. post-quantum signature schemes).
    let mut raw = Vec::with_capacity(2 + program.len());
    raw.push(0x50 + v); // OP_1 .. OP_16
    raw.push(program.len() as u8);
    raw.extend_from_slice(program);
    Ok(ScriptBuf::from_bytes(raw))
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neurai::{NeuraiNetwork, NetworkParams};
    use bitcoin::hashes::Hash;

    fn mainnet() -> &'static NetworkParams {
        NetworkParams::for_network(NeuraiNetwork::Mainnet)
    }

    fn testnet() -> &'static NetworkParams {
        NetworkParams::for_network(NeuraiNetwork::Testnet)
    }

    /// Roundtrip: encode then decode → same version + hash.
    #[test]
    fn base58check_roundtrip() {
        let hash = [0xABu8; 20];
        let encoded = base58check_encode(53, &hash);
        let (version, decoded) = base58check_decode(&encoded).unwrap();
        assert_eq!(version, 53);
        assert_eq!(decoded, hash);
    }

    /// Corrupt checksum → error.
    #[test]
    fn base58check_bad_checksum() {
        let hash = [0x01u8; 20];
        let mut encoded = base58check_encode(53, &hash).into_bytes();
        // flip the last character
        let last = encoded.last_mut().unwrap();
        *last ^= 1;
        let corrupted = String::from_utf8(encoded).unwrap();
        assert!(base58check_decode(&corrupted).is_err());
    }

    /// P2PKH roundtrip on mainnet (prefix 53 → 'N').
    #[test]
    fn p2pkh_mainnet_roundtrip() {
        let params = mainnet();
        let hash = [0x42u8; 20];
        let script = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash));
        let addr = script_to_address(&script, params).expect("P2PKH should encode");
        assert!(addr.starts_with('N'), "mainnet P2PKH starts with 'N', got {addr}");
        let decoded_script = address_to_script(&addr, params).expect("should decode");
        assert_eq!(script, decoded_script);
    }

    /// P2PKH roundtrip on testnet (prefix 127 → 't' or 'm').
    #[test]
    fn p2pkh_testnet_roundtrip() {
        let params = testnet();
        let hash = [0x11u8; 20];
        let script = ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash));
        let addr = script_to_address(&script, params).expect("P2PKH should encode");
        let decoded = address_to_script(&addr, params).expect("should decode");
        assert_eq!(script, decoded);
    }

    /// P2SH roundtrip on mainnet.
    #[test]
    fn p2sh_mainnet_roundtrip() {
        let params = mainnet();
        let hash = [0x55u8; 20];
        let script = ScriptBuf::new_p2sh(&BitcoinScriptHash::from_byte_array(hash));
        let addr = script_to_address(&script, params).expect("P2SH should encode");
        let decoded = address_to_script(&addr, params).expect("should decode");
        assert_eq!(script, decoded);
    }

    /// P2WPKH (bech32 nq1…) roundtrip on mainnet.
    #[test]
    fn p2wpkh_mainnet_roundtrip() {
        let params = mainnet();
        let hash = [0x99u8; 20];
        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash));
        let addr = script_to_address(&script, params).expect("P2WPKH should encode");
        assert!(addr.starts_with("nq1"), "mainnet bech32 starts with 'nq1', got {addr}");
        let decoded = address_to_script(&addr, params).expect("should decode");
        assert_eq!(script, decoded);
    }

    /// P2WSH (bech32 nq1…) roundtrip on mainnet.
    #[test]
    fn p2wsh_mainnet_roundtrip() {
        let params = mainnet();
        let hash = [0xCCu8; 32];
        let script = ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(hash));
        let addr = script_to_address(&script, params).expect("P2WSH should encode");
        let decoded = address_to_script(&addr, params).expect("should decode");
        assert_eq!(script, decoded);
    }

    /// P2WPKH (bech32 tnq1…) roundtrip on testnet.
    #[test]
    fn p2wpkh_testnet_roundtrip() {
        let params = testnet();
        let hash = [0x77u8; 20];
        let script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(hash));
        let addr = script_to_address(&script, params).expect("P2WPKH testnet should encode");
        assert!(addr.starts_with("tnq1"), "testnet bech32 starts with 'tnq1', got {addr}");
        let decoded = address_to_script(&addr, params).expect("should decode");
        assert_eq!(script, decoded);
    }

    /// Witness v2+ (future / PQ) round-trip: `OP_N <push> <program>`.
    #[test]
    fn witness_v2_and_higher_roundtrip() {
        let params = mainnet();
        for version in 2u8..=16 {
            let program = vec![0x55u8; 32];
            let mut raw = Vec::with_capacity(2 + program.len());
            raw.push(0x50 + version); // OP_N
            raw.push(program.len() as u8);
            raw.extend_from_slice(&program);
            let script = ScriptBuf::from_bytes(raw);

            let addr = script_to_address(&script, params)
                .unwrap_or_else(|| panic!("v{version} should encode"));
            assert!(
                addr.starts_with("nq1"),
                "v{version} address should use the nq HRP (got {addr})"
            );
            let decoded = address_to_script(&addr, params)
                .unwrap_or_else(|e| panic!("v{version} should decode: {e}"));
            assert_eq!(script, decoded, "round-trip failed for v{version}");
        }
    }

    /// Variable-length witness programs (2..=40 bytes) on v1+.
    #[test]
    fn witness_v1_variable_length() {
        let params = mainnet();
        for len in [2usize, 20, 32, 40] {
            let program = vec![0xABu8; len];
            let mut raw = Vec::with_capacity(2 + len);
            raw.push(0x51); // OP_1
            raw.push(len as u8);
            raw.extend_from_slice(&program);
            let script = ScriptBuf::from_bytes(raw);

            let addr = script_to_address(&script, params)
                .unwrap_or_else(|| panic!("len={len} should encode"));
            let decoded = address_to_script(&addr, params)
                .unwrap_or_else(|e| panic!("len={len} should decode: {e}"));
            assert_eq!(script, decoded);
        }
    }

    /// Wrong-network prefix → error on decode.
    #[test]
    fn wrong_network_prefix_error() {
        let mainnet_params = mainnet();
        let testnet_params = testnet();
        let hash = [0x01u8; 20];
        // Encode on mainnet, try to decode on testnet
        let mainnet_addr = base58check_encode(mainnet_params.pkh_prefix, &hash);
        let err = address_to_script(&mainnet_addr, testnet_params);
        assert!(err.is_err(), "wrong-network address should fail");
    }
}
