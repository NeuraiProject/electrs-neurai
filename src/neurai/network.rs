//! Neurai network identifiers and per-network parameters.
//!
//! All constants are mirrored from `src/chainparams.cpp` of the Neurai daemon.

use bitcoin::p2p::Magic;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use super::anchors;
use super::block::BlockHashAlgo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum NeuraiNetwork {
    Mainnet,
    Testnet,
    Regtest,
    /// Regtest of the Neurai v1.0.7 mainnet release (X16Rv2 headers), used to
    /// test against the same consensus/asset code as mainnet. `regtest` is the
    /// DePIN-Test regtest.
    RegtestV1,
}

impl Default for NeuraiNetwork {
    fn default() -> Self {
        NeuraiNetwork::Mainnet
    }
}

impl fmt::Display for NeuraiNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NeuraiNetwork::Mainnet => "neurai",
            NeuraiNetwork::Testnet => "testnet",
            NeuraiNetwork::Regtest => "regtest",
            NeuraiNetwork::RegtestV1 => "regtest-v1",
        })
    }
}

impl FromStr for NeuraiNetwork {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "neurai" | "mainnet" | "main" => Ok(NeuraiNetwork::Mainnet),
            "testnet" | "test" => Ok(NeuraiNetwork::Testnet),
            "regtest" => Ok(NeuraiNetwork::Regtest),
            "regtest-v1" => Ok(NeuraiNetwork::RegtestV1),
            other => Err(format!(
                "unknown network '{other}' (expected 'neurai', 'testnet', 'regtest' or 'regtest-v1')"
            )),
        }
    }
}

/// Frozen per-network constants.
pub struct NetworkParams {
    pub network: NeuraiNetwork,
    pub magic: Magic,
    pub default_p2p_port: u16,
    pub default_rpc_port: u16,
    pub default_electrum_port: u16,
    pub default_monitoring_port: u16,
    pub pkh_prefix: u8,
    pub sh_prefix: u8,
    pub bech32_hrp: &'static str,
    pub kawpow_activation_time: u32,
    pub block_hash_algo: BlockHashAlgo,
    pub pq_witness_enabled: bool,
    pub asset_activation_height: u32,
    /// Height at which DePIN / Soulbound (`&`-prefixed) asset names become
    /// valid. Mirrors the daemon's network-gated DEPIN feature.
    ///
    /// * `Some(h)` — activates at height `h` (`Some(0)` = active from genesis).
    /// * `None`    — not scheduled; treat `&`-names as invalid.
    ///
    /// Mainnet stays `None` until a fork height is announced.
    pub depin_assets_activation_height: Option<u32>,
    pub daemon_dir_subdir: Option<&'static str>,
    pub db_subdir: &'static str,
    /// Known block hash (raw, little-endian internal byte order) of the genesis block.
    /// Used to bootstrap the chain without having to run the native hashing algorithm.
    pub genesis_hash_le: [u8; 32],
    pub genesis_time: u32,
    pub genesis_bits: u32,
    pub genesis_nonce: u32,
    pub genesis_version: i32,
    pub genesis_merkle_root_le: [u8; 32],
    /// Block hashes every [`anchors::INTERVAL`] blocks that authenticate the headers
    /// up to them, so their KAWPOW is not recomputed (see [`anchors`]).
    pub header_anchors: &'static [&'static str],
    /// Height from which the unified fork's script rules apply (Neurai 2.0,
    /// `nStrictAuthScriptHeight`): the "xna" asset marker, AuthScript asset and
    /// tag forms, P2PKH-only classic asset prefix and 121-byte asset names.
    /// `None`: not scheduled (mainnet so far, the v1.0.7 regtest).
    pub unified_fork_height: Option<u32>,
}

impl NetworkParams {
    /// Whether the unified fork's rules apply to a block at `height`.
    pub fn fork_active(&self, height: usize) -> bool {
        self.unified_fork_height
            .is_some_and(|fork| height as u64 >= u64::from(fork))
    }

    /// Longest asset name the Electrum RPCs accept: ElectrumX's 32 characters,
    /// or the daemon's 121 bytes where the unified fork is scheduled.
    pub fn max_asset_name_len(&self) -> usize {
        if self.unified_fork_height.is_some() {
            121
        } else {
            32
        }
    }

    pub fn for_network(network: NeuraiNetwork) -> &'static NetworkParams {
        match network {
            NeuraiNetwork::Mainnet => LazyLock::force(&MAINNET),
            NeuraiNetwork::Testnet => LazyLock::force(&TESTNET),
            NeuraiNetwork::Regtest => LazyLock::force(&REGTEST),
            NeuraiNetwork::RegtestV1 => LazyLock::force(&REGTEST_V1),
        }
    }
}

impl fmt::Debug for NetworkParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkParams")
            .field("network", &self.network)
            .field("magic", &self.magic)
            .field("p2p_port", &self.default_p2p_port)
            .field("electrum_port", &self.default_electrum_port)
            .field("bech32_hrp", &self.bech32_hrp)
            .finish()
    }
}

/// Display byte order (big-endian) hash → little-endian internal byte order used by consensus.
const fn hex_be_to_le(hex: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(hex[i * 2]);
        let lo = hex_nibble(hex[i * 2 + 1]);
        // consensus stores hashes in reversed byte order relative to display
        out[31 - i] = (hi << 4) | lo;
        i += 1;
    }
    out
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex nibble"),
    }
}

const MERKLE_ROOT_BE: [u8; 64] =
    *b"4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951";

static MAINNET: LazyLock<NetworkParams> = LazyLock::new(|| NetworkParams {
    network: NeuraiNetwork::Mainnet,
    // pchMessageStart = { 0x4e, 0x45, 0x55, 0x52 } → ASCII "NEUR"
    magic: Magic::from_bytes([0x4e, 0x45, 0x55, 0x52]),
    default_p2p_port: 19000,
    default_rpc_port: 19001,
    default_electrum_port: 50001,
    default_monitoring_port: 4224,
    pkh_prefix: 53,   // 'N'
    sh_prefix: 117,
    bech32_hrp: "nq",
    // nKAWPOW = nGenesisTime + 1 = 1681720841
    kawpow_activation_time: 1681720841,
    block_hash_algo: BlockHashAlgo::X16rThenKawpow,
    pq_witness_enabled: false,
    asset_activation_height: 10,
    // Mainnet fork height for DePIN assets not announced yet — keep disabled.
    depin_assets_activation_height: None,
    daemon_dir_subdir: None,
    db_subdir: "neurai",
    genesis_hash_le: hex_be_to_le(
        b"00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806",
    ),
    genesis_time: 1681720840,
    genesis_bits: 0x1e00ffff,
    genesis_nonce: 7131026,
    genesis_version: 4,
    genesis_merkle_root_le: hex_be_to_le(&MERKLE_ROOT_BE),
    header_anchors: anchors::MAINNET,
    // MAINNET_FORK_HEIGHT in Neurai 2.0 is not set yet.
    unified_fork_height: None,
});

static TESTNET: LazyLock<NetworkParams> = LazyLock::new(|| NetworkParams {
    network: NeuraiNetwork::Testnet,
    // pchMessageStart = { 0x52, 0x55, 0x45, 0x4e } → "RUEN"
    magic: Magic::from_bytes([0x52, 0x55, 0x45, 0x4e]),
    default_p2p_port: 19100,
    default_rpc_port: 19101,
    default_electrum_port: 60001,
    default_monitoring_port: 14224,
    pkh_prefix: 127,  // 't'
    sh_prefix: 196,
    bech32_hrp: "tnq",
    kawpow_activation_time: 0xFFFFFFFF, // KAWPOW disabled → SHA256d headers
    block_hash_algo: BlockHashAlgo::Sha256d,
    pq_witness_enabled: true,
    asset_activation_height: 1,
    depin_assets_activation_height: Some(0),
    daemon_dir_subdir: Some("testnet"),
    db_subdir: "testnet",
    // The genesis hash and header are taken from the daemon at startup
    // (`Daemon::get_genesis`), so a testnet reset needs no new build. These
    // fields describe the current testnet genesis (DePIN-Test, 2026-11-05).
    genesis_hash_le: [0u8; 32],
    genesis_time: 1793836800,
    genesis_bits: 0x1e00ffff,
    genesis_nonce: 2915850,
    genesis_version: 2,
    genesis_merkle_root_le: hex_be_to_le(&MERKLE_ROOT_BE),
    header_anchors: &[],
    // TESTNET_FEATURES_HEIGHT
    unified_fork_height: Some(10),
});

static REGTEST: LazyLock<NetworkParams> = LazyLock::new(|| NetworkParams {
    network: NeuraiNetwork::Regtest,
    magic: Magic::from_bytes([0x52, 0x55, 0x45, 0x4e]),
    default_p2p_port: 19200,
    default_rpc_port: 19201,
    default_electrum_port: 60401,
    default_monitoring_port: 24224,
    pkh_prefix: 127,
    sh_prefix: 196,
    bech32_hrp: "rnq",
    kawpow_activation_time: 0xFFFFFFFF,
    block_hash_algo: BlockHashAlgo::Sha256d,
    pq_witness_enabled: true,
    asset_activation_height: 1,
    depin_assets_activation_height: Some(0),
    daemon_dir_subdir: Some("regtest"),
    db_subdir: "regtest",
    // Regtest genesis is auto-mined; filled in at runtime via RPC.
    genesis_hash_le: [0u8; 32],
    genesis_time: 1681720840,
    genesis_bits: 0x207fffff,
    genesis_nonce: 0,
    genesis_version: 2,
    genesis_merkle_root_le: hex_be_to_le(&MERKLE_ROOT_BE),
    header_anchors: &[],
    // nStrictAuthScriptHeight = 0 (-strictauthscriptheight moves it)
    unified_fork_height: Some(0),
});

/// Neurai v1.0.7 regtest (`CRegTestParams` of the `main` branch).
static REGTEST_V1: LazyLock<NetworkParams> = LazyLock::new(|| NetworkParams {
    network: NeuraiNetwork::RegtestV1,
    magic: Magic::from_bytes([0x52, 0x55, 0x45, 0x4e]),
    default_p2p_port: 19200,
    default_rpc_port: 19201,
    default_electrum_port: 60411,
    default_monitoring_port: 24234,
    pkh_prefix: 127,
    sh_prefix: 196,
    bech32_hrp: "rnq",
    // nKAWPOWActivationTime = 3582830167 (2083): 80-byte X16Rv2 headers
    kawpow_activation_time: 3_582_830_167,
    block_hash_algo: BlockHashAlgo::X16rv2ThenKawpow,
    pq_witness_enabled: false,
    asset_activation_height: 0,
    depin_assets_activation_height: None,
    daemon_dir_subdir: Some("regtest"),
    db_subdir: "regtest-v1",
    // genesis 6d7844e7…fa2e4 is X16R (not X16Rv2): fetched from the daemon
    genesis_hash_le: [0u8; 32],
    genesis_time: 1681720840,
    genesis_bits: 0x207fffff,
    genesis_nonce: 1,
    genesis_version: 4,
    genesis_merkle_root_le: hex_be_to_le(&MERKLE_ROOT_BE),
    header_anchors: &[],
    unified_fork_height: None,
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_magic_bytes_are_neur() {
        assert_eq!(MAINNET.magic.to_bytes(), [b'N', b'E', b'U', b'R']);
    }

    #[test]
    fn mainnet_genesis_hash_is_correct() {
        let display = hex_le_to_display(&MAINNET.genesis_hash_le);
        assert_eq!(
            display,
            "00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806"
        );
    }

    #[test]
    fn network_round_trips_through_string() {
        for n in [
            NeuraiNetwork::Mainnet,
            NeuraiNetwork::Testnet,
            NeuraiNetwork::Regtest,
            NeuraiNetwork::RegtestV1,
        ] {
            assert_eq!(NeuraiNetwork::from_str(&n.to_string()).unwrap(), n);
        }
    }

    fn hex_le_to_display(le: &[u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for b in le.iter().rev() {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }
}
