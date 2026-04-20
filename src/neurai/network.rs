//! Neurai network identifiers and per-network parameters.
//!
//! All constants are mirrored from `src/chainparams.cpp` of the Neurai daemon.

use bitcoin::p2p::Magic;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use super::block::BlockHashAlgo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Deserialize)]
pub enum NeuraiNetwork {
    Mainnet,
    Testnet,
    Regtest,
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
            other => Err(format!(
                "unknown network '{other}' (expected 'neurai', 'testnet' or 'regtest')"
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
}

impl NetworkParams {
    pub fn for_network(network: NeuraiNetwork) -> &'static NetworkParams {
        match network {
            NeuraiNetwork::Mainnet => LazyLock::force(&MAINNET),
            NeuraiNetwork::Testnet => LazyLock::force(&TESTNET),
            NeuraiNetwork::Regtest => LazyLock::force(&REGTEST),
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
    daemon_dir_subdir: Some("testnet"),
    db_subdir: "testnet",
    // Testnet genesis is epoch-dependent and auto-mined at daemon start; hash is obtained
    // via RPC (`getblockhash 0`) on first run, so we leave it as zeros here and fill it in
    // at runtime.
    genesis_hash_le: [0u8; 32],
    genesis_time: 1774828800,
    genesis_bits: 0x1e00ffff,
    genesis_nonce: 0,
    genesis_version: 2,
    genesis_merkle_root_le: hex_be_to_le(&MERKLE_ROOT_BE),
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
    daemon_dir_subdir: Some("regtest"),
    db_subdir: "regtest",
    // Regtest genesis is auto-mined; filled in at runtime via RPC.
    genesis_hash_le: [0u8; 32],
    genesis_time: 1681720840,
    genesis_bits: 0x207fffff,
    genesis_nonce: 0,
    genesis_version: 2,
    genesis_merkle_root_le: hex_be_to_le(&MERKLE_ROOT_BE),
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
