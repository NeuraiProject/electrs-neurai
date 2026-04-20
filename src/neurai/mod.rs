//! Neurai-specific types and constants.
//!
//! `rust-bitcoin` is kept for transaction/script parsing (bitcoin-compatible at the byte level),
//! but block headers and chain parameters differ from Bitcoin and live here.

pub mod address;
pub mod asset;
pub mod block;
pub mod network;

#[allow(unused_imports)]
pub use block::{BlockHashAlgo, NeuraiBlockHeader};
pub use network::{NeuraiNetwork, NetworkParams};
