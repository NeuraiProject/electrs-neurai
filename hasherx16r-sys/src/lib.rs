//! X16R / X16Rv2 hashing of Neurai block headers (pre-KAWPOW), as in
//! Neurai v1.0.7 `src/hash.h`. The previous block hash (bytes 4..36 of the
//! header) selects the hash functions; the result is in internal byte order.

use std::os::raw::c_uchar;

extern "C" {
    fn neurai_x16r(input: *const c_uchar, len: usize, prev: *const c_uchar, out: *mut c_uchar);
    fn neurai_x16rv2(input: *const c_uchar, len: usize, prev: *const c_uchar, out: *mut c_uchar);
}

fn prev_hash(header: &[u8; 80]) -> [u8; 32] {
    header[4..36].try_into().expect("32 bytes")
}

/// `HashX16R` of an 80-byte header.
pub fn x16r(header: &[u8; 80]) -> [u8; 32] {
    let prev = prev_hash(header);
    let mut out = [0u8; 32];
    unsafe {
        neurai_x16r(
            header.as_ptr(),
            header.len(),
            prev.as_ptr(),
            out.as_mut_ptr(),
        )
    };
    out
}

/// `HashX16RV2` of an 80-byte header.
pub fn x16rv2(header: &[u8; 80]) -> [u8; 32] {
    let prev = prev_hash(header);
    let mut out = [0u8; 32];
    unsafe {
        neurai_x16rv2(
            header.as_ptr(),
            header.len(),
            prev.as_ptr(),
            out.as_mut_ptr(),
        )
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(hex: &str) -> [u8; 80] {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn display(hash: [u8; 32]) -> String {
        hash.iter().rev().map(|b| format!("{:02x}", b)).collect()
    }

    /// Mainnet genesis: `consensus.hashGenesisBlock = genesis.GetX16RHash()`.
    #[test]
    fn mainnet_genesis_x16r() {
        let h = header("04000000000000000000000000000000000000000000000000000000000000000000000051595fe1fb519173c0bd75904e460872585a1d38579788d183cd60d993bf284b08063d64ffff001e92cf6c00");
        assert_eq!(
            display(x16r(&h)),
            "00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806"
        );
    }

    /// Regtest (v1.0.7) blocks are hashed with X16Rv2.
    #[test]
    fn regtest_block_x16rv2() {
        let h = header("00000020825f65d3f86857ec41b843f6b93147ffe3b4367633802700eb259e422df9f964768c85663d214d91ab78953ccba082cfc39755119444feeaf73a2e4a248403b6299bf86affff7f2000000000");
        assert_eq!(
            display(x16rv2(&h)),
            "707530977bb92d6bf7c01dfa218ceb88b7b597b5bc61b9bbd09ef60b44957ef6"
        );
        let h = header("00040030d1cfdce49b82649aa6df7acb461f2a01f2baf91c268d389c8eb8c1eb1b8b5a032a38d0f86e42574baf35635b8f07414abee5795fe4c463668865cdbad162dbb52ba0f86affff7f2003000000");
        assert_eq!(
            display(x16rv2(&h)),
            "18c6ce11c89a6b132e1f51bca36e317a5d03a1b65e3257595419492e4c036c0c"
        );
    }
}
