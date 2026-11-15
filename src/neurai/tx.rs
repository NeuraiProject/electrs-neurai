//! Neurai transactions, read in place from block or mempool bytes.
//!
//! Neurai serializes transactions like Bitcoin, plus NIP-014 reference inputs
//! (Neurai 2.0 / DePIN-Test): bit 2 of the extended format's flags announces a
//! list of outpoints between the outputs and the witnesses.
//!
//! ```text
//! version | [00 flags] | vin | vout | [vrefin if flags & 2] | [witnesses if flags & 1] | locktime
//! ```
//!
//! Unlike witnesses, reference inputs are part of the txid: it hashes
//! `version | 00 02 | vin | vout | vrefin | locktime` when they are present, and
//! `version | vin | vout | locktime` otherwise. `bitcoin_slices` and
//! rust-bitcoin only know the witness flag, hence this parser
//! (`UnserializeTransaction` in Neurai's `primitives/transaction.h`).

use std::ops::ControlFlow;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    absolute::LockTime,
    hashes::{sha256d, Hash, HashEngine},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness,
};

use crate::neurai::block::header_len;
use crate::neurai::NetworkParams;

const FLAG_WITNESS: u8 = 1;
const FLAG_REF_INPUTS: u8 = 2;
/// `MAX_SIZE` of Bitcoin's `ReadCompactSize`.
const MAX_SIZE: u64 = 0x0200_0000;

/// A transaction of a block or of the mempool, with its txid.
pub(crate) struct Transaction<'a> {
    bytes: &'a [u8],
    txid: Txid,
}

impl<'a> Transaction<'a> {
    pub(crate) fn txid(&self) -> Txid {
        self.txid
    }

    /// The transaction as serialized in the block (with its witnesses).
    pub(crate) fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

pub(crate) struct TxIn<'a> {
    prevout: OutPoint,
    script_sig: &'a [u8],
    sequence: u32,
}

impl TxIn<'_> {
    pub(crate) fn prevout(&self) -> OutPoint {
        self.prevout
    }
}

pub(crate) struct TxOut<'a> {
    value: u64,
    script_pubkey: &'a [u8],
}

impl<'a> TxOut<'a> {
    pub(crate) fn value(&self) -> u64 {
        self.value
    }

    pub(crate) fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }
}

/// Callbacks of [`visit_block`], in `bitcoin_slices`' order: every input, then
/// every output, then the transaction itself (its txid needs all of it).
pub(crate) trait Visitor {
    fn visit_tx_in(&mut self, _vin: usize, _tx_in: &TxIn) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
    fn visit_tx_out(&mut self, _vout: usize, _tx_out: &TxOut) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
    fn visit_transaction(&mut self, _tx: &Transaction) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
}

/// Visit the transactions of a serialized block (header included). Returns
/// `ControlFlow::Break` if the visitor stopped early.
pub(crate) fn visit_block(
    block: &[u8],
    params: &NetworkParams,
    visitor: &mut impl Visitor,
) -> Result<ControlFlow<()>> {
    let header = header_len(block, params).context("block too short for its header")?;
    let mut reader = Reader::new(&block[header..]);
    let count = reader.compact_size()?;
    for _ in 0..count {
        if visit_tx(&mut reader, visitor)?.is_break() {
            return Ok(ControlFlow::Break(()));
        }
    }
    ensure!(
        reader.is_empty(),
        "{} trailing bytes after the transactions",
        reader.remaining()
    );
    Ok(ControlFlow::Continue(()))
}

/// A transaction decoded into rust-bitcoin types, for the code that needs
/// them (mempool). rust-bitcoin has no reference inputs: they are kept apart.
pub(crate) struct DecodedTransaction {
    pub tx: bitcoin::Transaction,
    pub txid: Txid,
    #[allow(dead_code)]
    pub ref_inputs: Vec<OutPoint>,
}

/// Decode one serialized transaction (all of `bytes`).
pub(crate) fn decode_transaction(bytes: &[u8]) -> Result<DecodedTransaction> {
    struct Collect {
        inputs: Vec<bitcoin::TxIn>,
        outputs: Vec<bitcoin::TxOut>,
    }
    impl Visitor for Collect {
        fn visit_tx_in(&mut self, _vin: usize, tx_in: &TxIn) -> ControlFlow<()> {
            self.inputs.push(bitcoin::TxIn {
                previous_output: tx_in.prevout,
                script_sig: ScriptBuf::from_bytes(tx_in.script_sig.to_vec()),
                sequence: Sequence(tx_in.sequence),
                witness: Witness::new(),
            });
            ControlFlow::Continue(())
        }
        fn visit_tx_out(&mut self, _vout: usize, tx_out: &TxOut) -> ControlFlow<()> {
            self.outputs.push(bitcoin::TxOut {
                value: Amount::from_sat(tx_out.value),
                script_pubkey: ScriptBuf::from_bytes(tx_out.script_pubkey.to_vec()),
            });
            ControlFlow::Continue(())
        }
    }
    let mut collect = Collect {
        inputs: vec![],
        outputs: vec![],
    };
    let mut reader = Reader::new(bytes);
    let parsed = parse_tx(&mut reader, &mut collect)?;
    ensure!(
        reader.is_empty(),
        "{} trailing bytes after the transaction",
        reader.remaining()
    );
    for (input, witness) in collect.inputs.iter_mut().zip(parsed.witnesses) {
        input.witness = Witness::from_slice(&witness);
    }
    Ok(DecodedTransaction {
        tx: bitcoin::Transaction {
            version: Version(parsed.version),
            lock_time: LockTime::from_consensus(parsed.lock_time),
            input: collect.inputs,
            output: collect.outputs,
        },
        txid: parsed.txid,
        ref_inputs: parsed.ref_inputs,
    })
}

fn visit_tx(reader: &mut Reader, visitor: &mut impl Visitor) -> Result<ControlFlow<()>> {
    let start = reader.pos;
    let parsed = match parse_tx(reader, visitor) {
        Ok(parsed) => parsed,
        Err(e) if e.is::<Stop>() => return Ok(ControlFlow::Break(())),
        Err(e) => return Err(e),
    };
    let tx = Transaction {
        bytes: &reader.data[start..reader.pos],
        txid: parsed.txid,
    };
    Ok(visitor.visit_transaction(&tx))
}

/// The visitor asked to stop.
#[derive(Debug)]
struct Stop;

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("visit stopped")
    }
}

impl std::error::Error for Stop {}

struct ParsedTx<'a> {
    txid: Txid,
    version: i32,
    lock_time: u32,
    ref_inputs: Vec<OutPoint>,
    witnesses: Vec<Vec<&'a [u8]>>,
}

/// `UnserializeTransaction`, reporting inputs and outputs to `visitor`.
fn parse_tx<'a>(reader: &mut Reader<'a>, visitor: &mut impl Visitor) -> Result<ParsedTx<'a>> {
    let version_bytes = reader.bytes(4)?;
    let version = i32::from_le_bytes(version_bytes.try_into().expect("4 bytes"));

    let mut flags = 0u8;
    let mut io_start = reader.pos;
    let mut n_inputs = reader.compact_size()?;
    let mut has_io = true;
    if n_inputs == 0 {
        // A dummy empty vin: the extended format (or a transaction with neither
        // inputs nor outputs when the flags are zero).
        flags = reader.u8()?;
        if flags != 0 {
            io_start = reader.pos;
            n_inputs = reader.compact_size()?;
        } else {
            has_io = false;
        }
    }

    if has_io {
        for vin in 0..n_inputs as usize {
            let txid = Txid::from_slice(reader.bytes(32)?).expect("32 bytes");
            let vout = reader.u32()?;
            let script_len = reader.compact_size()? as usize;
            let script_sig = reader.bytes(script_len)?;
            let sequence = reader.u32()?;
            let tx_in = TxIn {
                prevout: OutPoint { txid, vout },
                script_sig,
                sequence,
            };
            if visitor.visit_tx_in(vin, &tx_in).is_break() {
                bail!(Stop);
            }
        }
        let n_outputs = reader.compact_size()?;
        for vout in 0..n_outputs as usize {
            let value = reader.u64()?;
            let script_len = reader.compact_size()? as usize;
            let script_pubkey = reader.bytes(script_len)?;
            if visitor
                .visit_tx_out(
                    vout,
                    &TxOut {
                        value,
                        script_pubkey,
                    },
                )
                .is_break()
            {
                bail!(Stop);
            }
        }
    }
    let io_end = reader.pos;

    let mut ref_inputs = vec![];
    let mut refs_range = io_end..io_end;
    if flags & FLAG_REF_INPUTS != 0 {
        flags ^= FLAG_REF_INPUTS;
        let start = reader.pos;
        let count = reader.compact_size()?;
        ensure!(count != 0, "superfluous reference inputs record");
        for _ in 0..count {
            let txid = Txid::from_slice(reader.bytes(32)?).expect("32 bytes");
            let vout = reader.u32()?;
            ref_inputs.push(OutPoint { txid, vout });
        }
        refs_range = start..reader.pos;
    }

    let mut witnesses = vec![];
    if flags & FLAG_WITNESS != 0 {
        flags ^= FLAG_WITNESS;
        for _ in 0..n_inputs {
            let items = reader.compact_size()?;
            let mut stack = Vec::with_capacity(items.min(1024) as usize);
            for _ in 0..items {
                let len = reader.compact_size()? as usize;
                stack.push(reader.bytes(len)?);
            }
            witnesses.push(stack);
        }
        if !ref_inputs.is_empty() {
            ensure!(
                witnesses.iter().any(|s| !s.is_empty()),
                "superfluous witness record"
            );
        }
    }
    ensure!(
        flags == 0,
        "unknown transaction optional data (flags {:#x})",
        flags
    );
    let lock_time_bytes = reader.bytes(4)?;
    let lock_time = u32::from_le_bytes(lock_time_bytes.try_into().expect("4 bytes"));

    let mut engine = sha256d::Hash::engine();
    engine.input(version_bytes);
    if !ref_inputs.is_empty() {
        engine.input(&[0, FLAG_REF_INPUTS]);
    }
    if has_io {
        engine.input(&reader.data[io_start..io_end]);
    } else {
        // An empty vin and an empty vout.
        engine.input(&[0, 0]);
    }
    engine.input(&reader.data[refs_range]);
    engine.input(lock_time_bytes);

    Ok(ParsedTx {
        txid: Txid::from_raw_hash(sha256d::Hash::from_engine(engine)),
        version,
        lock_time,
        ref_inputs,
        witnesses,
    })
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.remaining(), "transaction truncated");
        let bytes = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.bytes(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.bytes(8)?.try_into().expect("8 bytes"),
        ))
    }

    /// `ReadCompactSize`: canonical encodings only, at most `MAX_SIZE`.
    fn compact_size(&mut self) -> Result<u64> {
        let value = match self.u8()? {
            0xfd => {
                let v = u64::from(u16::from_le_bytes(
                    self.bytes(2)?.try_into().expect("2 bytes"),
                ));
                ensure!(v >= 0xfd, "non-canonical compact size");
                v
            }
            0xfe => {
                let v = u64::from(self.u32()?);
                ensure!(v >= 0x1_0000, "non-canonical compact size");
                v
            }
            0xff => {
                let v = self.u64()?;
                ensure!(v >= 0x1_0000_0000, "non-canonical compact size");
                v
            }
            n => u64::from(n),
        };
        ensure!(value <= MAX_SIZE, "compact size too large");
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{deserialize, serialize};

    fn sample_tx(witness: bool) -> bitcoin::Transaction {
        let input = |n: u8| bitcoin::TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([n; 32]),
                vout: u32::from(n),
            },
            script_sig: ScriptBuf::from_bytes(if witness { vec![] } else { vec![0x51, n] }),
            sequence: Sequence(0xffff_fffd),
            witness: if witness {
                Witness::from_slice(&[vec![0xab; 71], vec![n; 33]])
            } else {
                Witness::new()
            },
        };
        let output = |n: u8| bitcoin::TxOut {
            value: Amount::from_sat(1000 * u64::from(n)),
            script_pubkey: ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, n, 0x88, 0xac]),
        };
        bitcoin::Transaction {
            version: Version(2),
            lock_time: LockTime::from_consensus(123),
            input: vec![input(1), input(2)],
            output: vec![output(3), output(4), output(5)],
        }
    }

    /// Legacy and segwit transactions: same txid and decoding as rust-bitcoin.
    #[test]
    fn bitcoin_transactions_match_rust_bitcoin() {
        for witness in [false, true] {
            let expected = sample_tx(witness);
            let decoded = decode_transaction(&serialize(&expected)).unwrap();
            assert_eq!(decoded.txid, expected.compute_txid());
            assert_eq!(decoded.tx, expected);
            assert!(decoded.ref_inputs.is_empty());
        }
    }

    /// Real v1.0.7 regtest blocks: the txids are those of rust-bitcoin, and
    /// their merkle root is the header's.
    #[test]
    fn real_blocks_txids_and_merkle_root() {
        let params = NetworkParams::for_network(crate::neurai::NeuraiNetwork::RegtestV1);
        for height in [1101, 1104, 1106, 1107, 1110, 1111, 1112] {
            let path = format!(
                "{}/tests/fixtures/neurai-v1.0.7-regtest-block-{height}.hex",
                env!("CARGO_MANIFEST_DIR")
            );
            let hex = std::fs::read_to_string(path).unwrap();
            let bytes: Vec<u8> = (0..hex.trim().len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let block: bitcoin::Block = deserialize(&bytes).unwrap();

            struct Txids(Vec<(Txid, Vec<u8>)>);
            impl Visitor for Txids {
                fn visit_transaction(&mut self, tx: &Transaction) -> ControlFlow<()> {
                    self.0.push((tx.txid(), tx.as_bytes().to_vec()));
                    ControlFlow::Continue(())
                }
            }
            let mut txids = Txids(vec![]);
            assert!(visit_block(&bytes, params, &mut txids)
                .unwrap()
                .is_continue());
            assert_eq!(txids.0.len(), block.txdata.len());
            for ((txid, raw), tx) in txids.0.iter().zip(&block.txdata) {
                assert_eq!(*txid, tx.compute_txid());
                assert_eq!(*raw, serialize(tx));
            }
            let root =
                bitcoin::merkle_tree::calculate_root(txids.0.iter().map(|(t, _)| *t)).unwrap();
            assert_eq!(
                root.to_byte_array(),
                block.header.merkle_root.to_byte_array()
            );
        }
    }

    /// A v3 transaction with reference inputs, and what its txid hashes.
    fn ref_inputs_tx(witness: bool) -> (Vec<u8>, Vec<u8>) {
        let legacy = serialize(&sample_tx(false));
        let io = &legacy[4..legacy.len() - 4]; // vin | vout
        let mut refs = vec![2u8];
        for n in [7u8, 9] {
            refs.extend([n; 32]);
            refs.extend(u32::from(n).to_le_bytes());
        }
        let mut tx = 3i32.to_le_bytes().to_vec();
        tx.extend([0, if witness { 3 } else { 2 }]);
        tx.extend_from_slice(io);
        tx.extend_from_slice(&refs);
        if witness {
            tx.extend([1, 2, 0xab, 0xcd]); // input 0: one 2-byte item
            tx.extend([0]); // input 1: empty
        }
        tx.extend(123u32.to_le_bytes());
        let mut preimage = 3i32.to_le_bytes().to_vec();
        preimage.extend([0, 2]);
        preimage.extend_from_slice(io);
        preimage.extend_from_slice(&refs);
        preimage.extend(123u32.to_le_bytes());
        (tx, preimage)
    }

    #[test]
    fn reference_inputs_are_part_of_the_txid() {
        for witness in [false, true] {
            let (bytes, preimage) = ref_inputs_tx(witness);
            let decoded = decode_transaction(&bytes).unwrap();
            assert_eq!(
                decoded.txid,
                Txid::from_raw_hash(sha256d::Hash::hash(&preimage))
            );
            assert_eq!(decoded.tx.version, Version(3));
            assert_eq!(decoded.tx.input.len(), 2);
            assert_eq!(decoded.tx.output.len(), 3);
            assert_eq!(decoded.tx.lock_time, LockTime::from_consensus(123));
            assert_eq!(
                decoded.ref_inputs,
                vec![
                    OutPoint {
                        txid: Txid::from_byte_array([7; 32]),
                        vout: 7
                    },
                    OutPoint {
                        txid: Txid::from_byte_array([9; 32]),
                        vout: 9
                    },
                ]
            );
            assert_eq!(decoded.tx.input[0].witness.len(), usize::from(witness));
        }
    }

    #[test]
    fn malformed_extended_transactions_are_rejected() {
        let (bytes, _) = ref_inputs_tx(false);
        let refs_at = bytes.len() - 4 - (1 + 2 * 36);
        let mut empty_refs = bytes.clone();
        empty_refs.splice(refs_at..bytes.len() - 4, [0u8]);
        assert!(
            decode_transaction(&empty_refs).is_err(),
            "empty reference inputs"
        );

        let mut unknown_flag = bytes.clone();
        unknown_flag[5] = 6;
        assert!(decode_transaction(&unknown_flag).is_err(), "unknown flag");

        assert!(
            decode_transaction(&bytes[..bytes.len() - 1]).is_err(),
            "truncated"
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_transaction(&trailing).is_err(), "trailing bytes");

        // reference inputs with an all-empty witness record
        let (mut empty_witness, _) = ref_inputs_tx(true);
        let at = empty_witness.len() - 4 - 5;
        empty_witness.splice(at..empty_witness.len() - 4, [0u8, 0]);
        assert!(
            decode_transaction(&empty_witness).is_err(),
            "superfluous witness"
        );
    }
}
