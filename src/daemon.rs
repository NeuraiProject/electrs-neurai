use anyhow::{Context, Result};

use bitcoin::hashes::hex::FromHex;
use bitcoin::{Amount, BlockHash, Transaction, Txid};
use bitcoincore_rpc::{jsonrpc, Auth, Client, RpcApi};
use crossbeam_channel::Receiver;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, value::RawValue, Value};

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::{
    chain::{Chain, NewHeader},
    config::Config,
    metrics::Metrics,
    neurai::{self, NetworkParams},
    p2p::Connection,
    signals::ExitFlag,
    types::SerBlock,
};

/// A mempool transaction and its serialization.
pub(crate) type MempoolTx = (Transaction, Box<[u8]>);

enum PollResult {
    Done(Result<()>),
    Retry,
}

/// Minimal view over `getmempoolinfo`. Neurai's response omits fields that
/// `bitcoincore_rpc::json::GetMempoolInfoResult` requires (`loaded`, `total_fee`,
/// `minrelaytxfee`, `unbroadcastcount`), so we deserialize only what electrs reads.
/// Missing `loaded` defaults to `true` — the daemon answered, so the mempool is loaded.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct MempoolInfo {
    #[serde(default = "default_true")]
    pub loaded: Option<bool>,
}

fn default_true() -> Option<bool> {
    Some(true)
}

/// Minimal view over `getmempoolentry`.
///
/// Neurai (v1.0.7 and the DePIN-Test branch) still returns the pre-Bitcoin-0.17
/// shape — `size` / `fee` / `depends`, without the `fees` object, `spentby` or
/// `bip125-replaceable` — which `bitcoincore_rpc::json::GetMempoolEntryResult`
/// requires. Newer field names are accepted too.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct MempoolEntry {
    /// Virtual size (`size` on Neurai).
    #[serde(alias = "size")]
    pub vsize: u64,
    #[serde(default, with = "bitcoin::amount::serde::as_btc::opt")]
    fee: Option<Amount>,
    #[serde(default)]
    fees: Option<MempoolEntryFees>,
    pub depends: Vec<Txid>,
}

#[derive(Debug, serde::Deserialize)]
struct MempoolEntryFees {
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    base: Amount,
}

impl MempoolEntry {
    pub(crate) fn fee(&self) -> Option<Amount> {
        self.fees.as_ref().map(|f| f.base).or(self.fee)
    }
}

/// Minimal view over `getblock <hash> 1` — Neurai doesn't return `nTx`, which
/// `bitcoincore_rpc::json::GetBlockResult` requires.
#[derive(Debug, serde::Deserialize)]
struct BlockTxids {
    tx: Vec<Txid>,
}

/// Minimal view over `getblockchaininfo` — only the fields electrs actually needs.
///
/// Neurai's daemon still follows the pre-Bitcoin-0.19 RPC shape (`softforks` is an array
/// and `initialblockdownload` may be missing), so deserializing into
/// `bitcoincore_rpc::json::GetBlockchainInfoResult` fails. We ignore the incompatible
/// fields and fall back to `false` for a missing IBD flag.
#[derive(Debug, serde::Deserialize)]
struct BlockchainInfo {
    blocks: u64,
    headers: u64,
    #[serde(rename = "initialblockdownload", default)]
    initial_block_download: bool,
    pruned: bool,
}

fn rpc_poll(client: &mut Client, skip_block_download_wait: bool) -> PollResult {
    match client.call::<BlockchainInfo>("getblockchaininfo", &[]) {
        Ok(info) => {
            if skip_block_download_wait {
                // Neurai daemon RPC is available, don't wait for block download to finish
                return PollResult::Done(Ok(()));
            }
            let left_blocks = info.headers.saturating_sub(info.blocks);
            if info.initial_block_download || left_blocks > 0 {
                info!(
                    "waiting for {} blocks to download{}",
                    left_blocks,
                    if info.initial_block_download {
                        " (IBD)"
                    } else {
                        ""
                    }
                );
                return PollResult::Retry;
            }
            PollResult::Done(Ok(()))
        }
        Err(err) => {
            if let Some(e) = extract_bitcoind_error(&err) {
                if e.code == -28 {
                    debug!("waiting for RPC warmup: {}", e.message);
                    return PollResult::Retry;
                }
            }
            PollResult::Done(Err(err).context("daemon not available"))
        }
    }
}

fn read_cookie(path: &Path) -> Result<(String, String)> {
    // Load username and password from the Neurai daemon cookie file (same format as
    // bitcoind's RPC cookie — USER:PASSWORD, one line).
    let mut file = File::open(path).with_context(|| {
        format!("failed to open Neurai daemon cookie file: {}", path.display())
    })?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).with_context(|| {
        format!("failed to read Neurai daemon cookie from {}", path.display())
    })?;

    let parts: Vec<&str> = contents.splitn(2, ':').collect();
    ensure!(
        parts.len() == 2,
        "failed to parse Neurai daemon cookie - missing ':' separator"
    );
    Ok((parts[0].to_owned(), parts[1].to_owned()))
}

fn rpc_connect(config: &Config) -> Result<Client> {
    let rpc_url = format!("http://{}", config.daemon_rpc_addr);
    // Allow RPC calls to take longer before timing out.
    // See https://github.com/romanz/electrs/issues/495 for more details.
    let builder = jsonrpc::simple_http::SimpleHttpTransport::builder()
        .url(&rpc_url)?
        .timeout(config.jsonrpc_timeout);
    let builder = match config.daemon_auth.get_auth() {
        Auth::None => builder,
        Auth::UserPass(user, pass) => builder.auth(user, Some(pass)),
        Auth::CookieFile(path) => {
            let (user, pass) = read_cookie(&path)?;
            builder.auth(user, Some(pass))
        }
    };
    Ok(Client::from_jsonrpc(jsonrpc::Client::with_transport(
        builder.build(),
    )))
}

pub struct Daemon {
    p2p: Mutex<Connection>,
    rpc: Client,
}

impl Daemon {
    pub(crate) fn connect(
        config: &Config,
        exit_flag: &ExitFlag,
        metrics: &Metrics,
    ) -> Result<Self> {
        let mut rpc = rpc_connect(config)?;

        loop {
            exit_flag
                .poll()
                .context("Neurai daemon RPC polling interrupted")?;
            match rpc_poll(&mut rpc, config.skip_block_download_wait) {
                PollResult::Done(result) => {
                    result.context("Neurai daemon RPC polling failed")?;
                    break; // on success, finish polling
                }
                PollResult::Retry => {
                    std::thread::sleep(std::time::Duration::from_secs(1)); // wait a bit before polling
                }
            }
        }

        let network_info = rpc.get_network_info()?;
        if network_info.version < 21_00_00 {
            bail!("electrs-neurai requires a Neurai daemon with protocol version 0.21+");
        }
        if !network_info.network_active {
            bail!("electrs-neurai requires an active Neurai daemon p2p network");
        }
        let info = rpc.call::<BlockchainInfo>("getblockchaininfo", &[])?;
        if info.pruned {
            bail!("electrs-neurai requires a non-pruned Neurai daemon");
        }

        let params = NetworkParams::for_network(config.network);
        let p2p = Mutex::new(Connection::connect(
            config.daemon_p2p_addr,
            metrics,
            params,
        )?);
        Ok(Self { p2p, rpc })
    }

    /// `estimatesmartfee` as ElectrumX calls it: the daemon's `feerate` float
    /// (XNA/kB) is passed through unchanged; `None` when the daemon has no
    /// estimate (no `feerate` key) or fee estimation is disabled.
    pub(crate) fn estimate_smart_fee(&self, blocks: u64, mode: Option<&str>) -> Result<Option<f64>> {
        let mut params = vec![json!(blocks)];
        if let Some(mode) = mode {
            params.push(json!(mode));
        }
        match self.rpc.call::<Value>("estimatesmartfee", &params) {
            Ok(result) => Ok(result.get("feerate").and_then(Value::as_f64)),
            Err(bitcoincore_rpc::Error::JsonRpc(jsonrpc::Error::Rpc(RpcError {
                code: -32603, ..
            }))) => Ok(None),
            Err(e) => Err(e).context("failed to estimate fee"),
        }
    }

    /// Any daemon RPC, result passed through (errors keep the daemon's code).
    pub(crate) fn call(&self, method: &str, params: &[Value]) -> Result<Value> {
        self.rpc
            .call::<Value>(method, params)
            .with_context(|| format!("{} failed", method))
    }

    /// Raw `getnetworkinfo` reply (relay fee as the daemon's own float, version
    /// fields for the server banner).
    pub(crate) fn get_network_info_raw(&self) -> Result<Value> {
        self.rpc
            .call::<Value>("getnetworkinfo", &[])
            .context("failed to get network info")
    }

    /// `sendrawtransaction` of a hex string, decoded and validated by the daemon.
    pub(crate) fn broadcast_raw(&self, tx_hex: &str) -> Result<Txid> {
        self.rpc
            .call("sendrawtransaction", &[json!(tx_hex)])
            .context("failed to broadcast transaction")
    }

    #[allow(dead_code)]
    pub(crate) fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        self.rpc
            .send_raw_transaction(tx)
            .context("failed to broadcast transaction")
    }

    // Neurai's `getrawtransaction` accepts at most 2 params (`txid`, `verbose`):
    // there is no `blockhash` argument, so never pass one. Without `-txindex`
    // it only finds mempool transactions and those with unspent outputs.

    /// Verbose `getrawtransaction` — used for mempool transactions.
    pub(crate) fn get_transaction_info(&self, txid: &Txid) -> Result<Value> {
        // No need to parse the resulting JSON, just return it as-is to the client.
        self.rpc
            .call("getrawtransaction", &[json!(txid), json!(true)])
            .context("failed to get transaction info")
    }

    /// `decoderawtransaction` — verbose JSON for a transaction we already have.
    pub(crate) fn decode_transaction(&self, tx_bytes: &[u8]) -> Result<Value> {
        use bitcoin::hex::DisplayHex;
        self.rpc
            .call("decoderawtransaction", &[json!(tx_bytes.to_lower_hex_string())])
            .context("failed to decode transaction")
    }

    pub(crate) fn get_transaction_hex(&self, txid: &Txid) -> Result<Value> {
        use bitcoin::consensus::serde::{hex::Lower, Hex, With};

        let tx = self.get_transaction(txid)?;
        #[derive(serde::Serialize)]
        #[serde(transparent)]
        struct TxAsHex(#[serde(with = "With::<Hex<Lower>>")] Transaction);
        serde_json::to_value(TxAsHex(tx)).map_err(Into::into)
    }

    pub(crate) fn get_transaction(&self, txid: &Txid) -> Result<Transaction> {
        self.rpc
            .get_raw_transaction(txid, None)
            .context("failed to get transaction")
    }

    pub(crate) fn get_block_txids(&self, blockhash: BlockHash) -> Result<Vec<Txid>> {
        Ok(self
            .rpc
            .call::<BlockTxids>("getblock", &[json!(blockhash), json!(1)])
            .context("failed to get block txids")?
            .tx)
    }

    pub(crate) fn get_mempool_info(&self) -> Result<MempoolInfo> {
        self.rpc
            .call::<MempoolInfo>("getmempoolinfo", &[])
            .context("failed to get mempool info")
    }

    pub(crate) fn get_mempool_txids(&self) -> Result<Vec<Txid>> {
        self.rpc
            .get_raw_mempool()
            .context("failed to get mempool txids")
    }

    pub(crate) fn get_mempool_entries(&self, txids: &[Txid]) -> Result<Vec<Option<MempoolEntry>>> {
        let results = batch_request(self.rpc.get_jsonrpc_client(), "getmempoolentry", txids)?;
        Ok(results
            .into_iter()
            .map(|r| match r?.result::<MempoolEntry>() {
                Ok(entry) if entry.fee().is_some() => Some(entry),
                Ok(entry) => {
                    warn!("mempool entry without fee: {:?}", entry);
                    None
                }
                Err(err) => {
                    debug!("failed to get mempool entry: {}", err); // probably evicted meanwhile
                    None
                }
            })
            .collect())
    }

    /// Mempool transactions, decoded with Neurai's serialization (NIP-014
    /// reference inputs included), with the bytes the daemon returned.
    pub(crate) fn get_mempool_transactions(&self, txids: &[Txid]) -> Result<Vec<Option<MempoolTx>>> {
        let results = batch_request(self.rpc.get_jsonrpc_client(), "getrawtransaction", txids)?;
        Ok(results
            .into_iter()
            .zip(txids)
            .map(|(r, txid)| -> Option<MempoolTx> {
                let tx_hex = match r?.result::<String>() {
                    Ok(tx_hex) => Some(tx_hex),
                    Err(err) => {
                        debug!("failed to get mempool tx: {}", err); // probably due to RBF
                        None
                    }
                }?;
                let tx_bytes = match Vec::from_hex(&tx_hex) {
                    Ok(tx_bytes) => Some(tx_bytes),
                    Err(err) => {
                        warn!("got non-hex transaction {}: {}", tx_hex, err);
                        None
                    }
                }?;
                match neurai::tx::decode_transaction(&tx_bytes) {
                    Ok(decoded) if decoded.txid == *txid => Some((decoded.tx, tx_bytes.into_boxed_slice())),
                    Ok(decoded) => {
                        warn!("mempool tx {} decodes as {}", txid, decoded.txid);
                        None
                    }
                    Err(err) => {
                        warn!("got invalid tx {}: {:#}", tx_hex, err);
                        None
                    }
                }
            })
            .collect())
    }

    pub(crate) fn get_new_headers(&self, chain: &Chain) -> Result<Vec<NewHeader>> {
        self.p2p.lock().get_new_headers(chain)
    }

    pub(crate) fn for_blocks<B, F>(&self, blockhashes: B, func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        self.p2p.lock().for_blocks(blockhashes, func)
    }

    pub(crate) fn new_block_notification(&self) -> Receiver<()> {
        self.p2p.lock().new_block_notification()
    }

    /// Fetch the genesis block hash (height 0) from the daemon RPC.
    /// Used for testnet/regtest where the genesis is epoch-based.
    pub(crate) fn get_genesis_hash(&self) -> Result<BlockHash> {
        self.rpc
            .get_block_hash(0)
            .context("failed to get genesis block hash")
    }
}

pub(crate) type RpcError = bitcoincore_rpc::jsonrpc::error::RpcError;

pub(crate) fn extract_bitcoind_error(err: &bitcoincore_rpc::Error) -> Option<&RpcError> {
    use bitcoincore_rpc::{
        jsonrpc::error::Error::Rpc as ServerError, Error::JsonRpc as JsonRpcError,
    };
    match err {
        JsonRpcError(ServerError(e)) => Some(e),
        _ => None,
    }
}

fn batch_request<T>(
    client: &jsonrpc::Client,
    name: &str,
    items: &[T],
) -> Result<Vec<Option<jsonrpc::Response>>>
where
    T: Serialize,
{
    debug!("calling {} on {} items", name, items.len());
    let args: Vec<Box<RawValue>> = items
        .iter()
        .map(|item| jsonrpc::try_arg([item]).context("failed to serialize into JSON"))
        .collect::<Result<Vec<_>>>()?;
    let reqs: Vec<jsonrpc::Request> = args
        .iter()
        .map(|arg| client.build_request(name, Some(arg)))
        .collect();
    match client.send_batch(&reqs) {
        Ok(values) => {
            assert_eq!(items.len(), values.len());
            Ok(values)
        }
        Err(err) => bail!("batch {} request failed: {}", name, err),
    }
}

#[cfg(test)]
mod tests {
    use super::{BlockTxids, MempoolEntry};
    use bitcoin::Amount;

    /// `getmempoolentry` exactly as returned by neuraid v1.0.7.
    #[test]
    fn mempool_entry_from_neurai_v107() {
        let entry: MempoolEntry = serde_json::from_str(
            r#"{"size":542,"fee":0.00556575,"modifiedfee":0.00556575,"time":1794678725,
            "height":1107,"descendantcount":1,"descendantsize":542,"descendantfees":556575,
            "ancestorcount":1,"ancestorsize":542,"ancestorfees":556575,
            "wtxid":"2e49ee922182755060849d0543c652d08e70efa21758b9ba3623eb22caaf09f1",
            "depends":[]}"#,
        )
        .unwrap();
        assert_eq!(entry.vsize, 542);
        assert_eq!(entry.fee(), Some(Amount::from_sat(556_575)));
        assert!(entry.depends.is_empty());
    }

    /// Bitcoin Core >= 0.17 shape (`vsize` + `fees.base`) is still accepted.
    #[test]
    fn mempool_entry_from_newer_shape() {
        let entry: MempoolEntry = serde_json::from_str(
            r#"{"vsize":141,"fees":{"base":0.00001410,"modified":0.00001410},
            "depends":["2e49ee922182755060849d0543c652d08e70efa21758b9ba3623eb22caaf09f1"]}"#,
        )
        .unwrap();
        assert_eq!(entry.vsize, 141);
        assert_eq!(entry.fee(), Some(Amount::from_sat(1_410)));
        assert_eq!(entry.depends.len(), 1);
    }

    /// `getblock <hash> 1` from neuraid v1.0.7 (no `nTx` field).
    #[test]
    fn block_txids_from_neurai_v107() {
        let block: BlockTxids = serde_json::from_str(
            r#"{"hash":"18c6ce11c89a6b132e1f51bca36e317a5d03a1b65e3257595419492e4c036c0c",
            "confirmations":8,"strippedsize":1236,"size":1272,"weight":4980,"height":1101,
            "version":805307392,"versionHex":"30000400",
            "merkleroot":"b5db62d1bacd65886663c4e45f79e5be4a41078f5b6335af4b57426ef8d0382a",
            "tx":["8a3cefe269ef43e81b46227abd087966bd7b55b3cc964b518ffdba4cd0b0a105",
            "fcc43c0b3ce4fbc51b146023e6f70af89ce6a6be167921562ef9ff0276931f74",
            "0218cb7e8ca0abdc7c9066660a0a183c64e8370522c34622dbf0d160307157d2",
            "b8cbbbc6561ed4f2edae553eaa7941eb85f400f4c55c53616926b671644309f9"],
            "time":1794678827,"mediantime":1794678826,"nonce":3,"bits":"207fffff",
            "difficulty":4.656542373906925e-10,
            "chainwork":"000000000000000000000000000000000000000000000000000000000000089a",
            "headerhash":"9d73ddc6e268f2543a67e7772cad6cee7d8ac003df72f6a8ff7391cc2c8a8cf0",
            "mixhash":"0000000000000000000000000000000000000000000000000000000000000000",
            "nonce64":0,
            "previousblockhash":"035a8b1bebc1b88e9c388d261cf9baf2012a1f46cb7adfa69a64829be4dccfd1"}"#,
        )
        .unwrap();
        assert_eq!(block.tx.len(), 4);
        assert_eq!(
            block.tx[2].to_string(),
            "0218cb7e8ca0abdc7c9066660a0a183c64e8370522c34622dbf0d160307157d2"
        );
    }
}
