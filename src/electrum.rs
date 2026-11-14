use anyhow::{bail, Context, Result};
use bitcoin::{
    consensus::{deserialize, encode::serialize_hex},
    hashes::hex::FromHex,
    hex::DisplayHex,
    BlockHash, Transaction, Txid,
};
use crossbeam_channel::Receiver;
use rayon::prelude::*;
use serde_derive::Deserialize;
use serde_json::{self, json, Value};

use std::collections::{hash_map::Entry, BTreeSet, HashMap};
use std::fmt;
use std::iter::FromIterator;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::{
    cache::Cache,
    config::{Config, ELECTRS_VERSION},
    daemon::{self, extract_bitcoind_error, Daemon},
    merkle::Proof,
    metrics::{self, Histogram, Metrics},
    signals::Signal,
    status::{Balance, ScriptHashStatus, UnspentEntry, NATIVE_ASSET_KEY},
    tracker::Tracker,
    types::ScriptHash,
};

const PROTOCOL_VERSION: &str = "1.4";
const UNKNOWN_FEE: isize = -1; // (allowed by Electrum protocol)

const UNSUBSCRIBED_QUERY_MESSAGE: &str = "your wallet uses less efficient method of querying electrs, consider contacting the developer of your wallet. Reason:";

/// Per-client Electrum protocol state
#[derive(Default)]
pub struct Client {
    tip: Option<BlockHash>,
    scripthashes: HashMap<ScriptHash, ScriptHashStatus>,
}

#[derive(Deserialize)]
struct Request {
    id: Value,
    method: String,

    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Requests {
    Single(Request),
    Batch(Vec<Request>),
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
enum VersionRequest {
    Single(String),
    MinMax(String, String),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TxGetArgs {
    Txid((Txid,)),
    TxidVerbose(Txid, bool),
}

impl From<&TxGetArgs> for (Txid, bool) {
    fn from(args: &TxGetArgs) -> Self {
        match args {
            TxGetArgs::Txid((txid,)) => (*txid, false),
            TxGetArgs::TxidVerbose(txid, verbose) => (*txid, *verbose),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TxFromPosArgs {
    HeightPos((usize, usize)),
    HeightPosMerkle((usize, usize, bool)),
}

impl From<&TxFromPosArgs> for (usize, usize, bool) {
    fn from(args: &TxFromPosArgs) -> Self {
        match args {
            TxFromPosArgs::HeightPos((height, tx_pos)) => (*height, *tx_pos, false),
            TxFromPosArgs::HeightPosMerkle(args) => *args,
        }
    }
}

enum StandardError {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
}

enum RpcError {
    // JSON-RPC spec errors
    Standard(StandardError),
    // Electrum-specific errors
    BadRequest(anyhow::Error),
    DaemonError(daemon::RpcError),
    UnavailableIndex,
}

impl RpcError {
    fn to_value(&self) -> Value {
        match self {
            RpcError::Standard(err) => match err {
                StandardError::ParseError => json!({"code": -32700, "message": "parse error"}),
                StandardError::InvalidRequest => {
                    json!({"code": -32600, "message": "invalid request"})
                }
                StandardError::MethodNotFound => {
                    json!({"code": -32601, "message": "method not found"})
                }
                StandardError::InvalidParams => {
                    json!({"code": -32602, "message": "invalid params"})
                }
            },
            RpcError::BadRequest(err) => json!({"code": 1, "message": err.to_string()}),
            RpcError::DaemonError(err) => json!({"code": 2, "message": err.message}),
            RpcError::UnavailableIndex => {
                // Internal JSON-RPC error (https://www.jsonrpc.org/specification#error_object)
                json!({"code": -32603, "message": "unavailable index"})
            }
        }
    }
}

/// Optional `asset` parameter for `scripthash.get_balance` / `scripthash.listunspent`.
///
/// Wire forms (ElectrumX-neurai compatible):
/// * `false`, `null`, or absent  → `NativeOnly`
/// * `true`                       → `All`
/// * string `"TOKEN"`             → `One("TOKEN")`
/// * array `[null, "TOKEN_A"]`    → `Many { include_native: true, assets: {"TOKEN_A"} }`
///   * Inside the array, `null` means native; strings are asset names.
///   * `bool` is NOT a valid array element (only valid as the whole parameter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AssetFilter {
    NativeOnly,
    All,
    One(String),
    Many {
        include_native: bool,
        assets: BTreeSet<String>,
    },
}

impl Default for AssetFilter {
    fn default() -> Self {
        AssetFilter::NativeOnly
    }
}

impl AssetFilter {
    fn from_json(v: &Value) -> std::result::Result<Self, String> {
        match v {
            Value::Null => Ok(AssetFilter::NativeOnly),
            Value::Bool(false) => Ok(AssetFilter::NativeOnly),
            Value::Bool(true) => Ok(AssetFilter::All),
            Value::String(s) => Ok(AssetFilter::One(s.clone())),
            Value::Array(arr) => {
                let mut include_native = false;
                let mut assets = BTreeSet::new();
                for elem in arr {
                    match elem {
                        Value::Null => include_native = true,
                        Value::String(s) => {
                            assets.insert(s.clone());
                        }
                        // bool / number / nested arrays / objects are NOT
                        // valid array elements per the ElectrumX-neurai wire.
                        other => {
                            return Err(format!(
                                "asset-filter array element must be null or string, got {other}"
                            ));
                        }
                    }
                }
                Ok(AssetFilter::Many {
                    include_native,
                    assets,
                })
            }
            other => Err(format!(
                "asset filter must be bool, string, array, or null; got {other}"
            )),
        }
    }
}

impl<'de> serde::Deserialize<'de> for AssetFilter {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = Value::deserialize(deserializer)?;
        Self::from_json(&v).map_err(serde::de::Error::custom)
    }
}

/// `(scripthash, asset?)` arg shape, accepted by `scripthash.get_balance` and
/// `scripthash.listunspent`. The optional second element is parsed via
/// [`AssetFilter::from_json`] and defaults to `NativeOnly` when absent.
#[derive(Debug)]
pub(crate) struct ScriptHashWithAsset {
    pub scripthash: ScriptHash,
    pub asset: AssetFilter,
}

impl<'de> serde::Deserialize<'de> for ScriptHashWithAsset {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let arr = Vec::<Value>::deserialize(deserializer)?;
        if arr.is_empty() || arr.len() > 2 {
            return Err(serde::de::Error::custom(format!(
                "expected [scripthash] or [scripthash, asset], got {} elements",
                arr.len()
            )));
        }
        let scripthash: ScriptHash =
            serde_json::from_value(arr[0].clone()).map_err(serde::de::Error::custom)?;
        let asset = if arr.len() == 2 {
            AssetFilter::from_json(&arr[1]).map_err(serde::de::Error::custom)?
        } else {
            AssetFilter::NativeOnly
        };
        Ok(ScriptHashWithAsset { scripthash, asset })
    }
}

/// Format a `Balance` as JSON shaped by the requested `AssetFilter`.
///
/// * `NativeOnly` / `One(_)` → legacy single-asset shape `{"confirmed": N, "unconfirmed": M}`
/// * `All` / `Many { .. }`   → multi-asset map `{"rvn": {...}, "TOKEN": {...}}`
fn balance_to_json(balance: &Balance, filter: &AssetFilter) -> Value {
    fn entry(b: crate::status::AssetBalance) -> Value {
        // Cast i128 → i64 for the wire. Asset amounts in Neurai are i64 from
        // the daemon, so the only way to overflow is a runtime bug; if it
        // happens we cap to i64::MAX to surface obviously broken numbers
        // rather than silently wrapping.
        let to_i64 = |x: i128| -> i64 {
            i64::try_from(x).unwrap_or_else(|_| {
                if x.is_negative() {
                    i64::MIN
                } else {
                    i64::MAX
                }
            })
        };
        json!({"confirmed": to_i64(b.confirmed), "unconfirmed": to_i64(b.unconfirmed)})
    }
    match filter {
        AssetFilter::NativeOnly => entry(balance.native()),
        AssetFilter::One(name) => entry(balance.by_asset.get(name).copied().unwrap_or_default()),
        AssetFilter::All => {
            let mut map = serde_json::Map::new();
            for (k, v) in &balance.by_asset {
                map.insert(k.clone(), entry(*v));
            }
            Value::Object(map)
        }
        AssetFilter::Many {
            include_native,
            assets,
        } => {
            let mut map = serde_json::Map::new();
            if *include_native {
                map.insert(NATIVE_ASSET_KEY.to_string(), entry(balance.native()));
            }
            for name in assets {
                map.insert(
                    name.clone(),
                    entry(balance.by_asset.get(name).copied().unwrap_or_default()),
                );
            }
            Value::Object(map)
        }
    }
}

/// Filter a `Vec<UnspentEntry>` by `AssetFilter` and serialize to JSON.
fn unspent_to_json(entries: Vec<UnspentEntry>, filter: &AssetFilter) -> Value {
    let filtered: Vec<UnspentEntry> = entries
        .into_iter()
        .filter(|e| match filter {
            AssetFilter::NativeOnly => e.asset().is_none(),
            AssetFilter::All => true,
            AssetFilter::One(n) => e.asset() == Some(n.as_str()),
            AssetFilter::Many {
                include_native,
                assets,
            } => match e.asset() {
                None => *include_native,
                Some(name) => assets.contains(name),
            },
        })
        .collect();
    json!(filtered)
}

/// Electrum RPC handler
pub struct Rpc {
    tracker: Tracker,
    cache: Cache,
    rpc_duration: Histogram,
    daemon: Daemon,
    signal: Signal,
    banner: String,
    addr: SocketAddr,
}

impl Rpc {
    /// Perform initial index sync (may take a while on first run).
    pub fn new(config: &Config, metrics: Metrics) -> Result<Self> {
        let rpc_duration = metrics.histogram_vec(
            "rpc_duration",
            "RPC duration (in seconds)",
            "method",
            metrics::default_duration_buckets(),
        );

        let signal = Signal::new();

        // Connect the daemon first so we can fetch the genesis hash for networks
        // where it is epoch-based (testnet, regtest).
        let daemon = Daemon::connect(config, signal.exit_flag(), &metrics)?;

        let genesis_hash = {
            use crate::neurai::NetworkParams;
            use bitcoin::hashes::{sha256d, Hash};
            let params = NetworkParams::for_network(config.network);
            if params.genesis_hash_le == [0u8; 32] {
                // Dynamic genesis (testnet / regtest): fetch from daemon.
                daemon.get_genesis_hash()?
            } else {
                BlockHash::from_raw_hash(
                    sha256d::Hash::from_byte_array(params.genesis_hash_le),
                )
            }
        };

        let tracker = Tracker::new(config, metrics, genesis_hash)?;
        let cache = Cache::new(tracker.metrics());
        Ok(Self {
            tracker,
            cache,
            rpc_duration,
            daemon,
            signal,
            banner: config.server_banner.clone(),
            addr: config.electrum_rpc_addr,
        })
    }

    pub(crate) fn signal(&self) -> &Signal {
        &self.signal
    }

    pub fn new_block_notification(&self) -> Receiver<()> {
        self.daemon.new_block_notification()
    }

    pub fn sync(&mut self) -> Result<bool> {
        self.tracker.sync(&self.daemon, self.signal.exit_flag())
    }

    pub fn update_client(&self, client: &mut Client) -> Result<Vec<String>> {
        let chain = self.tracker.chain();
        let mut notifications = client
            .scripthashes
            .par_iter_mut()
            .filter_map(|(scripthash, status)| -> Option<Result<Value>> {
                match self
                    .tracker
                    .update_scripthash_status(status, &self.daemon, &self.cache)
                {
                    Ok(true) => Some(Ok(notification(
                        "blockchain.scripthash.subscribe",
                        &[json!(scripthash), json!(status.statushash())],
                    ))),
                    Ok(false) => None, // statushash is the same
                    Err(e) => Some(Err(e)),
                }
            })
            .collect::<Result<Vec<Value>>>()
            .context("failed to update status")?;

        if let Some(old_tip) = client.tip {
            let new_tip = self.tracker.chain().tip();
            if old_tip != new_tip {
                client.tip = Some(new_tip);
                let height = chain.height();
                let header = chain.get_block_header(height).unwrap();
                notifications.push(notification(
                    "blockchain.headers.subscribe",
                    &[json!({"hex": serialize_hex(&header), "height": height})],
                ));
            }
        }
        Ok(notifications.into_iter().map(|v| v.to_string()).collect())
    }

    fn headers_subscribe(&self, client: &mut Client) -> Result<Value> {
        let chain = self.tracker.chain();
        client.tip = Some(chain.tip());
        let height = chain.height();
        let header = chain.get_block_header(height).unwrap();
        Ok(json!({"hex": serialize_hex(header), "height": height}))
    }

    fn block_header(&self, (height,): (usize,)) -> Result<Value> {
        let chain = self.tracker.chain();
        let header = match chain.get_block_header(height) {
            None => bail!("no header at {}", height),
            Some(header) => header,
        };
        Ok(json!(serialize_hex(header)))
    }

    fn block_headers(&self, (start_height, count): (usize, usize)) -> Result<Value> {
        let chain = self.tracker.chain();
        let max_count = 2016usize;
        // return only the available block headers
        let end_height = std::cmp::min(
            chain.height() + 1,
            start_height + std::cmp::min(count, max_count),
        );
        let heights = start_height..end_height;
        let count = heights.len();
        let hex_headers =
            heights.filter_map(|height| chain.get_block_header(height).map(serialize_hex));

        Ok(json!({"count": count, "hex": String::from_iter(hex_headers), "max": max_count}))
    }

    fn estimate_fee(&self, (nblocks,): (u16,)) -> Result<Value> {
        Ok(self
            .daemon
            .estimate_fee(nblocks)?
            .map(|fee_rate| json!(fee_rate.to_btc()))
            .unwrap_or_else(|| json!(UNKNOWN_FEE)))
    }

    fn relayfee(&self) -> Result<Value> {
        Ok(json!(self.daemon.get_relay_fee()?.to_btc())) // [BTC/kB]
    }

    fn scripthash_get_balance(
        &self,
        client: &Client,
        args: &ScriptHashWithAsset,
    ) -> Result<Value> {
        let ScriptHashWithAsset { scripthash, asset } = args;
        // Subscription state is independent of the asset filter — the filter
        // is applied to the per-asset Balance map at serialization time, both
        // for already-subscribed and freshly-built status.
        let balance = match client.scripthashes.get(scripthash) {
            Some(status) => self.tracker.get_balance(status),
            None => {
                info!(
                    "{} blockchain.scripthash.get_balance called for unsubscribed scripthash",
                    UNSUBSCRIBED_QUERY_MESSAGE
                );
                self.tracker.get_balance(&self.new_status(*scripthash)?)
            }
        };
        Ok(balance_to_json(&balance, asset))
    }

    fn scripthash_get_history(
        &self,
        client: &Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        let history_entries = match client.scripthashes.get(scripthash) {
            Some(status) => json!(status.get_history()),
            None => {
                info!(
                    "{} blockchain.scripthash.get_history called for unsubscribed scripthash",
                    UNSUBSCRIBED_QUERY_MESSAGE
                );
                json!(self.new_status(*scripthash)?.get_history())
            }
        };
        Ok(history_entries)
    }

    fn scripthash_list_unspent(
        &self,
        client: &Client,
        args: &ScriptHashWithAsset,
    ) -> Result<Value> {
        let ScriptHashWithAsset { scripthash, asset } = args;
        let unspent_entries = match client.scripthashes.get(scripthash) {
            Some(status) => self.tracker.get_unspent(status),
            None => {
                info!(
                    "{} blockchain.scripthash.listunspent called for unsubscribed scripthash",
                    UNSUBSCRIBED_QUERY_MESSAGE
                );
                self.tracker.get_unspent(&self.new_status(*scripthash)?)
            }
        };
        Ok(unspent_to_json(unspent_entries, asset))
    }

    fn scripthash_subscribe(
        &self,
        client: &mut Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        self.scripthashes_subscribe(client, &[*scripthash])
            .next()
            .unwrap()
    }

    fn scripthash_unsubscribe(
        &self,
        client: &mut Client,
        (scripthash,): &(ScriptHash,),
    ) -> Result<Value> {
        let removed = client.scripthashes.remove(scripthash).is_some();
        Ok(json!(removed))
    }

    fn scripthashes_subscribe<'a>(
        &self,
        client: &'a mut Client,
        scripthashes: &'a [ScriptHash],
    ) -> impl Iterator<Item = Result<Value>> + 'a {
        let new_scripthashes: Vec<ScriptHash> = scripthashes
            .iter()
            .copied()
            .filter(|scripthash| !client.scripthashes.contains_key(scripthash))
            .collect();

        let mut results: HashMap<ScriptHash, Result<ScriptHashStatus>> = new_scripthashes
            .into_par_iter()
            .map(|scripthash| (scripthash, self.new_status(scripthash)))
            .collect();

        scripthashes.iter().map(move |scripthash| {
            let statushash = match client.scripthashes.entry(*scripthash) {
                Entry::Occupied(e) => e.get().statushash(),
                Entry::Vacant(e) => {
                    let status = results
                        .remove(scripthash)
                        .expect("missing scripthash status")?; // return an error for failed subscriptions
                    e.insert(status).statushash()
                }
            };
            Ok(json!(statushash))
        })
    }

    fn new_status(&self, scripthash: ScriptHash) -> Result<ScriptHashStatus> {
        let mut status = ScriptHashStatus::new(scripthash);
        self.tracker
            .update_scripthash_status(&mut status, &self.daemon, &self.cache)?;
        Ok(status)
    }

    fn address_get_scripthash(&self, (addr,): &(String,)) -> Result<Value> {
        use crate::neurai::address::address_to_script;
        let script = address_to_script(addr, self.tracker.chain().params())?;
        Ok(json!(ScriptHash::new(&script)))
    }

    fn asset_get_meta(&self, (name,): &(String,)) -> Result<Value> {
        use crate::types::AssetMetaEvent;
        let meta = match self.tracker.get_asset_metadata(name.as_bytes()) {
            Some(m) => m,
            None => return Ok(Value::Null),
        };
        let event = match meta.event {
            AssetMetaEvent::New => "new",
            AssetMetaEvent::Reissue => "reissue",
        };
        let (ipfs_type, ipfs_hash) = match meta.ipfs_marker {
            0x12 => (Some("ipfs"), Some(meta.ipfs_hash.to_lower_hex_string())),
            0x54 => (Some("txid"), Some(meta.ipfs_hash.to_lower_hex_string())),
            _ => (None, None),
        };
        Ok(json!({
            "name": name,
            "event": event,
            "issuance_txid": meta.issuance_txid,
            "issuance_height": meta.issuance_height,
            "amount": meta.amount,
            "units": meta.units,
            "reissuable": meta.reissuable,
            "ipfs_hash": ipfs_hash,
            "ipfs_type": ipfs_type,
        }))
    }

    fn asset_get_history(&self, (name,): &(String,)) -> Result<Value> {
        let history = self.tracker.get_asset_history(name.as_bytes());
        let mut items: Vec<Value> = history
            .confirmed
            .into_iter()
            .map(|entry| {
                // The stored prefix is `txid.as_byte_array()[..8]` — the *first*
                // 8 bytes in consensus (wire / little-endian) order. Electrum
                // clients display txids in the reversed (big-endian) order, so
                // we reverse the prefix before hex-encoding: the emitted string
                // is now the *last* 16 hex characters of the txid as displayed,
                // which clients can match with `tx_hash.ends_with(tx_prefix)`.
                let mut disp = entry.tx_prefix;
                disp.reverse();
                json!({
                    "height": entry.height,
                    "block_hash": entry.block_hash,
                    "tx_prefix": disp.to_lower_hex_string(),
                })
            })
            .collect();
        for entry in history.mempool {
            // Electrum height convention: 0 = unconfirmed / confirmed inputs only,
            // -1 = unconfirmed with unconfirmed inputs.
            let height: i64 = if entry.has_unconfirmed_inputs { -1 } else { 0 };
            items.push(json!({
                "height": height,
                "tx_hash": entry.txid,
                "fee": entry.fee.to_sat(),
            }));
        }
        Ok(json!(items))
    }

    fn transaction_broadcast(&self, (tx_hex,): &(String,)) -> Result<Value> {
        let txid = self.daemon.broadcast(&tx_from_hex(tx_hex)?)?;
        Ok(json!(txid))
    }

    fn transaction_get(&self, args: &TxGetArgs) -> Result<Value> {
        let (txid, verbose) = args.into();
        if verbose {
            // Neurai's `getrawtransaction` has no `blockhash` argument, so a
            // confirmed transaction can't be fetched by txid without `-txindex`.
            // Decode the raw transaction found through our own index instead and
            // add the block fields `getrawtransaction` would have returned.
            return match self.tracker.lookup_transaction(&self.daemon, txid)? {
                Some((blockhash, tx_bytes)) => {
                    let mut info = self.daemon.decode_transaction(&tx_bytes)?;
                    let chain = self.tracker.chain();
                    if let (Some(obj), Some(height)) =
                        (info.as_object_mut(), chain.get_block_height(&blockhash))
                    {
                        obj.insert("hex".into(), json!(tx_bytes.to_lower_hex_string()));
                        obj.insert("blockhash".into(), json!(blockhash));
                        obj.insert("confirmations".into(), json!(chain.height() + 1 - height));
                        if let Some(header) = chain.get_block_header(height) {
                            obj.insert("time".into(), json!(header.time));
                            obj.insert("blocktime".into(), json!(header.time));
                        }
                    }
                    Ok(info)
                }
                None => self.daemon.get_transaction_info(&txid), // mempool
            };
        }
        // if the scripthash was subscribed, tx should be cached
        if let Some(tx_hex) = self
            .cache
            .get_tx(&txid, |tx_bytes| tx_bytes.to_lower_hex_string())
        {
            return Ok(json!(tx_hex));
        }
        debug!("tx cache miss: txid={}", txid);
        // use internal index to load confirmed transaction
        if let Some(tx_hex) = self
            .tracker
            .lookup_transaction(&self.daemon, txid)?
            .map(|(_blockhash, tx)| tx.to_lower_hex_string())
        {
            return Ok(json!(tx_hex));
        }
        // load unconfirmed transaction via RPC
        Ok(json!(self.daemon.get_transaction_hex(&txid)?))
    }

    fn transaction_get_merkle(&self, (txid, height): &(Txid, usize)) -> Result<Value> {
        let chain = self.tracker.chain();
        let blockhash = match chain.get_block_hash(*height) {
            None => bail!("missing block at {}", height),
            Some(blockhash) => blockhash,
        };
        let txids = self.daemon.get_block_txids(blockhash)?;
        match txids.iter().position(|current_txid| *current_txid == *txid) {
            None => bail!("missing txid {} in block {}", txid, blockhash),
            Some(position) => {
                let proof = Proof::create(&txids, position);
                Ok(json!({
                    "block_height": height,
                    "pos": proof.position(),
                    "merkle": proof.to_hex(),
                }))
            }
        }
    }

    fn transaction_from_pos(&self, args: &TxFromPosArgs) -> Result<Value> {
        let (height, tx_pos, merkle) = args.into();
        let chain = self.tracker.chain();
        let blockhash = match chain.get_block_hash(height) {
            None => bail!("missing block at {}", height),
            Some(blockhash) => blockhash,
        };
        let txids = self.daemon.get_block_txids(blockhash)?;
        if tx_pos >= txids.len() {
            bail!("invalid tx_pos {} in block at height {}", tx_pos, height);
        }
        let txid: Txid = txids[tx_pos];
        if merkle {
            let proof = Proof::create(&txids, tx_pos);
            Ok(json!({"tx_hash": txid, "merkle": proof.to_hex()}))
        } else {
            // The protocol specifies a bare transaction hash when `merkle` is false.
            Ok(json!(txid))
        }
    }

    fn get_fee_histogram(&self) -> Result<Value> {
        Ok(json!(self.tracker.fees_histogram()))
    }

    fn server_id(&self) -> String {
        format!("electrs/{}", ELECTRS_VERSION)
    }

    fn version(&self, (client_id, client_version): &(String, VersionRequest)) -> Result<Value> {
        match client_version {
            VersionRequest::Single(exact) => check_between(PROTOCOL_VERSION, exact, exact),
            VersionRequest::MinMax(min, max) => check_between(PROTOCOL_VERSION, min, max),
        }
        .with_context(|| format!("unsupported request {:?} by {}", client_version, client_id))?;
        Ok(json!([self.server_id(), PROTOCOL_VERSION]))
    }

    fn features(&self) -> Result<Value> {
        Ok(json!({
            "genesis_hash": self.tracker.chain().get_block_hash(0),
            "hosts": {
                self.addr.ip().to_string(): {
                    "tcp_port": self.addr.port()
                }
            },
            "protocol_max": PROTOCOL_VERSION,
            "protocol_min": PROTOCOL_VERSION,
            "pruning": null,
            "server_version": self.server_id(),
            "hash_function": "sha256"
        }))
    }

    pub fn handle_requests(&self, client: &mut Client, lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|line| {
                parse_requests(line)
                    .map(Calls::parse)
                    .map_err(error_msg_no_id)
            })
            .map(|calls| self.handle_calls(client, calls).to_string())
            .collect()
    }

    fn handle_calls(&self, client: &mut Client, calls: Result<Calls, Value>) -> Value {
        let calls: Calls = match calls {
            Ok(calls) => calls,
            Err(response) => return response, // JSON parsing failed - the response does not contain request id
        };

        match calls {
            Calls::Batch(batch) => {
                if let Some(result) = self.try_multi_call(client, &batch) {
                    return json!(result);
                }
                json!(batch
                    .into_iter()
                    .map(|result| self.single_call(client, result))
                    .collect::<Vec<Value>>())
            }
            Calls::Single(result) => self.single_call(client, result),
        }
    }

    fn try_multi_call(
        &self,
        client: &mut Client,
        calls: &[Result<Call, Value>],
    ) -> Option<Vec<Value>> {
        // exit if any call failed to parse
        let valid_calls = calls
            .iter()
            .map(|result| result.as_ref().ok())
            .collect::<Option<Vec<&Call>>>()?;

        // only "blockchain.scripthashes.subscribe" are supported
        let scripthashes: Vec<ScriptHash> = valid_calls
            .iter()
            .map(|call| match &call.params {
                Params::ScriptHashSubscribe((scripthash,)) => Some(*scripthash),
                _ => None, // exit if any of the calls is not supported
            })
            .collect::<Option<Vec<ScriptHash>>>()?;

        Some(
            self.rpc_duration
                .observe_duration("blockchain.scripthash.subscribe:multi", || {
                    self.scripthashes_subscribe(client, &scripthashes)
                        .zip(valid_calls)
                        .map(|(result, call)| call.response(result))
                        .collect::<Vec<Value>>()
                }),
        )
    }

    fn single_call(&self, client: &mut Client, call: Result<Call, Value>) -> Value {
        let call = match call {
            Ok(call) => call,
            Err(response) => return response, // params parsing may fail - the response contains request id
        };
        self.rpc_duration.observe_duration(&call.method, || {
            if self.tracker.status().is_err() {
                // Allow only a few RPC (for sync status notification) not requiring index DB being compacted.
                match &call.params {
                    Params::BlockHeader(_)
                    | Params::BlockHeaders(_)
                    | Params::HeadersSubscribe
                    | Params::Version(_) => (),
                    _ => return error_msg(&call.id, RpcError::UnavailableIndex),
                };
            }
            let result = match &call.params {
                Params::AddressGetScripthash(args) => self.address_get_scripthash(args),
                Params::AssetGetMeta(args) => self.asset_get_meta(args),
                Params::AssetGetHistory(args) => self.asset_get_history(args),
                Params::Banner => Ok(json!(self.banner)),
                Params::BlockHeader(args) => self.block_header(*args),
                Params::BlockHeaders(args) => self.block_headers(*args),
                Params::Donation => Ok(Value::Null),
                Params::EstimateFee(args) => self.estimate_fee(*args),
                Params::Features => self.features(),
                Params::HeadersSubscribe => self.headers_subscribe(client),
                Params::MempoolFeeHistogram => self.get_fee_histogram(),
                Params::PeersSubscribe => Ok(json!([])),
                Params::Ping => Ok(Value::Null),
                Params::RelayFee => self.relayfee(),
                Params::ScriptHashGetBalance(args) => self.scripthash_get_balance(client, args),
                Params::ScriptHashGetHistory(args) => self.scripthash_get_history(client, args),
                Params::ScriptHashListUnspent(args) => self.scripthash_list_unspent(client, args),
                Params::ScriptHashSubscribe(args) => self.scripthash_subscribe(client, args),
                Params::ScriptHashUnsubscribe(args) => self.scripthash_unsubscribe(client, args),
                Params::TransactionBroadcast(args) => self.transaction_broadcast(args),
                Params::TransactionGet(args) => self.transaction_get(args),
                Params::TransactionGetMerkle(args) => self.transaction_get_merkle(args),
                Params::TransactionFromPosition(args) => self.transaction_from_pos(args),
                Params::Version(args) => self.version(args),
            };
            call.response(result)
        })
    }
}

#[derive(Deserialize)]
enum Params {
    AddressGetScripthash((String,)),
    AssetGetMeta((String,)),
    AssetGetHistory((String,)),
    Banner,
    BlockHeader((usize,)),
    BlockHeaders((usize, usize)),
    TransactionBroadcast((String,)),
    Donation,
    EstimateFee((u16,)),
    Features,
    HeadersSubscribe,
    MempoolFeeHistogram,
    PeersSubscribe,
    Ping,
    RelayFee,
    ScriptHashGetBalance(ScriptHashWithAsset),
    ScriptHashGetHistory((ScriptHash,)),
    ScriptHashListUnspent(ScriptHashWithAsset),
    ScriptHashSubscribe((ScriptHash,)),
    ScriptHashUnsubscribe((ScriptHash,)),
    TransactionGet(TxGetArgs),
    TransactionGetMerkle((Txid, usize)),
    TransactionFromPosition(TxFromPosArgs),
    Version((String, VersionRequest)),
}

impl Params {
    fn parse(method: &str, params: Value) -> std::result::Result<Params, StandardError> {
        Ok(match method {
            "blockchain.address.get_scripthash" => {
                Params::AddressGetScripthash(convert(params)?)
            }
            "blockchain.asset.get_meta" => Params::AssetGetMeta(convert(params)?),
            "blockchain.asset.get_history" => Params::AssetGetHistory(convert(params)?),
            "blockchain.block.header" => Params::BlockHeader(convert(params)?),
            "blockchain.block.headers" => Params::BlockHeaders(convert(params)?),
            "blockchain.estimatefee" => Params::EstimateFee(convert(params)?),
            "blockchain.headers.subscribe" => Params::HeadersSubscribe,
            "blockchain.relayfee" => Params::RelayFee,
            "blockchain.scripthash.get_balance" => Params::ScriptHashGetBalance(convert(params)?),
            "blockchain.scripthash.get_history" => Params::ScriptHashGetHistory(convert(params)?),
            "blockchain.scripthash.listunspent" => Params::ScriptHashListUnspent(convert(params)?),
            "blockchain.scripthash.subscribe" => Params::ScriptHashSubscribe(convert(params)?),
            "blockchain.scripthash.unsubscribe" => Params::ScriptHashUnsubscribe(convert(params)?),
            "blockchain.transaction.broadcast" => Params::TransactionBroadcast(convert(params)?),
            "blockchain.transaction.get" => Params::TransactionGet(convert(params)?),
            "blockchain.transaction.get_merkle" => Params::TransactionGetMerkle(convert(params)?),
            "blockchain.transaction.id_from_pos" => {
                Params::TransactionFromPosition(convert(params)?)
            }
            "mempool.get_fee_histogram" => Params::MempoolFeeHistogram,
            "server.banner" => Params::Banner,
            "server.donation_address" => Params::Donation,
            "server.features" => Params::Features,
            "server.peers.subscribe" => Params::PeersSubscribe,
            "server.ping" => Params::Ping,
            "server.version" => Params::Version(convert(params)?),
            _ => {
                warn!("unknown method {}", method);
                return Err(StandardError::MethodNotFound);
            }
        })
    }
}

struct Call {
    id: Value,
    method: String,
    params: Params,
}

impl Call {
    fn parse(request: Request) -> Result<Call, Value> {
        match Params::parse(&request.method, request.params) {
            Ok(params) => Ok(Call {
                id: request.id,
                method: request.method,
                params,
            }),
            Err(e) => Err(error_msg(&request.id, RpcError::Standard(e))),
        }
    }

    fn response(&self, result: Result<Value>) -> Value {
        match result {
            Ok(value) => result_msg(&self.id, value),
            Err(err) => {
                warn!("RPC {} failed: {:#}", self.method, err);
                match err
                    .downcast_ref::<bitcoincore_rpc::Error>()
                    .and_then(extract_bitcoind_error)
                {
                    Some(e) => error_msg(&self.id, RpcError::DaemonError(e.clone())),
                    None => error_msg(&self.id, RpcError::BadRequest(err)),
                }
            }
        }
    }
}

enum Calls {
    Batch(Vec<Result<Call, Value>>),
    Single(Result<Call, Value>),
}

impl Calls {
    fn parse(requests: Requests) -> Calls {
        match requests {
            Requests::Single(request) => Calls::Single(Call::parse(request)),
            Requests::Batch(batch) => {
                Calls::Batch(batch.into_iter().map(Call::parse).collect::<Vec<_>>())
            }
        }
    }
}

fn convert<T>(params: Value) -> std::result::Result<T, StandardError>
where
    T: serde::de::DeserializeOwned,
{
    let params_str = params.to_string();
    serde_json::from_value(params).map_err(|err| {
        warn!("invalid params {}: {}", params_str, err);
        StandardError::InvalidParams
    })
}

fn notification(method: &str, params: &[Value]) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

fn result_msg(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn error_msg(id: &Value, error: RpcError) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": error.to_value()})
}

fn error_msg_no_id(err: StandardError) -> Value {
    error_msg(&Value::Null, RpcError::Standard(err))
}

fn parse_requests(line: &str) -> Result<Requests, StandardError> {
    match serde_json::from_str(line) {
        // parse JSON from str
        Ok(value) => match serde_json::from_value(value) {
            // parse RPC from JSON
            Ok(requests) => Ok(requests),
            Err(err) => {
                warn!("invalid RPC request ({:?}): {}", line, err);
                Err(StandardError::InvalidRequest)
            }
        },
        Err(err) => {
            warn!("invalid JSON ({:?}): {}", line, err);
            Err(StandardError::ParseError)
        }
    }
}

fn parse_version(version: &str) -> Result<Version> {
    let result = version
        .split('.')
        .map(|part| usize::from_str(part).with_context(|| format!("invalid version {}", version)))
        .collect::<Result<Vec<usize>>>()?;
    Ok(Version(result))
}

#[derive(PartialOrd, PartialEq, Debug)]
struct Version(Vec<usize>);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, v) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", v)?;
        }
        Ok(())
    }
}

fn check_between(version_str: &str, min_str: &str, max_str: &str) -> Result<()> {
    let version = parse_version(version_str)?;
    let min = parse_version(min_str)?;
    if version < min {
        bail!("version {} < {}", version, min);
    }
    let max = parse_version(max_str)?;
    if version > max {
        bail!("version {} > {}", version, max);
    }
    Ok(())
}

fn tx_from_hex(tx_hex: &str) -> Result<Transaction> {
    let tx_bytes = Vec::from_hex(tx_hex).context("non-hex transaction")?;
    let tx = deserialize(&tx_bytes).context("invalid transaction")?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(parse_version("1").unwrap(), Version(vec![1]));
        assert_eq!(parse_version("1.2").unwrap(), Version(vec![1, 2]));
        assert_eq!(parse_version("1.2.345").unwrap(), Version(vec![1, 2, 345]));

        assert!(parse_version("1.2").unwrap() < parse_version("1.100").unwrap());
    }

    #[test]
    fn test_between() {
        assert!(check_between("1.4", "1.4", "1.4").is_ok());
        assert!(check_between("1.4", "1.4", "1.5").is_ok());
        assert!(check_between("1.4", "1.3", "1.4").is_ok());
        assert!(check_between("1.4", "1.3", "1.5").is_ok());

        assert!(check_between("1.4", "1.5", "1.5").is_err());
        assert!(check_between("1.4", "1.3", "1.3").is_err());
        assert!(check_between("1.4", "1.4.1", "1.5").is_err());
        assert!(check_between("1.4", "1", "1").is_err());
    }

    #[test]
    fn test_tx_from_pos_args() {
        // `merkle` is optional per the protocol, defaulting to false.
        let args: TxFromPosArgs = serde_json::from_str("[630000,68]").unwrap();
        assert_eq!(<(usize, usize, bool)>::from(&args), (630000, 68, false));

        let args: TxFromPosArgs = serde_json::from_str("[630000,68,false]").unwrap();
        assert_eq!(<(usize, usize, bool)>::from(&args), (630000, 68, false));

        let args: TxFromPosArgs = serde_json::from_str("[630000,68,true]").unwrap();
        assert_eq!(<(usize, usize, bool)>::from(&args), (630000, 68, true));

        // Malformed params are still rejected.
        assert!(serde_json::from_str::<TxFromPosArgs>("[630000]").is_err());
        assert!(serde_json::from_str::<TxFromPosArgs>("[]").is_err());
        assert!(serde_json::from_str::<TxFromPosArgs>("[630000,68,1]").is_err());
        assert!(serde_json::from_str::<TxFromPosArgs>("[630000,68,true,1]").is_err());
    }

    #[test]
    fn test_params_id_from_pos() {
        // Both arities are accepted by the method dispatcher.
        for params in ["[630000,68]", "[630000,68,true]"] {
            let parsed = Params::parse(
                "blockchain.transaction.id_from_pos",
                serde_json::from_str(params).unwrap(),
            );
            assert!(
                matches!(parsed, Ok(Params::TransactionFromPosition(_))),
                "failed to parse {params}"
            );
        }
    }

    #[test]
    fn test_requests() {
        assert!(matches!(
            parse_requests("foo"),
            Err(StandardError::ParseError)
        ));
        assert!(matches!(
            parse_requests(r"{}"),
            Err(StandardError::InvalidRequest)
        ));
        assert!(parse_requests(r#"{"id":1,"method":"name","params":[]}"#).is_ok());
        assert!(parse_requests(r#"{"id":1,"method":"name","params":[],"unrelated":42}"#).is_ok());
        assert!(parse_requests(r#" { "id" : 1 , "method" : "name" , "params" : [ ] } "#).is_ok());
    }

    // ─── AssetFilter::from_json ────────────────────────────────────────────────
    //
    // Wire forms accepted (ElectrumX-neurai compatible):
    //   false/null/absent  → NativeOnly
    //   true               → All
    //   "TOKEN"            → One("TOKEN")
    //   [null, "T", ...]   → Many { include_native, assets }
    // Inside an array, only `null` and string are valid; bool / number / etc.
    // are rejected (bool is only valid as the top-level value).

    fn parse_filter(s: &str) -> std::result::Result<AssetFilter, String> {
        let v: Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
        AssetFilter::from_json(&v)
    }

    #[test]
    fn asset_filter_false_is_native_only() {
        assert_eq!(parse_filter("false").unwrap(), AssetFilter::NativeOnly);
    }

    #[test]
    fn asset_filter_null_is_native_only() {
        assert_eq!(parse_filter("null").unwrap(), AssetFilter::NativeOnly);
    }

    #[test]
    fn asset_filter_true_is_all() {
        assert_eq!(parse_filter("true").unwrap(), AssetFilter::All);
    }

    #[test]
    fn asset_filter_string_is_one() {
        assert_eq!(
            parse_filter(r#""TOKEN""#).unwrap(),
            AssetFilter::One("TOKEN".into())
        );
    }

    #[test]
    fn asset_filter_empty_array_is_empty_many() {
        assert_eq!(
            parse_filter("[]").unwrap(),
            AssetFilter::Many {
                include_native: false,
                assets: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn asset_filter_array_assets_only() {
        let assets: BTreeSet<String> =
            ["TOKEN_A".to_string(), "TOKEN_B".to_string()].into_iter().collect();
        assert_eq!(
            parse_filter(r#"["TOKEN_A","TOKEN_B"]"#).unwrap(),
            AssetFilter::Many {
                include_native: false,
                assets,
            }
        );
    }

    #[test]
    fn asset_filter_array_with_null_includes_native() {
        let assets: BTreeSet<String> = ["TOKEN_A".to_string()].into_iter().collect();
        assert_eq!(
            parse_filter(r#"[null,"TOKEN_A"]"#).unwrap(),
            AssetFilter::Many {
                include_native: true,
                assets,
            }
        );
    }

    #[test]
    fn asset_filter_array_just_null() {
        assert_eq!(
            parse_filter("[null]").unwrap(),
            AssetFilter::Many {
                include_native: true,
                assets: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn asset_filter_array_duplicates_deduped() {
        let assets: BTreeSet<String> = ["TOKEN_A".to_string()].into_iter().collect();
        assert_eq!(
            parse_filter(r#"["TOKEN_A","TOKEN_A"]"#).unwrap(),
            AssetFilter::Many {
                include_native: false,
                assets,
            }
        );
    }

    #[test]
    fn asset_filter_array_double_null() {
        // Repeated nulls keep include_native=true (no semantic change).
        assert_eq!(
            parse_filter("[null,null]").unwrap(),
            AssetFilter::Many {
                include_native: true,
                assets: BTreeSet::new(),
            }
        );
    }

    #[test]
    fn asset_filter_number_top_level_rejected() {
        assert!(parse_filter("42").is_err());
    }

    #[test]
    fn asset_filter_bool_inside_array_rejected() {
        // `bool` is only valid as the whole top-level parameter, never as an
        // array element. Wallets that emit `["TOKEN", true]` are malformed.
        assert!(parse_filter(r#"["TOKEN",true]"#).is_err());
    }

    #[test]
    fn asset_filter_number_inside_array_rejected() {
        assert!(parse_filter(r#"["TOKEN",42]"#).is_err());
    }

    // ─── ScriptHashWithAsset deserialization ──────────────────────────────────

    fn parse_args(s: &str) -> std::result::Result<ScriptHashWithAsset, String> {
        let v: Value = serde_json::from_str(s).map_err(|e| e.to_string())?;
        serde_json::from_value(v).map_err(|e| e.to_string())
    }

    /// All-zeros scripthash as a hex string (32 bytes).
    const ZERO_SH: &str = "\"0000000000000000000000000000000000000000000000000000000000000000\"";

    #[test]
    fn scripthash_with_asset_just_scripthash_defaults_to_native() {
        let args = parse_args(&format!("[{ZERO_SH}]")).unwrap();
        assert_eq!(args.asset, AssetFilter::NativeOnly);
    }

    #[test]
    fn scripthash_with_asset_explicit_false() {
        let args = parse_args(&format!("[{ZERO_SH}, false]")).unwrap();
        assert_eq!(args.asset, AssetFilter::NativeOnly);
    }

    #[test]
    fn scripthash_with_asset_explicit_true() {
        let args = parse_args(&format!("[{ZERO_SH}, true]")).unwrap();
        assert_eq!(args.asset, AssetFilter::All);
    }

    #[test]
    fn scripthash_with_asset_single_token() {
        let args = parse_args(&format!("[{ZERO_SH}, \"TOKEN\"]")).unwrap();
        assert_eq!(args.asset, AssetFilter::One("TOKEN".into()));
    }

    #[test]
    fn scripthash_with_asset_array_with_null() {
        let args = parse_args(&format!("[{ZERO_SH}, [null, \"TOKEN\"]]")).unwrap();
        let mut assets = BTreeSet::new();
        assets.insert("TOKEN".to_string());
        assert_eq!(
            args.asset,
            AssetFilter::Many {
                include_native: true,
                assets
            }
        );
    }

    #[test]
    fn scripthash_with_asset_empty_array_rejected() {
        // 0-element arg array doesn't carry the required scripthash.
        assert!(parse_args("[]").is_err());
    }

    #[test]
    fn scripthash_with_asset_too_many_args_rejected() {
        assert!(parse_args(&format!("[{ZERO_SH}, false, \"extra\"]")).is_err());
    }
}
