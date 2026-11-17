use anyhow::{bail, Context, Result};
use bitcoin::{
    consensus::{deserialize, encode::serialize_hex},
    hashes::{hex::FromHex, sha256d, Hash},
    hex::DisplayHex,
    BlockHash, Transaction, Txid,
};
use crossbeam_channel::Receiver;
use parking_lot::Mutex;
use rayon::prelude::*;
use serde_derive::Deserialize;
use serde_json::{self, json, Value};

use std::collections::{hash_map::Entry, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::{
    cache::Cache,
    config::{Config, ELECTRS_VERSION},
    daemon::{self, extract_bitcoind_error, Daemon},
    electrum_assets::AssetSubscriptions,
    merkle::Proof,
    metrics::{self, Histogram, Metrics},
    signals::Signal,
    limits::{waiting, Semaphore},
    status::{
        has_long_history, Balance, ScriptHashStatus, SnapshotSlot, UnspentEntry, UnspentStatus,
        UtxoSnapshot, UtxoSnapshots, NATIVE_ASSET_KEY,
    },
    tracker::Tracker,
    transport::Service,
    types::ScriptHash,
    utxo::{self, Changes, Chunked, MempoolPart, Replies, Sum256, SyncState},
};

/// Protocol range of ElectrumX-neurai (`session.py` `PROTOCOL_MIN`/`PROTOCOL_MAX`).
/// electrum-neurai 0.2.2 asks for exactly "1.0".
const PROTOCOL_MIN: &[i64] = &[1, 0];
const PROTOCOL_MAX: &[i64] = &[1, 4];
/// ElectrumX `MAX_CHUNK_SIZE` for `blockchain.block.headers`.
const MAX_CHUNK_SIZE: usize = 2016;
/// ElectrumX default `MAX_SEND`; `get_history` refuses histories of
/// `MAX_SEND // 99` entries or more with "history too large".
const MAX_SEND: usize = 10_000_000;
const MAX_HISTORY: usize = MAX_SEND / 99;

const UNSUBSCRIBED_QUERY_MESSAGE: &str = "your wallet uses less efficient method of querying electrs, consider contacting the developer of your wallet. Reason:";

/// Heavy queries (UTXO snapshots of long histories) running at once: the
/// others wait, the light ones don't.
const MAX_HEAVY_QUERIES: usize = 2;
/// `blockchain.scripthash.utxo_subscribe` subscriptions of a client (ElectrumX's
/// `MAX_SESSION_SUBS` for `subscribe`).
const MAX_UTXO_SUBSCRIPTIONS: usize = 50_000;

/// Per-client Electrum protocol state
#[derive(Default)]
pub struct Client {
    tip: Option<BlockHash>,
    scripthashes: HashMap<ScriptHash, ScriptHashStatus>,
    utxo_subscriptions: HashMap<ScriptHash, UtxoSubscription>,
    pub(crate) assets: AssetSubscriptions,
    version_sent: bool,
    disconnect: bool,
    /// Some notifications could not be checked (a snapshot was busy).
    notify_again: bool,
}

impl Client {
    /// Set after a reply that must be followed by a disconnect (as ElectrumX
    /// does for an unsupported protocol version).
    pub(crate) fn should_disconnect(&self) -> bool {
        self.disconnect
    }

    /// Whether some notifications are still to be checked.
    pub(crate) fn take_notify_again(&mut self) -> bool {
        std::mem::take(&mut self.notify_again)
    }
}

/// A `blockchain.scripthash.utxo_subscribe` subscription.
struct UtxoSubscription {
    /// For short histories: kept synced, like `blockchain.scripthash.subscribe`
    /// ones. Long histories use the shared `UtxoSnapshot` instead.
    status: Option<ScriptHashStatus>,
    /// The hash of its confirmed set, at the block of `status`.
    set_hash: Option<(BlockHash, Sum256, usize)>,
    /// The status last sent.
    last: Sum256,
}

/// An error with its own JSON-RPC code.
#[derive(Debug)]
struct CodedError {
    code: i64,
    message: String,
}

impl std::fmt::Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodedError {}

/// Error 10 of `doc/utxo-chunks.md`: the client starts again with `utxo_sync`.
fn snapshot_expired() -> anyhow::Error {
    CodedError {
        code: 10,
        message: "snapshot expired".into(),
    }
    .into()
}

/// What `Rpc::snapshot_of` found.
enum SnapshotOf<T> {
    Done(T),
    /// A short history: no snapshot.
    Short,
    /// Another query is busy with the snapshot (only when not waiting).
    Busy,
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
    Coded(i64, String),
}

impl RpcError {
    fn to_value(&self) -> Value {
        match self {
            RpcError::Standard(err) => match err {
                StandardError::ParseError => json!({"code": -32700, "message": "invalid JSON"}),
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
            // Same text as ElectrumX: `f'daemon error: {e!r}'` of a DaemonError(dict).
            RpcError::DaemonError(err) => json!({
                "code": 2,
                "message": format!(
                    "daemon error: DaemonError({{'code': {}, 'message': {}}})",
                    err.code,
                    py_repr(&json!(err.message))
                ),
            }),
            RpcError::UnavailableIndex => {
                // Internal JSON-RPC error (https://www.jsonrpc.org/specification#error_object)
                json!({"code": -32603, "message": "unavailable index"})
            }
            RpcError::Coded(code, message) => json!({"code": code, "message": message}),
        }
    }
}

// ─── Python-compatible argument handling ─────────────────────────────────────
//
// ElectrumX validates arguments in Python and answers with BAD_REQUEST (code 1)
// and specific messages; the helpers below reproduce those checks and texts.

/// `str(value)` of the Python object JSON-decoded from `value`.
pub(crate) fn py_str(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => py_repr(other),
    }
}

/// `repr(value)` of the Python object JSON-decoded from `value`.
pub(crate) fn py_repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
            let mut out = String::with_capacity(s.len() + 2);
            out.push(quote);
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c => out.push(c),
                }
            }
            out.push(quote);
            out
        }
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(py_repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}: {}", py_repr(&json!(k)), py_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Python `f'{n:,d}'`.
pub(crate) fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// ElectrumX `non_negative_integer`: `int(value)` must succeed and be ≥ 0.
pub(crate) fn non_negative_integer(value: &Value) -> Result<u64> {
    let parsed: Option<i128> = match value {
        Value::Bool(b) => Some(i128::from(*b)),
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
            .or_else(|| n.as_f64().filter(|f| f.is_finite()).map(|f| f.trunc() as i128)),
        Value::String(s) => s.trim().replace('_', "").parse::<i128>().ok(),
        _ => None,
    };
    match parsed {
        Some(n) if n >= 0 && n <= i128::from(u64::MAX) => Ok(n as u64),
        _ => bail!("{} should be a non-negative integer", py_str(value)),
    }
}

/// `hex_str_to_hash`: 64 hex chars, display order → internal order.
fn hex_hash(value: &Value) -> Option<[u8; 32]> {
    let s = value.as_str()?;
    let mut bytes = <[u8; 32]>::from_hex(s).ok()?;
    bytes.reverse();
    Some(bytes)
}

pub(crate) fn parse_scripthash(value: &Value) -> Result<ScriptHash> {
    match hex_hash(value) {
        Some(bytes) => Ok(ScriptHash::from_byte_array(bytes)),
        None => bail!("{} is not a valid script hash", py_str(value)),
    }
}

fn parse_block_hash(value: &Value) -> Result<BlockHash> {
    match hex_hash(value) {
        Some(bytes) => Ok(BlockHash::from_byte_array(bytes)),
        None => bail!("{} is not a valid block hash", py_str(value)),
    }
}

pub(crate) fn assert_tx_hash(value: &Value) -> Result<Txid> {
    match hex_hash(value) {
        Some(bytes) => Ok(Txid::from_byte_array(bytes)),
        None => bail!("{} should be a transaction hash", py_str(value)),
    }
}

/// ElectrumX `check_asset`.
/// Longest asset name accepted by [`check_asset`]: ElectrumX's 32 characters,
/// raised for the network when the RPC handler is created.
static MAX_ASSET_NAME_LEN: AtomicUsize = AtomicUsize::new(32);

pub(crate) fn check_asset(value: &Value) -> Result<String> {
    let max_len = MAX_ASSET_NAME_LEN.load(Ordering::Relaxed);
    match value {
        Value::String(name) if name.is_empty() => bail!("asset name is empty!"),
        Value::String(name) if name.len() > max_len => {
            bail!("asset name greater than {} characters", max_len)
        }
        Value::String(name) => Ok(name.clone()),
        other => bail!(
            "the asset name must be a string ({}; {})",
            py_repr(other),
            py_class(other)
        ),
    }
}

/// ElectrumX `check_h160`.
pub(crate) fn check_h160(value: &Value) -> Result<[u8; 20]> {
    let s = match value.as_str() {
        Some(s) => s,
        None => bail!("the h160 must be a string"),
    };
    if s.len() != 40 {
        bail!("h160 not 20 bytes");
    }
    <[u8; 20]>::from_hex(s).map_err(|_| anyhow!("non-hexadecimal number found in fromhex() arg"))
}

/// `<class 'str'>`-style class repr of a decoded JSON value.
fn py_class(value: &Value) -> &'static str {
    match value {
        Value::Null => "<class 'NoneType'>",
        Value::Bool(_) => "<class 'bool'>",
        Value::Number(n) if n.is_f64() => "<class 'float'>",
        Value::Number(_) => "<class 'int'>",
        Value::String(_) => "<class 'str'>",
        Value::Array(_) => "<class 'list'>",
        Value::Object(_) => "<class 'dict'>",
    }
}

pub(crate) fn require_bool(value: Option<&Value>, default: bool, name: &str) -> Result<bool> {
    match value {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        // Python `x in (True, False)` also accepts 0 and 1
        Some(Value::Number(n)) if n.as_u64() == Some(0) => Ok(false),
        Some(Value::Number(n)) if n.as_u64() == Some(1) => Ok(true),
        Some(_) => bail!("\"{}\" must be a boolean", name),
    }
}

/// Python truthiness, for flags ElectrumX never type-checks (`include_mempool`).
pub(crate) fn truthy(value: Option<&Value>, default: bool) -> bool {
    match value {
        None => default,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// Request params after applying an ElectrumX handler signature: positional
/// (array) or named (object) arguments, `None` where not supplied.
pub(crate) struct Args(Vec<Option<Value>>);

impl Args {
    fn parse(params: Value, names: &[&str], required: usize) -> std::result::Result<Self, StandardError> {
        let mut slots: Vec<Option<Value>> = match params {
            Value::Null => vec![],
            Value::Array(values) => {
                if values.len() > names.len() {
                    return Err(StandardError::InvalidParams);
                }
                values.into_iter().map(Some).collect()
            }
            Value::Object(map) => {
                let mut slots = vec![None; names.len()];
                for (key, value) in map {
                    match names.iter().position(|name| *name == key) {
                        Some(i) => slots[i] = Some(value),
                        None => return Err(StandardError::InvalidParams),
                    }
                }
                slots
            }
            _ => return Err(StandardError::InvalidParams),
        };
        slots.resize(names.len(), None);
        if slots[..required].iter().any(Option::is_none) {
            return Err(StandardError::InvalidParams);
        }
        Ok(Args(slots))
    }

    pub(crate) fn get(&self, i: usize) -> Option<&Value> {
        self.0.get(i).and_then(Option::as_ref)
    }

    pub(crate) fn req(&self, i: usize) -> &Value {
        self.get(i).expect("required arguments are checked by Args::parse")
    }
}

/// ElectrumX `util.protocol_tuple`.
fn protocol_tuple(value: &Value) -> Vec<i64> {
    value
        .as_str()
        .and_then(|s| {
            s.split('.')
                .map(|part| part.trim().parse::<i64>().ok())
                .collect::<Option<Vec<i64>>>()
        })
        .unwrap_or_else(|| vec![0])
}

/// ElectrumX `util.protocol_version`: the negotiated version, if any.
fn negotiate_protocol(request: &Value) -> Option<Vec<i64>> {
    let (client_min, client_max) = match request {
        Value::Null => (PROTOCOL_MIN.to_vec(), PROTOCOL_MIN.to_vec()),
        Value::Array(pair) if pair.len() == 2 => (protocol_tuple(&pair[0]), protocol_tuple(&pair[1])),
        other => (protocol_tuple(other), protocol_tuple(other)),
    };
    let result = std::cmp::min(client_max, PROTOCOL_MAX.to_vec());
    let floor = std::cmp::max(client_min, PROTOCOL_MIN.to_vec());
    if result < floor || result == [0] {
        return None;
    }
    Some(result)
}

/// ElectrumX `util.version_string`.
fn version_string(version: &[i64]) -> String {
    let mut parts: Vec<String> = version.iter().map(i64::to_string).collect();
    while parts.len() < 2 {
        parts.push("0".into());
    }
    parts.join(".")
}

/// ElectrumX `Coin.bucket_estimatefee_block_target`.
fn bucket_estimatefee_block_target(n: u64) -> u64 {
    match n {
        0..=1 => 1,
        2..=12 => n,
        25 => n,
        13..=48 => n / 2 * 2,
        49..=1008 => n / 24 * 24,
        _ => 1008,
    }
}

/// Merkle branch and root over `hashes` (internal byte order), as ElectrumX
/// `Merkle.branch_and_root`. In TSC format, a duplicated last node is `None`.
pub(crate) fn merkle_branch_and_root(
    mut hashes: Vec<[u8; 32]>,
    mut index: usize,
    tsc_format: bool,
) -> (Vec<Option<[u8; 32]>>, [u8; 32]) {
    assert!(index < hashes.len());
    let mut branch = vec![];
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().unwrap());
            let is_last = index ^ 1 == hashes.len() - 1;
            if tsc_format && is_last {
                branch.push(None);
            } else {
                branch.push(Some(hashes[index ^ 1]));
            }
        } else {
            branch.push(Some(hashes[index ^ 1]));
        }
        index >>= 1;
        hashes = hashes
            .chunks(2)
            .map(|pair| sha256d::Hash::hash(&[pair[0], pair[1]].concat()).to_byte_array())
            .collect();
    }
    (branch, hashes[0])
}

fn display_hex(hash: &[u8; 32]) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    reversed.to_lower_hex_string()
}

/// Optional `asset` parameter for `scripthash.get_balance` / `scripthash.listunspent`.
///
/// Wire forms (ElectrumX-neurai `session.py` `get_balance` / `hashX_listunspent`):
/// * `false`               → `NativeOnly`
/// * `true`                → `All`
/// * string `"TOKEN"`      → `One("TOKEN")`
/// * list `[null, "A"]`    → `Many { include_native: true, assets: {"A"} }`
///   (a JSON object is iterated by key, like a Python dict)
///
/// `null` is accepted by `listunspent` (mapped to `false`) but not by `get_balance`.
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

impl AssetFilter {
    fn from_json(value: &Value) -> Result<Self> {
        let many = |items: Vec<&Value>| -> Result<AssetFilter> {
            let mut include_native = false;
            let mut assets = BTreeSet::new();
            for item in items {
                match item {
                    Value::Null => include_native = true,
                    other => {
                        assets.insert(check_asset(other)?);
                    }
                }
            }
            Ok(AssetFilter::Many {
                include_native,
                assets,
            })
        };
        match value {
            Value::Bool(false) => Ok(AssetFilter::NativeOnly),
            Value::Bool(true) => Ok(AssetFilter::All),
            Value::String(_) => Ok(AssetFilter::One(check_asset(value)?)),
            Value::Array(items) => many(items.iter().collect()),
            Value::Object(map) => {
                let keys: Vec<Value> = map.keys().map(|k| json!(k)).collect();
                many(keys.iter().collect())
            }
            _ => bail!("asset must be a list, string, or boolean"),
        }
    }
}

/// Format a `Balance` as JSON shaped by the requested `AssetFilter`.
///
/// * `NativeOnly` / `One(_)` → flat `{"confirmed": N, "unconfirmed": M}`
/// * `All` / `Many { .. }`   → map `{"rvn": {...}, "TOKEN": {...}}`
fn balance_to_json(balance: &Balance, filter: &AssetFilter) -> Value {
    fn entry(b: crate::status::AssetBalance) -> Value {
        // Cast i128 → i64 for the wire. Asset amounts in Neurai are i64 from
        // the daemon, so the only way to overflow is a runtime bug; if it
        // happens we cap to i64::MAX to surface obviously broken numbers
        // rather than silently wrapping.
        let to_i64 = |x: i128| -> i64 {
            i64::try_from(x).unwrap_or(if x.is_negative() { i64::MIN } else { i64::MAX })
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

/// One advertised service (`server.features` `hosts` / `services`).
#[derive(Clone, Debug)]
pub(crate) struct ReportedService {
    service: Service,
    host: String,
    port: u16,
}

fn parse_report_services(spec: &str, listeners: &[(Service, SocketAddr)]) -> Result<Vec<ReportedService>> {
    if spec.trim().is_empty() {
        return Ok(listeners
            .iter()
            .map(|(service, addr)| ReportedService {
                service: *service,
                host: addr.ip().to_string(),
                port: addr.port(),
            })
            .collect());
    }
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|item| {
            let (scheme, rest) = item
                .split_once("://")
                .with_context(|| format!("invalid service {:?} (expected proto://host:port)", item))?;
            let service = Service::from_scheme(scheme)
                .with_context(|| format!("unknown service protocol {:?}", scheme))?;
            let (host, port) = rest
                .rsplit_once(':')
                .with_context(|| format!("missing port in service {:?}", item))?;
            let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
            let port = port
                .parse()
                .with_context(|| format!("invalid port in service {:?}", item))?;
            Ok(ReportedService {
                service,
                host,
                port,
            })
        })
        .collect()
}

/// `(bucketed block target, mode)`
type EstimateFeeKey = (u64, Option<String>);

/// UTXO snapshots saved by the previous run (see `Rpc::drop`).
fn load_utxo_snapshots(tracker: &Tracker) -> UtxoSnapshots {
    let snapshots = UtxoSnapshots::default();
    let rows = tracker.index().store().utxo_snapshots();
    let count = rows.len();
    for (scripthash, value) in rows {
        match UtxoSnapshot::from_bytes(ScriptHash::from_byte_array(scripthash), &value) {
            Some(snapshot) => snapshots.insert(snapshot),
            None => warn!("ignoring an unreadable UTXO snapshot"),
        }
    }
    if count > 0 {
        info!("loaded {} UTXO snapshots", count);
    }
    snapshots
}

/// Electrum RPC handler
pub struct Rpc {
    pub(crate) tracker: Tracker,
    cache: Cache,
    rpc_duration: Histogram,
    pub(crate) daemon: Daemon,
    signal: Signal,
    banner: String,
    donation_address: String,
    services: Vec<ReportedService>,
    estimatefee_cache: Mutex<HashMap<EstimateFeeKey, (BlockHash, f64)>>,
    /// Broadcast candidates already checked against their transaction inputs.
    pub(crate) broadcast_checks: Mutex<HashMap<(Txid, u32), bool>>,
    /// UTXOs of the scripthashes with long histories, shared by all clients.
    utxo_snapshots: UtxoSnapshots,
    /// `utxo_sync` replies of several chunks, shared by all clients.
    utxo_replies: Replies,
    heavy_queries: Semaphore,
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

        let (genesis_hash, genesis_header) = {
            use crate::neurai::NetworkParams;
            let params = NetworkParams::for_network(config.network);
            MAX_ASSET_NAME_LEN.store(params.max_asset_name_len(), Ordering::Relaxed);
            if params.genesis_hash_le == [0u8; 32] {
                // Dynamic genesis (testnet / regtest): fetch from daemon.
                daemon.get_genesis(params)?
            } else {
                (
                    BlockHash::from_raw_hash(sha256d::Hash::from_byte_array(params.genesis_hash_le)),
                    crate::chain::Chain::params_genesis_header(params),
                )
            }
        };

        let services = parse_report_services(
            &config.report_services,
            &crate::server::listeners(config),
        )
        .context("invalid report_services")?;

        let tracker = Tracker::new(config, metrics, genesis_hash, genesis_header)?;
        let cache = Cache::new(tracker.metrics());
        let utxo_snapshots = load_utxo_snapshots(&tracker);
        Ok(Self {
            tracker,
            cache,
            rpc_duration,
            daemon,
            signal,
            banner: config.server_banner.clone(),
            donation_address: config.donation_address.clone(),
            services,
            estimatefee_cache: Mutex::new(HashMap::new()),
            broadcast_checks: Mutex::new(HashMap::new()),
            utxo_snapshots,
            utxo_replies: Replies::default(),
            heavy_queries: Semaphore::new(MAX_HEAVY_QUERIES),
        })
    }

    pub(crate) fn signal(&self) -> &Signal {
        &self.signal
    }

    pub fn new_block_notification(&self) -> Receiver<()> {
        self.daemon.new_block_notification()
    }

    pub fn sync(&self) -> Result<bool> {
        self.tracker.sync(&self.daemon, self.signal.exit_flag())
    }

    /// Saves the UTXO snapshots for the next run, which then only reads the
    /// blocks found since. Runs on every exit of `server::serve`.
    pub(crate) fn save_utxo_snapshots(&self) {
        let mut rows = Vec::new();
        self.utxo_snapshots
            .for_each(|s| rows.push((s.scripthash().to_byte_array(), s.to_bytes())));
        let count = rows.len();
        self.tracker
            .index()
            .store()
            .set_utxo_snapshots(rows.into_iter());
        info!("saved {} UTXO snapshots", count);
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

        notifications.extend(self.update_asset_subscriptions(&mut client.assets)?);

        let mut notify_again = false;
        for (scripthash, subscription) in client.utxo_subscriptions.iter_mut() {
            match self.update_utxo_subscription(*scripthash, subscription)? {
                SnapshotOf::Done(Some(status)) => notifications.push(notification(
                    "blockchain.scripthash.utxo_subscribe",
                    &[json!(scripthash), json!(status.to_hex())],
                )),
                SnapshotOf::Done(None) => (),
                // another query is updating it: look again later
                SnapshotOf::Busy => notify_again = true,
                // its snapshot became too large to keep: the next query builds it
                SnapshotOf::Short => notify_again = true,
            }
        }
        client.notify_again |= notify_again;

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

    fn raw_header_hex(&self, height: u64) -> Result<String> {
        let chain = self.tracker.chain();
        match usize::try_from(height).ok().and_then(|h| chain.get_block_header(h)) {
            Some(header) => Ok(serialize_hex(header)),
            None => bail!("height {} out of range", commas(height)),
        }
    }

    /// ElectrumX `_merkle_proof`: branch and root of the header hashes
    /// `0..=cp_height` proving the header at `height`.
    fn header_merkle_proof(&self, cp_height: u64, height: u64) -> Result<serde_json::Map<String, Value>> {
        let chain = self.tracker.chain();
        let max_height = chain.height() as u64;
        if !(height <= cp_height && cp_height <= max_height) {
            bail!(
                "require header height {} <= cp_height {} <= chain height {}",
                commas(height),
                commas(cp_height),
                commas(max_height)
            );
        }
        let hashes: Vec<[u8; 32]> = (0..=cp_height as usize)
            .map(|h| chain.get_block_hash(h).expect("height <= tip").to_byte_array())
            .collect();
        let (branch, root) = merkle_branch_and_root(hashes, height as usize, false);
        let mut result = serde_json::Map::new();
        result.insert(
            "branch".into(),
            json!(branch.iter().map(|h| display_hex(&h.expect("not TSC"))).collect::<Vec<_>>()),
        );
        result.insert("root".into(), json!(display_hex(&root)));
        Ok(result)
    }

    fn block_header(&self, args: &Args) -> Result<Value> {
        let height = non_negative_integer(args.req(0))?;
        let cp_height = args.get(1).map(non_negative_integer).transpose()?.unwrap_or(0);
        let header = self.raw_header_hex(height)?;
        if cp_height == 0 {
            return Ok(json!(header));
        }
        let mut result = serde_json::Map::new();
        result.insert("header".into(), json!(header));
        result.extend(self.header_merkle_proof(cp_height, height)?);
        Ok(Value::Object(result))
    }

    fn block_headers(&self, args: &Args) -> Result<Value> {
        let start_height = non_negative_integer(args.req(0))?;
        let count = non_negative_integer(args.req(1))?;
        let cp_height = args.get(2).map(non_negative_integer).transpose()?.unwrap_or(0);
        let chain = self.tracker.chain();
        let count = std::cmp::min(count, MAX_CHUNK_SIZE as u64) as usize;
        let mut hex = String::new();
        let mut returned = 0usize;
        if let Ok(start) = usize::try_from(start_height) {
            for height in start..start.saturating_add(count) {
                match chain.get_block_header(height) {
                    Some(header) => {
                        hex.push_str(&serialize_hex(header));
                        returned += 1;
                    }
                    None => break,
                }
            }
        }
        let mut result = serde_json::Map::new();
        result.insert("hex".into(), json!(hex));
        result.insert("count".into(), json!(returned));
        result.insert("max".into(), json!(MAX_CHUNK_SIZE));
        if returned > 0 && cp_height > 0 {
            result.extend(self.header_merkle_proof(cp_height, start_height + returned as u64 - 1)?);
        }
        Ok(Value::Object(result))
    }

    fn estimate_fee(&self, args: &Args) -> Result<Value> {
        let number = non_negative_integer(args.req(0))?;
        let mode = match args.get(1) {
            None | Some(Value::Null) => None,
            Some(Value::String(m)) if m == "CONSERVATIVE" || m == "ECONOMICAL" => Some(m.clone()),
            Some(other) => bail!("unknown estimatefee mode: {}", py_str(other)),
        };
        let number = bucket_estimatefee_block_target(number);
        let tip = self.tracker.chain().tip();
        let key = (number, mode.clone());
        if let Some((blockhash, feerate)) = self.estimatefee_cache.lock().get(&key) {
            if *blockhash == tip {
                return Ok(json!(feerate));
            }
        }
        let feerate = match self.daemon.estimate_smart_fee(number, mode.as_deref())? {
            Some(feerate) => feerate,
            // no estimate available: ElectrumX falls back to the relay fee
            None => self.relay_fee_value()?,
        };
        self.estimatefee_cache.lock().insert(key, (tip, feerate));
        Ok(json!(feerate))
    }

    fn relay_fee_value(&self) -> Result<f64> {
        self.daemon
            .get_network_info_raw()?
            .get("relayfee")
            .and_then(Value::as_f64)
            .context("getnetworkinfo has no relayfee")
    }

    fn relayfee(&self) -> Result<Value> {
        Ok(json!(self.relay_fee_value()?)) // [XNA/kB]
    }

    fn status_of(&self, client: &Client, scripthash: ScriptHash, method: &str) -> Result<ScriptHashStatus> {
        let _ = client;
        info!(
            "{} {} called for unsubscribed scripthash",
            UNSUBSCRIBED_QUERY_MESSAGE, method
        );
        self.new_status(scripthash)
    }

    fn scripthash_get_balance(&self, client: &Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        let filter = match args.get(1) {
            None => AssetFilter::NativeOnly,
            Some(value) => AssetFilter::from_json(value)?,
        };
        let balance = match client.scripthashes.get(&scripthash) {
            Some(status) => self.tracker.get_balance(status),
            None => self
                .unspent_status_of(client, scripthash, "blockchain.scripthash.get_balance")?
                .balance()
                .clone(),
        };
        Ok(balance_to_json(&balance, &filter))
    }

    fn history_json(&self, status: &ScriptHashStatus) -> Result<Value> {
        let history = status.get_history();
        if history.len() >= MAX_HISTORY {
            bail!("history too large");
        }
        Ok(json!(history))
    }

    fn scripthash_get_history(&self, client: &Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        match client.scripthashes.get(&scripthash) {
            Some(status) => self.history_json(status),
            None => {
                self.check_history_size(scripthash)?;
                self.history_json(&self.status_of(
                    client,
                    scripthash,
                    "blockchain.scripthash.get_history",
                )?)
            }
        }
    }

    /// Like ElectrumX, whatever the size of the confirmed history.
    fn scripthash_get_mempool(&self, client: &Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        match client.scripthashes.get(&scripthash) {
            Some(status) => {
                let entries: Vec<&crate::status::HistoryEntry> = status
                    .get_history()
                    .iter()
                    .filter(|e| e.is_unconfirmed())
                    .collect();
                Ok(json!(entries))
            }
            None => Ok(json!(self
                .unspent_status_of(client, scripthash, "blockchain.scripthash.get_mempool")?
                .mempool_history())),
        }
    }

    /// ElectrumX refuses histories of `MAX_HISTORY` transactions or more. Every
    /// block with an output to the scripthash adds at least one, so the index
    /// tells about the longest ones before their blocks are downloaded.
    fn check_history_size(&self, scripthash: ScriptHash) -> Result<()> {
        let height = self.tracker.chain().height();
        let blocks = self
            .tracker
            .index()
            .funding_heights(scripthash)
            .filter(|&h| h <= height)
            .take(MAX_HISTORY)
            .count();
        if blocks >= MAX_HISTORY {
            bail!("history too large");
        }
        Ok(())
    }

    /// Unspent outputs, balance and mempool history of an unsubscribed
    /// scripthash. Those of long histories are kept in `utxo_snapshots`, so
    /// that the next queries only read the blocks found since.
    fn unspent_status_of(
        &self,
        client: &Client,
        scripthash: ScriptHash,
        method: &str,
    ) -> Result<UnspentStatus> {
        let found = self.snapshot_of(scripthash, true, method, |snapshot| {
            snapshot.unspent_status(&self.tracker.mempool(), &self.cache)
        })?;
        if let SnapshotOf::Done(status) = found {
            return Ok(status);
        }
        let status = self.status_of(client, scripthash, method)?;
        let chain = self.tracker.chain();
        self.keep_long_history(&status, &chain);
        Ok(status.unspent_status(&chain, &self.tracker.mempool()))
    }

    /// Keeps a snapshot of `status` if its history is long.
    fn keep_long_history(&self, status: &ScriptHashStatus, chain: &crate::chain::Chain) {
        if let Some(mut snapshot) = UtxoSnapshot::of_long_history(status, chain) {
            self.save_utxo_snapshot(&mut snapshot);
            let slot = self.utxo_snapshots.slot(snapshot.scripthash());
            let mut guard = waiting(|| slot.snapshot.lock());
            if guard.is_none() {
                *guard = Some(snapshot);
                self.utxo_snapshots.update(&slot, &guard);
            }
        }
    }

    /// Runs `f` on the up-to-date `UtxoSnapshot` of `scripthash`, building it
    /// first for a long history. Only one query builds or updates a snapshot:
    /// the others wait for it, or get `Busy` when not `wait`ing.
    fn snapshot_of<T>(
        &self,
        scripthash: ScriptHash,
        wait: bool,
        method: &str,
        f: impl FnOnce(&mut UtxoSnapshot) -> T,
    ) -> Result<SnapshotOf<T>> {
        let index = self.tracker.index();
        if !self.utxo_snapshots.contains(&scripthash) && !has_long_history(index, scripthash) {
            return Ok(SnapshotOf::Short);
        }
        let slot = self.utxo_snapshots.slot(scripthash);
        let mut guard = if wait {
            waiting(|| slot.snapshot.lock())
        } else {
            match slot.snapshot.try_lock() {
                Some(guard) => guard,
                None => return Ok(SnapshotOf::Busy),
            }
        };
        if !self.refresh_snapshot(&slot, &mut guard, scripthash, method)? {
            return Ok(SnapshotOf::Short);
        }
        Ok(SnapshotOf::Done(f(guard.as_mut().expect("refreshed"))))
    }

    /// Brings the snapshot of `slot` up to date, building it if needed.
    /// `false` for a short history.
    fn refresh_snapshot(
        &self,
        slot: &SnapshotSlot,
        snapshot: &mut Option<UtxoSnapshot>,
        scripthash: ScriptHash,
        method: &str,
    ) -> Result<bool> {
        let index = self.tracker.index();
        if let Some(current) = snapshot.as_mut() {
            if current.update(index, &self.daemon)? {
                if current.save_due() {
                    self.save_utxo_snapshot(current);
                }
                self.utxo_snapshots.update(slot, snapshot);
                return Ok(snapshot.is_some());
            }
            *snapshot = None; // rebuilt below
        }
        if !has_long_history(index, scripthash) {
            self.utxo_snapshots.update(slot, snapshot);
            return Ok(false);
        }
        info!(
            "{} {} called for unsubscribed scripthash",
            UNSUBSCRIBED_QUERY_MESSAGE, method
        );
        let mut built = {
            let _permit = self.heavy_queries.acquire();
            UtxoSnapshot::build(scripthash, index, &self.daemon)?
        };
        self.save_utxo_snapshot(&mut built);
        *snapshot = Some(built);
        self.utxo_snapshots.update(slot, snapshot);
        // too large to keep: answered once anyway
        Ok(true)
    }

    // ─── Chunked UTXO sets (doc/utxo-chunks.md) ─────────────────────────────

    fn scripthash_utxo_sync(&self, client: &mut Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        let from = match args.get(1) {
            None | Some(Value::Null) => None,
            Some(value) => Some(parse_block_hash(value)?),
        };
        let method = "blockchain.scripthash.utxo_sync";
        // long histories: the shared snapshot and its journal
        let found = self.snapshot_of(scripthash, true, method, |snapshot| {
            let from_block = from.filter(|from| snapshot.knows(from));
            let state = SyncState {
                from_block,
                height: snapshot.tip_height(),
                block_hash: snapshot.tip(),
                count: snapshot.count(),
                set_hash: snapshot.set_hash(),
            };
            let mempool = snapshot.mempool_part(&self.tracker.mempool());
            let id = utxo::reply_id(scripthash, from_block, state.block_hash);
            // computed once for every client asking the same
            let changes = match self.utxo_replies.get(&id) {
                Some(_) => None,
                None => Some(match from_block {
                    Some(from) => snapshot.changes_since(&from).expect("known: knows() said so"),
                    None => Changes {
                        removed: Vec::new(),
                        added: snapshot.utxo_list(),
                    },
                }),
            };
            (state, mempool, id, changes)
        })?;
        if let SnapshotOf::Done((state, mempool, id, changes)) = found {
            return Ok(self.utxo_sync_reply(scripthash, id, state, changes, mempool));
        }

        // short histories: from their status, synced with this chain
        let chain = self.tracker.chain();
        let fresh;
        let status = match client
            .utxo_subscriptions
            .get_mut(&scripthash)
            .and_then(|sub| sub.status.as_mut())
        {
            Some(status) => {
                self.tracker
                    .update_scripthash_status_on(status, &chain, &self.daemon, &self.cache)?;
                &*status
            }
            None => {
                fresh = self.new_status_on(scripthash, &chain)?;
                &fresh
            }
        };
        let block_hash = status.tip();
        let height = chain
            .get_block_height(&block_hash)
            .context("synced with another chain")?;
        let now = status.utxos_at(&chain, Some(height));
        let from_height = from
            .and_then(|from| chain.get_block_height(&from))
            .filter(|from| *from <= height);
        let (from_block, changes) = match from_height {
            Some(from_height) => (
                from,
                Changes::between(&status.utxos_at(&chain, Some(from_height)), &now),
            ),
            None => (
                None,
                Changes {
                    removed: Vec::new(),
                    added: now.values().cloned().collect(),
                },
            ),
        };
        let state = SyncState {
            from_block,
            height,
            block_hash,
            count: now.len(),
            set_hash: utxo::set_hash(now.values()),
        };
        let mempool = status.mempool_part(&chain);
        let id = utxo::reply_id(scripthash, from_block, block_hash);
        Ok(self.utxo_sync_reply(scripthash, id, state, Some(changes), mempool))
    }

    /// The reply to `utxo_sync`: inline for a single chunk, otherwise kept for
    /// `utxo_chunk` (`changes` is `None` when it is already kept).
    fn utxo_sync_reply(
        &self,
        scripthash: ScriptHash,
        id: String,
        state: SyncState,
        changes: Option<Changes>,
        mempool: MempoolPart,
    ) -> Value {
        if let Some(kept) = self.utxo_replies.get(&id) {
            return utxo::sync_reply(&kept.state, Some(&id), &kept.hashes, None, &mempool);
        }
        let changes = changes.unwrap_or_default(); // dropped meanwhile: not likely
        let (chunks, hashes) = utxo::split(changes, utxo::CHUNK_BYTES);
        if chunks.len() == 1 {
            return utxo::sync_reply(&state, None, &hashes, chunks.first(), &mempool);
        }
        let reply = utxo::sync_reply(&state, Some(&id), &hashes, None, &mempool);
        self.utxo_replies.put(Arc::new(Chunked {
            id,
            scripthash,
            state,
            chunks,
            hashes,
        }));
        reply
    }

    fn scripthash_utxo_chunk(&self, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        let id = match args.req(1) {
            Value::String(id) => id,
            other => bail!("{} is not a valid id", py_str(other)),
        };
        let index = non_negative_integer(args.req(2))?;
        let reply = self
            .utxo_replies
            .get(id)
            .filter(|reply| reply.scripthash == scripthash)
            .ok_or_else(snapshot_expired)?;
        match usize::try_from(index).ok().and_then(|i| reply.chunks.get(i)) {
            Some(chunk) => Ok(chunk.to_json()),
            None => Err(CodedError {
                code: -32602,
                message: format!("chunk {} out of range", index),
            }
            .into()),
        }
    }

    fn scripthash_utxo_subscribe(&self, client: &mut Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        if client.utxo_subscriptions.len() >= MAX_UTXO_SUBSCRIPTIONS
            && !client.utxo_subscriptions.contains_key(&scripthash)
        {
            bail!("too many UTXO subscriptions");
        }
        let method = "blockchain.scripthash.utxo_subscribe";
        let found = self.snapshot_of(scripthash, true, method, |snapshot| {
            utxo::status(snapshot.set_hash(), &snapshot.mempool_part(&self.tracker.mempool()))
        })?;
        let subscription = match found {
            SnapshotOf::Done(status) => UtxoSubscription {
                status: None,
                set_hash: None,
                last: status,
            },
            _ => {
                let chain = self.tracker.chain();
                let mut subscription = UtxoSubscription {
                    status: Some(self.new_status_on(scripthash, &chain)?),
                    set_hash: None,
                    last: Sum256::default(),
                };
                subscription.last = self.short_utxo_status(&mut subscription, &chain)?;
                subscription
            }
        };
        let status = subscription.last;
        client.utxo_subscriptions.insert(scripthash, subscription);
        Ok(json!(status.to_hex()))
    }

    fn scripthash_utxo_unsubscribe(&self, client: &mut Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        Ok(json!(client.utxo_subscriptions.remove(&scripthash).is_some()))
    }

    /// The `utxo_subscribe` status of a short history, from its status synced
    /// with `chain`.
    fn short_utxo_status(
        &self,
        subscription: &mut UtxoSubscription,
        chain: &crate::chain::Chain,
    ) -> Result<Sum256> {
        let status = subscription.status.as_ref().expect("a short history");
        let tip = status.tip();
        let set_hash = match subscription.set_hash {
            Some((block, set_hash, _)) if block == tip => set_hash,
            _ => {
                let height = chain
                    .get_block_height(&tip)
                    .context("synced with another chain")?;
                let utxos = status.utxos_at(chain, Some(height));
                let set_hash = utxo::set_hash(utxos.values());
                subscription.set_hash = Some((tip, set_hash, utxos.len()));
                set_hash
            }
        };
        Ok(utxo::status(set_hash, &status.mempool_part(chain)))
    }

    /// The new status of a `utxo_subscribe` subscription, if it changed.
    fn update_utxo_subscription(
        &self,
        scripthash: ScriptHash,
        subscription: &mut UtxoSubscription,
    ) -> Result<SnapshotOf<Option<Sum256>>> {
        let status = match subscription.status.as_mut() {
            Some(status) => {
                let chain = self.tracker.chain();
                self.tracker
                    .update_scripthash_status_on(status, &chain, &self.daemon, &self.cache)?;
                self.short_utxo_status(subscription, &chain)?
            }
            None => {
                let method = "blockchain.scripthash.utxo_subscribe";
                match self.snapshot_of(scripthash, false, method, |snapshot| {
                    utxo::status(snapshot.set_hash(), &snapshot.mempool_part(&self.tracker.mempool()))
                })? {
                    SnapshotOf::Done(status) => status,
                    SnapshotOf::Busy => return Ok(SnapshotOf::Busy),
                    SnapshotOf::Short => return Ok(SnapshotOf::Short),
                }
            }
        };
        if status == subscription.last {
            return Ok(SnapshotOf::Done(None));
        }
        subscription.last = status;
        Ok(SnapshotOf::Done(Some(status)))
    }

    /// Saved when built too, and every `UTXO_SNAPSHOT_SAVE_BLOCKS`: a crash
    /// then only loses the blocks applied since.
    fn save_utxo_snapshot(&self, snapshot: &mut UtxoSnapshot) {
        let key = snapshot.scripthash().to_byte_array();
        self.tracker
            .index()
            .store()
            .put_utxo_snapshot(&key, &snapshot.to_bytes());
        snapshot.mark_saved();
    }

    fn scripthash_list_unspent(&self, client: &Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        let filter = match args.get(1) {
            None | Some(Value::Null) => AssetFilter::NativeOnly,
            Some(value) => AssetFilter::from_json(value)?,
        };
        let unspent_entries = match client.scripthashes.get(&scripthash) {
            Some(status) => self.tracker.get_unspent(status),
            None => self
                .unspent_status_of(client, scripthash, "blockchain.scripthash.listunspent")?
                .into_unspent(),
        };
        Ok(unspent_to_json(unspent_entries, &filter))
    }

    fn scripthash_subscribe(&self, client: &mut Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        let status = self.scripthashes_subscribe(client, &[scripthash]).next().unwrap()?;
        let too_large = client
            .scripthashes
            .get(&scripthash)
            .is_some_and(|s| s.get_history().len() >= MAX_HISTORY);
        if too_large {
            // like ElectrumX, a history that is too large is not kept subscribed
            client.scripthashes.remove(&scripthash);
            bail!("history too large");
        }
        Ok(status)
    }

    fn scripthash_unsubscribe(&self, client: &mut Client, args: &Args) -> Result<Value> {
        let scripthash = parse_scripthash(args.req(0))?;
        let removed = client.scripthashes.remove(&scripthash).is_some();
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
            .map(|scripthash| (scripthash, self.subscription_status(scripthash)))
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

    /// Status of a new subscription: like ElectrumX, not for histories too large.
    fn subscription_status(&self, scripthash: ScriptHash) -> Result<ScriptHashStatus> {
        self.check_history_size(scripthash)?;
        let status = self.new_status(scripthash)?;
        if status.get_history().len() >= MAX_HISTORY {
            bail!("history too large");
        }
        Ok(status)
    }

    /// A status synced up to the tip of `chain`.
    fn new_status_on(
        &self,
        scripthash: ScriptHash,
        chain: &crate::chain::Chain,
    ) -> Result<ScriptHashStatus> {
        let mut status = ScriptHashStatus::new(scripthash);
        self.tracker
            .update_scripthash_status_on(&mut status, chain, &self.daemon, &self.cache)?;
        Ok(status)
    }

    pub(crate) fn new_status(&self, scripthash: ScriptHash) -> Result<ScriptHashStatus> {
        let mut status = ScriptHashStatus::new(scripthash);
        self.tracker
            .update_scripthash_status(&mut status, &self.daemon, &self.cache)?;
        Ok(status)
    }

    fn address_get_scripthash(&self, args: &Args) -> Result<Value> {
        use crate::neurai::address::address_to_script;
        let addr = match args.req(0) {
            Value::String(addr) => addr,
            other => bail!("{} is not a valid address", py_str(other)),
        };
        let script = address_to_script(addr, self.tracker.chain().params())?;
        Ok(json!(ScriptHash::new(&script)))
    }

    fn transaction_broadcast(&self, args: &Args) -> Result<Value> {
        let raw_tx = args.req(0);
        let raw_hex = match raw_tx.as_str() {
            Some(hex) if Vec::<u8>::from_hex(hex).is_ok() => hex,
            _ => bail!("argument should be hex-encoded bytes"),
        };
        // Like ElectrumX, the daemon decodes and validates the transaction.
        match self.daemon.broadcast_raw(raw_hex) {
            Ok(txid) => Ok(json!(txid)),
            Err(e) => {
                let message = e
                    .downcast_ref::<bitcoincore_rpc::Error>()
                    .and_then(extract_bitcoind_error)
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| format!("{:#}", e));
                bail!(
                    "the transaction was rejected by network rules.\n\n{}\n[{}]",
                    message,
                    py_str(raw_tx)
                )
            }
        }
    }

    fn transaction_get(&self, args: &Args) -> Result<Value> {
        let txid = assert_tx_hash(args.req(0))?;
        let verbose = require_bool(args.get(1), false, "verbose")?;
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
        Ok(json!(self.raw_transaction_hex(txid)?))
    }

    pub(crate) fn raw_transaction_hex(&self, txid: Txid) -> Result<String> {
        // if the scripthash was subscribed, tx should be cached
        if let Some(tx_hex) = self
            .cache
            .get_tx(&txid, |tx_bytes| tx_bytes.to_lower_hex_string())
        {
            return Ok(tx_hex);
        }
        debug!("tx cache miss: txid={}", txid);
        // use internal index to load confirmed transaction
        if let Some(tx_hex) = self
            .tracker
            .lookup_transaction(&self.daemon, txid)?
            .map(|(_blockhash, tx)| tx.to_lower_hex_string())
        {
            return Ok(tx_hex);
        }
        // load unconfirmed transaction via RPC
        Ok(self
            .daemon
            .get_transaction_hex(&txid)?
            .as_str()
            .map(str::to_owned)
            .unwrap_or_default())
    }

    /// Txids of the block at `height`, with ElectrumX's error for a height
    /// above the tip.
    fn tx_hashes_at_height(&self, height: u64) -> Result<Vec<Txid>> {
        let chain = self.tracker.chain();
        let blockhash = match usize::try_from(height).ok().and_then(|h| chain.get_block_hash(h)) {
            Some(blockhash) => blockhash,
            None => bail!(
                "db error: DBError('block {} not on disk (>{})')",
                commas(height),
                commas(chain.height() as u64)
            ),
        };
        self.daemon.get_block_txids(blockhash)
    }

    fn transaction_get_merkle(&self, args: &Args) -> Result<Value> {
        let txid = assert_tx_hash(args.req(0))?;
        let height = non_negative_integer(args.req(1))?;
        let txids = self.tx_hashes_at_height(height)?;
        match txids.iter().position(|current_txid| *current_txid == txid) {
            None => bail!("tx {} not in block at height {}", txid, commas(height)),
            Some(position) => {
                let proof = Proof::create(&txids, position);
                Ok(json!({
                    "block_height": height,
                    "merkle": proof.to_hex(),
                    "pos": proof.position(),
                }))
            }
        }
    }

    /// `blockchain.transaction.get_tsc_merkle`, as ElectrumX: the "block_hash"
    /// target is `dsha256(raw header)` (for KAWPOW headers this is *not* the
    /// block hash; ElectrumX behaviour kept on purpose).
    fn transaction_get_tsc_merkle(&self, args: &Args) -> Result<Value> {
        let txid = assert_tx_hash(args.req(0))?;
        let height = non_negative_integer(args.req(1))?;
        let txid_or_tx = args.get(2).cloned().unwrap_or_else(|| json!("txid"));
        let target_type = args.get(3).cloned().unwrap_or_else(|| json!("block_hash"));

        let txids = self.tx_hashes_at_height(height)?;
        let pos = match txids.iter().position(|t| *t == txid) {
            Some(pos) => pos,
            None => bail!("tx {} not in block at height {}", txid, commas(height)),
        };
        let hashes: Vec<[u8; 32]> = txids.iter().map(|t| t.to_byte_array()).collect();
        let (branch, root) = merkle_branch_and_root(hashes, pos, true);

        let raw_header = Vec::<u8>::from_hex(&self.raw_header_hex(height)?)?;
        let root_from_header: [u8; 32] = raw_header[36..68].try_into().expect("32 bytes");
        if root != root_from_header {
            bail!("db error. Merkle root from cached block header does not match the derived merkle root");
        }
        let target = match target_type.as_str() {
            Some("block_header") => raw_header.to_lower_hex_string(),
            Some("merkle_root") => display_hex(&root_from_header),
            _ => display_hex(&sha256d::Hash::hash(&raw_header).to_byte_array()),
        };
        let tx_or_id = if txid_or_tx.as_str() == Some("tx") {
            self.raw_transaction_hex(txid)?
        } else {
            txid.to_string()
        };
        let nodes: Vec<String> = branch
            .iter()
            .map(|node| node.map_or_else(|| "*".to_owned(), |h| display_hex(&h)))
            .collect();
        Ok(json!({
            "index": pos,
            "txOrId": tx_or_id,
            "target": target,
            "nodes": nodes,
            "targetType": target_type,
            "proofType": "branch",
            "composite": false,
        }))
    }

    fn transaction_from_pos(&self, args: &Args) -> Result<Value> {
        let height = non_negative_integer(args.req(0))?;
        let tx_pos = non_negative_integer(args.req(1))?;
        let merkle = require_bool(args.get(2), false, "merkle")?;
        let txids = self.tx_hashes_at_height(height)?;
        let txid = match usize::try_from(tx_pos).ok().and_then(|p| txids.get(p)) {
            Some(txid) => *txid,
            None => bail!(
                "no tx at position {} in block at height {}",
                commas(tx_pos),
                commas(height)
            ),
        };
        if merkle {
            let proof = Proof::create(&txids, tx_pos as usize);
            Ok(json!({"tx_hash": txid, "merkle": proof.to_hex()}))
        } else {
            // The protocol specifies a bare transaction hash when `merkle` is false.
            Ok(json!(txid))
        }
    }

    fn get_fee_histogram(&self) -> Result<Value> {
        Ok(json!(self.tracker.compact_fee_histogram()))
    }

    fn server_id(&self) -> String {
        format!("electrs-neurai/{}", ELECTRS_VERSION)
    }

    fn version(&self, client: &mut Client, args: &Args) -> Result<Value> {
        if client.version_sent {
            bail!("server.version already sent");
        }
        client.version_sent = true;
        let requested = args.get(1).cloned().unwrap_or(Value::Null);
        match negotiate_protocol(&requested) {
            Some(version) => Ok(json!([self.server_id(), version_string(&version)])),
            None => {
                client.disconnect = true;
                bail!("unsupported protocol version: {}", py_str(&requested))
            }
        }
    }

    fn banner(&self) -> Result<Value> {
        let mut banner = self.banner.clone();
        if banner.contains('$') {
            let info = self.daemon.get_network_info_raw().unwrap_or(Value::Null);
            let version = info.get("version").and_then(Value::as_u64).unwrap_or(0);
            let daemon_version = format!(
                "{}.{}.{}",
                version / 1_000_000,
                (version / 10_000) % 100,
                (version / 100) % 100
            );
            let subversion = info.get("subversion").and_then(Value::as_str).unwrap_or("");
            for (var, value) in [
                ("$SERVER_VERSION", ELECTRS_VERSION),
                ("$SERVER_SUBVERSION", self.server_id().as_str()),
                ("$DAEMON_VERSION", daemon_version.as_str()),
                ("$DAEMON_SUBVERSION", subversion),
                ("$DONATION_ADDRESS", self.donation_address.as_str()),
            ] {
                banner = banner.replace(var, value);
            }
        }
        Ok(json!(banner))
    }

    fn features(&self) -> Result<Value> {
        let mut hosts = serde_json::Map::new();
        for service in &self.services {
            let entry = hosts
                .entry(service.host.clone())
                .or_insert_with(|| json!({}));
            let key = format!("{}_port", service.service.scheme());
            if let Some(ports) = entry.as_object_mut() {
                ports.entry(key).or_insert(json!(service.port));
            }
        }
        let services: Vec<String> = self
            .services
            .iter()
            .map(|s| {
                if s.host.contains(':') {
                    format!("{}://[{}]:{}", s.service.scheme(), s.host, s.port)
                } else {
                    format!("{}://{}:{}", s.service.scheme(), s.host, s.port)
                }
            })
            .collect();
        Ok(json!({
            "hosts": hosts,
            "pruning": null,
            "server_version": self.server_id(),
            "protocol_min": version_string(PROTOCOL_MIN),
            "protocol_max": version_string(PROTOCOL_MAX),
            "protocol_bad": [],
            "genesis_hash": self.tracker.chain().get_block_hash(0),
            "hash_function": "sha256",
            "services": services,
            // electrs-neurai extension (doc/utxo-chunks.md)
            "utxo_chunks": utxo::PROTOCOL_VERSION,
        }))
    }

    /// The reply to a request (or batch of requests) and its number of calls.
    pub(crate) fn handle_request(&self, client: &mut Client, line: &str) -> (String, usize) {
        let calls = parse_requests(line)
            .map(Calls::parse)
            .map_err(error_msg_no_id);
        let count = match &calls {
            Ok(Calls::Batch(batch)) => batch.len().max(1),
            _ => 1,
        };
        (self.handle_calls(client, calls).to_string(), count)
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
            .map(|call| match call.method {
                Method::ScriptHashSubscribe => parse_scripthash(call.args.req(0)).ok(),
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
        self.rpc_duration.observe_duration(&call.name, || {
            if self.tracker.status().is_err() && !call.method.available_during_sync() {
                return error_msg(&call.id, RpcError::UnavailableIndex);
            }
            let args = &call.args;
            let result = match call.method {
                Method::ServerVersion => self.version(client, args),
                Method::ServerFeatures => self.features(),
                Method::ServerBanner => self.banner(),
                Method::ServerDonationAddress => Ok(json!(self.donation_address)),
                Method::ServerPing => Ok(Value::Null),
                Method::ServerPeersSubscribe => Ok(json!([])),
                Method::ServerAddPeer => Ok(json!(false)), // no peer discovery
                Method::HeadersSubscribe => self.headers_subscribe(client),
                Method::BlockHeader => self.block_header(args),
                Method::BlockHeaders => self.block_headers(args),
                Method::EstimateFee => self.estimate_fee(args),
                Method::RelayFee => self.relayfee(),
                Method::MempoolFeeHistogram => self.get_fee_histogram(),
                Method::ScriptHashGetBalance => self.scripthash_get_balance(client, args),
                Method::ScriptHashGetHistory => self.scripthash_get_history(client, args),
                Method::ScriptHashGetMempool => self.scripthash_get_mempool(client, args),
                Method::ScriptHashListUnspent => self.scripthash_list_unspent(client, args),
                Method::ScriptHashSubscribe => self.scripthash_subscribe(client, args),
                Method::ScriptHashUnsubscribe => self.scripthash_unsubscribe(client, args),
                Method::ScriptHashUtxoSync => self.scripthash_utxo_sync(client, args),
                Method::ScriptHashUtxoChunk => self.scripthash_utxo_chunk(args),
                Method::ScriptHashUtxoSubscribe => self.scripthash_utxo_subscribe(client, args),
                Method::ScriptHashUtxoUnsubscribe => self.scripthash_utxo_unsubscribe(client, args),
                Method::TransactionBroadcast => self.transaction_broadcast(args),
                Method::TransactionGet => self.transaction_get(args),
                Method::TransactionGetMerkle => self.transaction_get_merkle(args),
                Method::TransactionGetTscMerkle => self.transaction_get_tsc_merkle(args),
                Method::TransactionIdFromPos => self.transaction_from_pos(args),
                Method::AddressGetScripthash => self.address_get_scripthash(args),
                Method::Asset(method) => self.asset_call(client, method, args),
            };
            call.response(result)
        })
    }
}

/// Every method ElectrumX-neurai registers (`session.py` `set_request_handlers`)
/// plus electrs-neurai extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    ServerVersion,
    ServerFeatures,
    ServerBanner,
    ServerDonationAddress,
    ServerPing,
    ServerPeersSubscribe,
    ServerAddPeer,
    HeadersSubscribe,
    BlockHeader,
    BlockHeaders,
    EstimateFee,
    RelayFee,
    MempoolFeeHistogram,
    ScriptHashGetBalance,
    ScriptHashGetHistory,
    ScriptHashGetMempool,
    ScriptHashListUnspent,
    ScriptHashSubscribe,
    ScriptHashUnsubscribe,
    TransactionBroadcast,
    TransactionGet,
    TransactionGetMerkle,
    TransactionGetTscMerkle,
    TransactionIdFromPos,
    /// electrs-neurai extensions
    AddressGetScripthash,
    ScriptHashUtxoSync,
    ScriptHashUtxoChunk,
    ScriptHashUtxoSubscribe,
    ScriptHashUtxoUnsubscribe,
    Asset(crate::electrum_assets::AssetMethod),
}

impl Method {
    /// Method, ElectrumX parameter names and number of required parameters.
    fn lookup(name: &str) -> Option<(Method, &'static [&'static str], usize)> {
        use crate::electrum_assets::AssetMethod;
        Some(match name {
            "server.version" => (Method::ServerVersion, &["client_name", "protocol_version"], 0),
            "server.features" => (Method::ServerFeatures, &[], 0),
            "server.banner" => (Method::ServerBanner, &[], 0),
            "server.donation_address" => (Method::ServerDonationAddress, &[], 0),
            "server.ping" => (Method::ServerPing, &[], 0),
            "server.peers.subscribe" => (Method::ServerPeersSubscribe, &[], 0),
            "server.add_peer" => (Method::ServerAddPeer, &["features"], 1),
            "blockchain.headers.subscribe" => (Method::HeadersSubscribe, &[], 0),
            "blockchain.block.header" => (Method::BlockHeader, &["height", "cp_height"], 1),
            "blockchain.block.headers" => (
                Method::BlockHeaders,
                &["start_height", "count", "cp_height"],
                2,
            ),
            "blockchain.estimatefee" => (Method::EstimateFee, &["number", "mode"], 1),
            "blockchain.relayfee" => (Method::RelayFee, &[], 0),
            "mempool.get_fee_histogram" => (Method::MempoolFeeHistogram, &[], 0),
            "blockchain.scripthash.get_balance" => {
                (Method::ScriptHashGetBalance, &["scripthash", "asset"], 1)
            }
            "blockchain.scripthash.get_history" => {
                (Method::ScriptHashGetHistory, &["scripthash"], 1)
            }
            "blockchain.scripthash.get_mempool" => {
                (Method::ScriptHashGetMempool, &["scripthash"], 1)
            }
            "blockchain.scripthash.listunspent" => {
                (Method::ScriptHashListUnspent, &["scripthash", "asset"], 1)
            }
            "blockchain.scripthash.subscribe" => (Method::ScriptHashSubscribe, &["scripthash"], 1),
            "blockchain.scripthash.unsubscribe" => {
                (Method::ScriptHashUnsubscribe, &["scripthash"], 1)
            }
            "blockchain.transaction.broadcast" => (Method::TransactionBroadcast, &["raw_tx"], 1),
            "blockchain.transaction.get" => (Method::TransactionGet, &["tx_hash", "verbose"], 1),
            "blockchain.transaction.get_merkle" => {
                (Method::TransactionGetMerkle, &["tx_hash", "height"], 2)
            }
            "blockchain.transaction.get_tsc_merkle" => (
                Method::TransactionGetTscMerkle,
                &["tx_hash", "height", "txid_or_tx", "target_type"],
                2,
            ),
            "blockchain.transaction.id_from_pos" => (
                Method::TransactionIdFromPos,
                &["height", "tx_pos", "merkle"],
                2,
            ),
            "blockchain.address.get_scripthash" => (Method::AddressGetScripthash, &["address"], 1),
            "blockchain.scripthash.utxo_sync" => {
                (Method::ScriptHashUtxoSync, &["scripthash", "from_block"], 1)
            }
            "blockchain.scripthash.utxo_chunk" => {
                (Method::ScriptHashUtxoChunk, &["scripthash", "id", "index"], 3)
            }
            "blockchain.scripthash.utxo_subscribe" => {
                (Method::ScriptHashUtxoSubscribe, &["scripthash"], 1)
            }
            "blockchain.scripthash.utxo_unsubscribe" => {
                (Method::ScriptHashUtxoUnsubscribe, &["scripthash"], 1)
            }
            other => {
                let (method, names, required) = AssetMethod::lookup(other)?;
                (Method::Asset(method), names, required)
            }
        })
    }

    /// Methods answered before the initial index sync completes.
    fn available_during_sync(self) -> bool {
        matches!(
            self,
            Method::ServerVersion
                | Method::ServerFeatures
                | Method::ServerBanner
                | Method::ServerDonationAddress
                | Method::ServerPing
                | Method::ServerPeersSubscribe
                | Method::ServerAddPeer
                | Method::HeadersSubscribe
                | Method::BlockHeader
                | Method::BlockHeaders
                | Method::EstimateFee
                | Method::RelayFee
        )
    }
}

struct Call {
    id: Value,
    name: String,
    method: Method,
    args: Args,
}

impl Call {
    fn parse(request: Request) -> Result<Call, Value> {
        let (method, names, required) = match Method::lookup(&request.method) {
            Some(found) => found,
            None => {
                warn!("unknown method {}", request.method);
                return Err(error_msg(
                    &request.id,
                    RpcError::Standard(StandardError::MethodNotFound),
                ));
            }
        };
        match Args::parse(request.params, names, required) {
            Ok(args) => Ok(Call {
                id: request.id,
                name: request.method,
                method,
                args,
            }),
            Err(e) => Err(error_msg(&request.id, RpcError::Standard(e))),
        }
    }

    fn response(&self, result: Result<Value>) -> Value {
        match result {
            Ok(value) => result_msg(&self.id, value),
            Err(err) => {
                if let Some(coded) = err.downcast_ref::<CodedError>() {
                    debug!("RPC {} failed: {}", self.name, coded);
                    return error_msg(&self.id, RpcError::Coded(coded.code, coded.message.clone()));
                }
                warn!("RPC {} failed: {:#}", self.name, err);
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

pub(crate) fn notification(method: &str, params: &[Value]) -> Value {
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
                // errors of the client, answered as such: not worth a warning
                debug!("invalid RPC request ({:?}): {}", line, err);
                Err(StandardError::InvalidRequest)
            }
        },
        Err(err) => {
            debug!("invalid JSON ({:?}): {}", line, err);
            Err(StandardError::ParseError)
        }
    }
}

#[allow(dead_code)]
fn tx_from_hex(tx_hex: &str) -> Result<Transaction> {
    let tx_bytes = Vec::from_hex(tx_hex).context("non-hex transaction")?;
    let tx = deserialize(&tx_bytes).context("invalid transaction")?;
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn negotiated(request: Value) -> Option<String> {
        negotiate_protocol(&request).map(|v| version_string(&v))
    }

    /// Same answers as ElectrumX `util.protocol_version` with min 1.0 / max 1.4.
    #[test]
    fn protocol_negotiation_matches_electrumx() {
        assert_eq!(negotiated(json!("1.0")).as_deref(), Some("1.0")); // electrum-neurai 0.2.2
        assert_eq!(negotiated(json!("1.4")).as_deref(), Some("1.4"));
        assert_eq!(negotiated(json!(["1.2", "1.6"])).as_deref(), Some("1.4"));
        assert_eq!(negotiated(json!(["1.0", "1.4.2"])).as_deref(), Some("1.4"));
        assert_eq!(negotiated(Value::Null).as_deref(), Some("1.0"));
        assert_eq!(negotiated(json!("1.4.2")), None); // (1,4) < (1,4,2)
        assert_eq!(negotiated(json!("1.5")), None); // min((1,5),(1,4)) < client min (1,5)
        assert_eq!(negotiated(json!(["1.5", "1.6"])), None);
        assert_eq!(negotiated(json!("1")), None); // (1,) < (1,0) in Python
        assert_eq!(negotiated(json!("0.9")), None);
        assert_eq!(negotiated(json!("x")), None);
        assert_eq!(negotiated(json!(1.4)), None);
    }

    #[test]
    fn python_formatting_helpers() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1_000), "1,000");
        assert_eq!(commas(1_868_013), "1,868,013");
        assert_eq!(py_str(&json!("abc")), "abc");
        assert_eq!(py_repr(&json!("abc")), "'abc'");
        assert_eq!(py_repr(&json!("it's")), "\"it's\"");
        assert_eq!(py_str(&json!(["1.5", "1.6"])), "['1.5', '1.6']");
        assert_eq!(py_str(&Value::Null), "None");
        assert_eq!(py_str(&json!(true)), "True");
    }

    #[test]
    fn argument_validation_messages() {
        assert_eq!(non_negative_integer(&json!(5)).unwrap(), 5);
        assert_eq!(non_negative_integer(&json!("7")).unwrap(), 7);
        assert_eq!(non_negative_integer(&json!(2.9)).unwrap(), 2);
        assert_eq!(
            non_negative_integer(&json!(-1)).unwrap_err().to_string(),
            "-1 should be a non-negative integer"
        );
        assert_eq!(
            non_negative_integer(&json!("abc")).unwrap_err().to_string(),
            "abc should be a non-negative integer"
        );
        assert_eq!(
            parse_scripthash(&json!("zz")).unwrap_err().to_string(),
            "zz is not a valid script hash"
        );
        assert_eq!(
            assert_tx_hash(&json!(12)).unwrap_err().to_string(),
            "12 should be a transaction hash"
        );
        assert_eq!(check_asset(&json!("")).unwrap_err().to_string(), "asset name is empty!");
        assert_eq!(
            check_asset(&json!("A".repeat(33))).unwrap_err().to_string(),
            "asset name greater than 32 characters"
        );
        assert_eq!(
            check_asset(&json!(5)).unwrap_err().to_string(),
            "the asset name must be a string (5; <class 'int'>)"
        );
        assert_eq!(check_h160(&json!(5)).unwrap_err().to_string(), "the h160 must be a string");
        assert_eq!(check_h160(&json!("ab")).unwrap_err().to_string(), "h160 not 20 bytes");
        assert!(check_h160(&json!("00".repeat(20))).is_ok());
        assert_eq!(
            require_bool(Some(&json!("yes")), false, "verbose").unwrap_err().to_string(),
            "\"verbose\" must be a boolean"
        );
    }

    #[test]
    fn named_and_positional_args() {
        let names = &["scripthash", "asset"];
        let args = Args::parse(json!(["aa", true]), names, 1).ok().unwrap();
        assert_eq!(args.get(1), Some(&json!(true)));
        let args = Args::parse(json!({"asset": "X", "scripthash": "aa"}), names, 1).ok().unwrap();
        assert_eq!(args.req(0), &json!("aa"));
        assert_eq!(args.get(1), Some(&json!("X")));
        assert!(Args::parse(json!([]), names, 1).is_err());
        assert!(Args::parse(json!(["a", "b", "c"]), names, 1).is_err());
        assert!(Args::parse(json!({"bogus": 1}), names, 1).is_err());
        let args = Args::parse(Value::Null, &["client_name", "protocol_version"], 0).ok().unwrap();
        assert!(args.get(0).is_none());
    }

    #[test]
    fn asset_filter_semantics() {
        assert_eq!(AssetFilter::from_json(&json!(false)).unwrap(), AssetFilter::NativeOnly);
        assert_eq!(AssetFilter::from_json(&json!(true)).unwrap(), AssetFilter::All);
        assert_eq!(
            AssetFilter::from_json(&json!("TOKEN")).unwrap(),
            AssetFilter::One("TOKEN".into())
        );
        let many = AssetFilter::from_json(&json!([null, "A", "A"])).unwrap();
        assert_eq!(
            many,
            AssetFilter::Many {
                include_native: true,
                assets: ["A".to_string()].into_iter().collect()
            }
        );
        // `null` itself is not valid for get_balance (ElectrumX error text)
        assert_eq!(
            AssetFilter::from_json(&Value::Null).unwrap_err().to_string(),
            "asset must be a list, string, or boolean"
        );
        assert_eq!(
            AssetFilter::from_json(&json!(42)).unwrap_err().to_string(),
            "asset must be a list, string, or boolean"
        );
        assert!(AssetFilter::from_json(&json!(["A", 42])).is_err());
    }

    #[test]
    fn estimatefee_buckets() {
        for (n, b) in [(0, 1), (1, 1), (6, 6), (12, 12), (13, 12), (25, 25), (26, 26), (48, 48), (49, 48), (100, 96), (2000, 1008)] {
            assert_eq!(bucket_estimatefee_block_target(n), b, "n={n}");
        }
    }

    /// Bitcoin block 100000: 4 txs, known merkle root.
    #[test]
    fn merkle_branch_and_root_matches_bitcoin() {
        let txids = [
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
            "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
            "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
        ];
        let hashes: Vec<[u8; 32]> = txids
            .iter()
            .map(|t| Txid::from_str(t).unwrap().to_byte_array())
            .collect();
        let (branch, root) = merkle_branch_and_root(hashes.clone(), 2, false);
        assert_eq!(
            display_hex(&root),
            "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
        );
        assert_eq!(branch.len(), 2);
        // odd level in TSC format marks the duplicated node with "*"
        let (branch, _) = merkle_branch_and_root(hashes[..3].to_vec(), 2, true);
        assert_eq!(branch[0], None);
    }

    #[test]
    fn report_services_parsing() {
        let listeners = vec![(Service::Tcp, "127.0.0.1:50001".parse().unwrap())];
        let derived = parse_report_services("", &listeners).unwrap();
        assert_eq!(derived[0].host, "127.0.0.1");
        let services = parse_report_services(
            "ssl://electrum.example.org:50002, wss://electrum.example.org:50004",
            &listeners,
        )
        .unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[1].service, Service::Wss);
        assert_eq!(services[1].port, 50004);
        assert!(parse_report_services("foo://h:1", &listeners).is_err());
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

    #[test]
    fn every_electrumx_method_is_routed() {
        // `set_request_handlers` of electrumx-neurai @ a6b2d7d (48 methods)
        for name in [
            "blockchain.asset.broadcasts", "blockchain.asset.broadcasts.subscribe",
            "blockchain.asset.broadcasts.unsubscribe", "blockchain.asset.get_assets_with_prefix",
            "blockchain.asset.get_meta", "blockchain.asset.is_frozen",
            "blockchain.asset.is_frozen.subscribe", "blockchain.asset.is_frozen.unsubscribe",
            "blockchain.asset.list_addresses_by_asset", "blockchain.asset.restricted_associations",
            "blockchain.asset.restricted_associations.subscribe",
            "blockchain.asset.restricted_associations.unsubscribe", "blockchain.asset.subscribe",
            "blockchain.asset.unsubscribe", "blockchain.asset.verifier_string",
            "blockchain.asset.verifier_string.subscribe", "blockchain.asset.verifier_string.unsubscribe",
            "blockchain.block.header", "blockchain.block.headers", "blockchain.estimatefee",
            "blockchain.headers.subscribe", "blockchain.relayfee",
            "blockchain.scripthash.get_balance", "blockchain.scripthash.get_history",
            "blockchain.scripthash.get_mempool", "blockchain.scripthash.listunspent",
            "blockchain.scripthash.subscribe", "blockchain.scripthash.unsubscribe",
            "blockchain.tag.check", "blockchain.tag.h160.list", "blockchain.tag.h160.subscribe",
            "blockchain.tag.h160.unsubscribe", "blockchain.tag.qualifier.list",
            "blockchain.tag.qualifier.subscribe", "blockchain.tag.qualifier.unsubscribe",
            "blockchain.transaction.broadcast", "blockchain.transaction.get",
            "blockchain.transaction.get_merkle", "blockchain.transaction.get_tsc_merkle",
            "blockchain.transaction.id_from_pos", "mempool.get_fee_histogram", "server.add_peer",
            "server.banner", "server.donation_address", "server.features", "server.peers.subscribe",
            "server.ping", "server.version",
        ] {
            assert!(Method::lookup(name).is_some(), "{name} is not routed");
        }
        // electrs-neurai extensions are kept
        assert!(Method::lookup("blockchain.address.get_scripthash").is_some());
        assert!(Method::lookup("blockchain.asset.get_history").is_some());
    }
}
