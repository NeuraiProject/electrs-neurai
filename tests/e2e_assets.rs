//! End-to-end tests for Neurai asset support against a real `neuraid` daemon.
//!
//! Uses **testnet** rather than regtest because testnet has assets active
//! from height 1 (no BIP9 dance required), trivial PoW (powLimit = ffff...
//! so generatetoaddress works instantly), and the daemon's epoch-resets keep
//! the chain compact. We run with `connect=0 maxconnections=0` so the local
//! testnet daemon stays isolated from the public testnet and the chain state
//! is fully controlled by this test.
//!
//! The test populates the chain with confirmed asset transfers, then spawns
//! `electrs` against it and validates the Electrum wire responses for the
//! per-asset balance and unspent endpoints introduced in Fase 0 + Fase 1.
//!
//! ## Requirements
//!
//! * `neuraid` and `neurai-cli` binaries. By default the tests look for them
//!   on `PATH`; override the directory with `NEURAI_BIN_DIR=/path/to/bin`.
//! * The `electrs` binary is built automatically by Cargo (via
//!   `CARGO_BIN_EXE_electrs`).
//!
//! ## Running
//!
//! These tests are marked `#[ignore]` so a stock `cargo test` skips them.
//! Run with:
//!
//! ```sh
//! cargo test --test e2e_assets -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: the daemon and electrs bind well-known
//! regtest TCP ports, so concurrent tests would clash.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

// Testnet defaults per src/neurai/network.rs and CTestNetParams.
//
// We rely on the test runner being executed inside a docker container with
// its own network namespace (the `electrs-neurai-dev` image — see the
// `## Running` doc-block at the top of this file). That isolation prevents
// the test ports from clashing with any host-side testnet daemon.
// Neurai's `[test]` conf section is NOT honored for port overrides, so we
// can't shift to non-default ports anyway.
const TESTNET_DAEMON_RPC_PORT: u16 = 19101;
// P2P port 19100 is the daemon default; electrs picks it up automatically
// when given the daemon datadir.
const TESTNET_ELECTRS_PORT: u16 = 60001;
const TESTNET_MONITORING_PORT: u16 = 14224;

const RPC_USER: &str = "test";
const RPC_PASS: &str = "test";

// ─── binary discovery ────────────────────────────────────────────────────────

fn neurai_bin_dir() -> PathBuf {
    std::env::var_os("NEURAI_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin"))
}

fn neuraid_bin() -> PathBuf {
    neurai_bin_dir().join("neuraid")
}

fn neurai_cli_bin() -> PathBuf {
    neurai_bin_dir().join("neurai-cli")
}

fn electrs_bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_electrs"))
}

// ─── daemon control ──────────────────────────────────────────────────────────

/// A neuraid testnet daemon with a temporary datadir, isolated from the
/// public testnet via `connect=0 maxconnections=0`. Stopped + cleaned on drop.
struct Daemon {
    child: Option<Child>,
    datadir: PathBuf,
}

impl Daemon {
    fn start() -> Self {
        let datadir = tempdir("neurai-testnet");
        std::fs::write(
            datadir.join("neurai.conf"),
            format!(
                "testnet=1\n\
                 server=1\n\
                 daemon=0\n\
                 # Bind P2P to localhost only — electrs talks to the daemon\n\
                 # via P2P on this address. No public peers are wanted, so\n\
                 # disable DNS seeds and outbound discovery.\n\
                 bind=127.0.0.1\n\
                 dnsseed=0\n\
                 dns=0\n\
                 listenonion=0\n\
                 upnp=0\n\
                 discover=0\n\
                 txindex=1\n\
                 assetindex=1\n\
                 fallbackfee=0.001\n\
                 rpcuser={RPC_USER}\n\
                 rpcpassword={RPC_PASS}\n\
                 rpcbind=127.0.0.1\n\
                 rpcallowip=127.0.0.1\n\
                 # The test inspects P2PKH script bytes directly, so force\n\
                 # legacy addresses (not bech32m AuthScript v1 — Neurai's\n\
                 # nPQWitnessEnabled is true on testnet).\n\
                 addresstype=legacy\n\
                 changetype=legacy\n\
                 # Defaults match testnet base params; [test] section is\n\
                 # not honored by Neurai for port overrides, so we don't\n\
                 # bother specifying them here.\n"
            ),
        )
        .expect("write neurai.conf");

        // Redirect daemon stdout/stderr to logfiles in the datadir so they
        // survive the test for post-mortem inspection (the regtest/debug.log
        // also lives there).
        let stdout = std::fs::File::create(datadir.join("daemon.stdout")).unwrap();
        let stderr = std::fs::File::create(datadir.join("daemon.stderr")).unwrap();
        let child = Command::new(neuraid_bin())
            .arg(format!("-datadir={}", datadir.display()))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn neuraid (set NEURAI_BIN_DIR if not on PATH)");

        let daemon = Daemon {
            child: Some(child),
            datadir,
        };
        daemon.wait_until_rpc_ready();
        daemon
    }

    fn rpc_args(&self) -> Vec<String> {
        vec![
            format!("-datadir={}", self.datadir.display()),
            "-testnet".into(),
            format!("-rpcuser={RPC_USER}"),
            format!("-rpcpassword={RPC_PASS}"),
            format!("-rpcport={TESTNET_DAEMON_RPC_PORT}"),
            "-rpcconnect=127.0.0.1".into(),
        ]
    }

    fn cli<I, S>(&self, args: I) -> Value
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let out = Command::new(neurai_cli_bin())
            .args(self.rpc_args())
            .args(args)
            .output()
            .expect("run neurai-cli");
        if !out.status.success() {
            panic!(
                "neurai-cli failed: {}\nstderr: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // CLI sometimes returns bare strings/numbers (not JSON-quoted) — try
        // to parse and fall back to a JSON string of the raw stdout.
        serde_json::from_str(&stdout).unwrap_or_else(|_| Value::String(stdout))
    }

    fn wait_until_rpc_ready(&self) {
        wait_for(Duration::from_secs(30), "daemon RPC", || {
            let out = Command::new(neurai_cli_bin())
                .args(self.rpc_args())
                .arg("getblockchaininfo")
                .output()
                .ok()?;
            out.status.success().then_some(())
        });
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new(neurai_cli_bin())
            .args(self.rpc_args())
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
        // Only clean the datadir on successful drop (not on panic), so log
        // files survive for inspection of failing tests.
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.datadir);
        } else {
            eprintln!(
                "(daemon datadir preserved on panic: {})",
                self.datadir.display()
            );
        }
    }
}

// ─── electrs control ─────────────────────────────────────────────────────────

struct Electrs {
    child: Option<Child>,
    _db_dir: PathBuf,
}

impl Electrs {
    fn start(daemon: &Daemon) -> Self {
        let db_dir = tempdir("electrs-testnet-db");
        // electrs-neurai's `auth` is `argument = false, env_var = false` — it
        // can only be set via config file. Write a minimal conf with the test
        // credentials and pass `--conf`.
        let conf_path = db_dir.join("electrs.conf");
        std::fs::write(
            &conf_path,
            format!("auth = \"{RPC_USER}:{RPC_PASS}\"\n"),
        )
        .expect("write electrs.conf");

        // Same log-capture pattern as Daemon: keep stdout/stderr around so a
        // failed startup can be inspected after the test panics.
        let stdout = std::fs::File::create(db_dir.join("electrs.stdout")).unwrap();
        let stderr = std::fs::File::create(db_dir.join("electrs.stderr")).unwrap();
        let child = Command::new(electrs_bin())
            .arg(format!("--conf={}", conf_path.display()))
            .arg("--network=testnet")
            .arg(format!("--db-dir={}", db_dir.display()))
            .arg(format!("--daemon-dir={}", daemon.datadir.display()))
            .arg(format!("--daemon-rpc-addr=127.0.0.1:{TESTNET_DAEMON_RPC_PORT}"))
            .arg(format!("--electrum-rpc-addr=127.0.0.1:{TESTNET_ELECTRS_PORT}"))
            .arg(format!("--monitoring-addr=127.0.0.1:{TESTNET_MONITORING_PORT}"))
            .env("RUST_LOG", "electrs_neurai=debug")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn electrs");

        let electrs = Electrs {
            child: Some(child),
            _db_dir: db_dir,
        };
        electrs.wait_until_port_open();
        electrs
    }

    fn wait_until_port_open(&self) {
        wait_for(Duration::from_secs(30), "electrs port", || {
            TcpStream::connect(("127.0.0.1", TESTNET_ELECTRS_PORT))
                .ok()
                .map(|_| ())
        });
    }
}

impl Drop for Electrs {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ─── electrum JSON-RPC client over TCP ───────────────────────────────────────

struct ElectrumClient {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    next_id: u64,
}

impl ElectrumClient {
    fn connect() -> Self {
        let addr = ("127.0.0.1", TESTNET_ELECTRS_PORT)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .expect("electrs TCP connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let writer = stream.try_clone().unwrap();
        ElectrumClient {
            reader: BufReader::new(stream),
            writer,
            next_id: 1,
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": id});
        let line = format!("{req}\n");
        self.writer.write_all(line.as_bytes()).expect("write");
        self.writer.flush().ok();
        // Drain notifications until we see our response id.
        loop {
            let mut buf = String::new();
            self.reader.read_line(&mut buf).expect("read");
            let v: Value = serde_json::from_str(buf.trim()).expect("parse json");
            if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                    panic!("electrum error from {method}: {err}");
                }
                return v.get("result").cloned().unwrap_or(Value::Null);
            }
            // Otherwise it's a notification — ignore for the synchronous call path.
        }
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Wait up to `total` for `probe` to return `Some`. Polls every 250ms.
fn wait_for<F>(total: Duration, what: &str, mut probe: F)
where
    F: FnMut() -> Option<()>,
{
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if probe().is_some() {
            return;
        }
        sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what} ({total:?})");
}

fn tempdir(prefix: &str) -> PathBuf {
    let base = std::env::temp_dir();
    let mut attempt = 0;
    loop {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = base.join(format!("{prefix}-{nanos}-{attempt}"));
        if std::fs::create_dir(&path).is_ok() {
            return path;
        }
        attempt += 1;
        if attempt > 50 {
            panic!("could not create tempdir under {}", base.display());
        }
    }
}

/// SHA256 of a script's bytes, in the byte order Electrum uses on the wire
/// (reverse of internal): consensus scripthash big-endian hex.
fn scripthash_hex(script_bytes: &[u8]) -> String {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::hex::DisplayHex;
    let h = sha256::Hash::hash(script_bytes);
    // Electrum reverses the SHA256 bytes.
    let mut bytes = h.to_byte_array();
    bytes.reverse();
    bytes.to_lower_hex_string()
}

/// Build a P2PKH script `OP_DUP OP_HASH160 <20-byte hash160> OP_EQUALVERIFY OP_CHECKSIG`
/// from a base58 legacy address. Regtest uses prefix 127.
fn p2pkh_script_from_address(address: &str) -> Vec<u8> {
    let raw = bitcoin::base58::decode(address).expect("base58 decode");
    assert_eq!(raw.len(), 25, "expected base58check payload of 25 bytes");
    let hash160 = &raw[1..21];
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 push-20
    script.extend_from_slice(hash160);
    script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    script
}

// ─── tests ───────────────────────────────────────────────────────────────────

/// Full happy-path: a P2PKH address that receives both XNA and an asset transfer
/// must be reachable through electrs by its bare-address scripthash, and the
/// per-asset balance / unspent responses must follow the ElectrumX wire shape.
///
/// This single test exercises the Fase 0 invariant (effective scripthash) and
/// the Fase 1 wire (per-asset Balance, per-asset UnspentEntry, AssetFilter).
#[test]
#[ignore = "requires neuraid + neurai-cli; run with `cargo test -- --ignored --test-threads=1`"]
fn end_to_end_asset_balance_and_unspent() {
    let daemon = Daemon::start();

    // Set up a wallet + mining address. Regtest only has the default wallet.
    let mining_addr = daemon.cli(["getnewaddress"]).as_str().unwrap().to_string();
    daemon.cli([
        "generatetoaddress".into(),
        "110".into(),
        mining_addr.clone(),
    ]);

    // The recipient: a freshly generated legacy P2PKH address. addresstype
    // is forced to "legacy" in the conf so we can compute the bare scripthash
    // with the simple P2PKH layout used in p2pkh_script_from_address.
    // (Neurai's getnewaddress doesn't accept an address_type argument; the
    // signature is `getnewaddress ( "account" )` only.)
    let recipient = daemon.cli(["getnewaddress"]).as_str().unwrap().to_string();
    let recipient_script = p2pkh_script_from_address(&recipient);
    let recipient_sh = scripthash_hex(&recipient_script);

    // Issue 1000 units of a new asset directly to the recipient.
    let asset_name = "E2ETEST";
    daemon.cli([
        "issue".into(),
        asset_name.into(),
        "1000".into(),
        recipient.clone(),
    ]);
    // Mine the issuance into a block (issuance + 1 confirmation is enough).
    daemon.cli([
        "generatetoaddress".into(),
        "1".into(),
        mining_addr.clone(),
    ]);

    // ── start electrs against this daemon ───────────────────────────────────
    let _electrs = Electrs::start(&daemon);

    // Wait until electrs has caught up to the daemon's current height.
    // neurai-cli usually prints `getblockcount` as a bare integer (no JSON
    // quotes), so `Value::String("110")` is the common case; we also accept
    // a JSON number for robustness.
    let block_count = daemon.cli(["getblockcount"]);
    let expected_height = block_count
        .as_u64()
        .or_else(|| block_count.as_str().and_then(|s| s.parse().ok()))
        .expect("getblockcount as u64");
    let mut client = ElectrumClient::connect();
    wait_for(Duration::from_secs(20), "electrs height", || {
        let resp = client.call("blockchain.headers.subscribe", json!([]));
        resp.get("height")
            .and_then(|h| h.as_u64())
            .filter(|h| *h >= expected_height)
            .map(|_| ())
    });

    // ── Fase 0 invariant: bare-address scripthash sees the asset ────────────
    //
    // listunspent(asset=true) on the recipient scripthash must include exactly
    // one asset UTXO with `asset == E2ETEST`. Without the effective_script
    // fix this would be empty: the asset-wrapped output's full-script hash
    // doesn't match the bare P2PKH scripthash.
    let unspent_all = client.call(
        "blockchain.scripthash.listunspent",
        json!([recipient_sh, true]),
    );
    let entries = unspent_all.as_array().expect("listunspent returns array");
    let asset_utxos: Vec<&Value> = entries
        .iter()
        .filter(|e| e["asset"].as_str() == Some(asset_name))
        .collect();
    assert_eq!(
        asset_utxos.len(),
        1,
        "expected exactly one E2ETEST UTXO, got {entries:?}"
    );
    // Default units for `issue` is 0 → amount = qty (1000) in raw min-units.
    // With units=0, "1000" issued is stored as 1000 * 10^8 = 100_000_000_000
    // because Neurai assets share the COIN multiplier with XNA. The wire
    // value is the asset's min-units, which is 100_000_000_000 for "1000".
    assert_eq!(
        asset_utxos[0]["value"].as_u64(),
        Some(100_000_000_000),
        "asset UTXO value is min-units (1000 * 10^8)"
    );

    // ── Fase 1: per-asset shape on get_balance(asset=true) ──────────────────
    //
    // Multi-asset map must include both "rvn" (native dust + burn change) and
    // the asset key. Confirmed for native may be 0 if the recipient only has
    // the asset output (no XNA to itself), but the key must still appear
    // because the asset UTXO carries dust. We assert structure, not values.
    let balance_all = client.call(
        "blockchain.scripthash.get_balance",
        json!([recipient_sh, true]),
    );
    let map = balance_all.as_object().expect("multi-asset object");
    assert!(
        map.contains_key(asset_name),
        "multi-asset balance must contain key {asset_name}: {balance_all}"
    );
    assert_eq!(
        map[asset_name]["confirmed"].as_i64(),
        Some(100_000_000_000),
        "confirmed asset balance = 1000 * 10^8 min-units"
    );

    // ── Fase 1: single-asset filter ─────────────────────────────────────────
    let balance_one = client.call(
        "blockchain.scripthash.get_balance",
        json!([recipient_sh, asset_name]),
    );
    assert_eq!(
        balance_one,
        json!({"confirmed": 100_000_000_000_i64, "unconfirmed": 0}),
        "asset-only filter returns legacy single-asset shape"
    );

    // ── Fase 1: NativeOnly default excludes the asset UTXO ─────────────────
    let unspent_native = client.call(
        "blockchain.scripthash.listunspent",
        json!([recipient_sh]),
    );
    let native_entries = unspent_native
        .as_array()
        .expect("listunspent native array");
    assert!(
        native_entries.iter().all(|e| e["asset"].is_null()),
        "asset=False (default) must filter to native-only, got {native_entries:?}"
    );

    // ── Fase 1: NativeOnly balance hides the asset ─────────────────────────
    let balance_default = client.call(
        "blockchain.scripthash.get_balance",
        json!([recipient_sh]),
    );
    let obj = balance_default.as_object().expect("legacy shape object");
    assert!(
        obj.contains_key("confirmed") && obj.contains_key("unconfirmed"),
        "legacy single-asset shape (no asset key)"
    );
    // The asset name must NOT appear at the top level of the legacy shape.
    assert!(!obj.contains_key(asset_name));
}
