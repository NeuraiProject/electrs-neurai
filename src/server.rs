use anyhow::{Context, Result};
use crossbeam_channel::select;
use parking_lot::Mutex;

use std::{
    collections::hash_map::HashMap,
    net::{IpAddr, SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::{
    config::Config,
    electrum::{Client, Rpc},
    limits::{take_waited, waiting, IpKey, RateLimits, Refusal, Verdict},
    metrics::{self, Metrics},
    signals::ExitError,
    thread::spawn,
    transport::{Connection, Service, TlsCertificate, Writer},
};

/// Threads sending notifications: a client that doesn't read can hold one
/// for a while (see `Connection::accept`), never the indexer.
const NOTIFY_THREADS: usize = 4;

/// A connected client. Its requests are handled by its own thread, one at a
/// time; notifications are sent by the notification threads when it is idle,
/// otherwise by its thread after the request it is busy with.
struct Peer {
    id: usize,
    ip: IpAddr,
    client: Mutex<Client>,
    writer: Writer,
    /// New blocks or mempool transactions may bring it notifications.
    pending: AtomicBool,
    /// A notification thread is going to look at it.
    queued: AtomicBool,
}

impl Peer {
    fn new(id: usize, ip: IpAddr, writer: Writer) -> Self {
        Self {
            id,
            ip,
            client: Mutex::new(Client::default()),
            writer,
            pending: AtomicBool::new(false),
            queued: AtomicBool::new(false),
        }
    }

    fn send(&self, values: Vec<String>) -> Result<()> {
        for value in values {
            debug!("{}: send {}", self.id, value);
            self.writer
                .send_message(&value)
                .with_context(|| format!("failed to send response: {:?}", value))?;
        }
        Ok(())
    }

    /// Sends the pending notifications, with `client` locked.
    fn notify(&self, rpc: &Rpc, client: &mut Client) -> Result<()> {
        if !self.pending.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        let notifications = rpc
            .update_client(client)
            .context("failed to generate notifications")?;
        if client.take_notify_again() {
            // checked again at the next round, or after its next request
            self.pending.store(true, Ordering::SeqCst);
        }
        self.send(notifications)
            .context("failed to send notifications")
    }

    fn disconnect(&self) {
        self.writer.close();
    }
}

type Peers = Arc<Mutex<HashMap<usize, Arc<Peer>>>>;

/// Everything a connection thread needs.
#[derive(Clone)]
struct Shared {
    rpc: Arc<Rpc>,
    peers: Peers,
    limits: Arc<RateLimits>,
}

impl Shared {
    /// Closes every connection of `ip` (or of its IPv6 /64).
    fn disconnect_ip(&self, ip: IpAddr) {
        let key = IpKey::of(ip);
        let peers: Vec<Arc<Peer>> = self
            .peers
            .lock()
            .values()
            .filter(|peer| IpKey::of(peer.ip) == key)
            .cloned()
            .collect();
        // not under the lock: closing waits for a send in progress
        peers.iter().for_each(|peer| peer.disconnect());
    }
}

/// Listening addresses of the enabled Electrum services.
pub(crate) fn listeners(config: &Config) -> Vec<(Service, SocketAddr)> {
    let mut result = vec![];
    if !config.disable_electrum_rpc {
        result.push((Service::Tcp, config.electrum_rpc_addr));
    }
    for (service, addr) in [
        (Service::Ssl, config.electrum_ssl_addr),
        (Service::Ws, config.electrum_ws_addr),
        (Service::Wss, config.electrum_wss_addr),
    ] {
        if let Some(addr) = addr {
            result.push((service, addr));
        }
    }
    result
}

pub fn run() -> Result<()> {
    let result = serve();
    if let Err(e) = &result {
        for cause in e.chain() {
            if cause.downcast_ref::<ExitError>().is_some() {
                info!("electrs stopped: {:?}", e);
                return Ok(());
            }
        }
    }
    result.context("electrs failed")
}

/// Saves what is worth keeping for the next run, whatever way `serve` ends.
struct SaveOnExit(Arc<Rpc>);

impl Drop for SaveOnExit {
    fn drop(&mut self) {
        self.0.save_utxo_snapshots();
    }
}

fn serve() -> Result<()> {
    let config = Config::from_args();
    let metrics = Metrics::new(config.monitoring_addr)?;

    let tls = match (&config.ssl_certfile, &config.ssl_keyfile) {
        (Some(cert), Some(key)) => Some(Arc::new(TlsCertificate::load(cert, key)?)),
        _ => None,
    };
    let duration = metrics.histogram_vec(
        "server_loop_duration",
        "server loop duration",
        "step",
        metrics::default_duration_buckets(),
    );
    let rpc = Arc::new(Rpc::new(&config, metrics)?);
    let _save = SaveOnExit(Arc::clone(&rpc));
    let shared = Shared {
        rpc: Arc::clone(&rpc),
        peers: Default::default(),
        limits: Arc::new(RateLimits::new(config.limits.clone())),
    };
    let notifier = rayon::ThreadPoolBuilder::new()
        .num_threads(NOTIFY_THREADS)
        .thread_name(|i| format!("notify_{}", i))
        .build()
        .context("failed to start the notification threads")?;

    let next_peer_id = Arc::new(AtomicUsize::new(0));
    for (service, addr) in listeners(&config) {
        let listener = TcpListener::bind(addr)
            .with_context(|| format!("failed to bind {}://{}", service.scheme(), addr))?;
        info!(
            "serving Electrum RPC over {} on {}",
            service.scheme(),
            listener.local_addr()?
        );
        let tls = tls.clone();
        let ids = Arc::clone(&next_peer_id);
        let shared = shared.clone();
        spawn("accept_loop", move || {
            accept_loop(listener, service, tls, ids, shared)
        }); // detach accepting thread
    }

    // Client requests are handled by their connections' threads: this one
    // only indexes new blocks and the mempool, and queues notifications.
    let new_block_rx = rpc.new_block_notification();
    loop {
        // initial sync and compaction may take a few hours
        loop {
            let done = duration.observe_duration("sync", || rpc.sync().context("sync failed"))?;
            duration.observe_duration("notify", || notify_peers(&shared, &notifier));
            if !done {
                continue; // more blocks to sync
            }
            if config.sync_once {
                return Ok(()); // exit after initial sync is done
            }
            break;
        }
        duration.observe_duration("select", || -> Result<()> {
            select! {
                // Handle signals for graceful shutdown
                recv(rpc.signal().receiver()) -> result => {
                    result.context("signal channel disconnected")?;
                    rpc.signal().exit_flag().poll().context("RPC server interrupted")?;
                },
                // Handle new blocks' notifications
                recv(new_block_rx) -> result => match result {
                    Ok(_) => (), // sync and update
                    Err(_) => {
                        info!("disconnected from Neurai daemon");
                        return Ok(());
                    }
                },
                default(config.wait_duration) => (), // sync and update
            };
            Ok(())
        })?;
    }
}

/// Marks every peer as having pending notifications, and has the
/// notification threads send them to the idle ones (without waiting).
fn notify_peers(shared: &Shared, notifier: &rayon::ThreadPool) {
    let peers: Vec<Arc<Peer>> = shared.peers.lock().values().cloned().collect();
    for peer in peers {
        peer.pending.store(true, Ordering::SeqCst);
        if peer.queued.swap(true, Ordering::SeqCst) {
            continue; // a notification thread is about to look at it
        }
        let rpc = Arc::clone(&shared.rpc);
        notifier.spawn(move || {
            peer.queued.store(false, Ordering::SeqCst);
            // a busy peer gets them from its own thread, after its request
            if let Some(mut client) = peer.client.try_lock() {
                if let Err(e) = peer.notify(&rpc, &mut client) {
                    error!("failed to notify peer {}: {:#}", peer.id, e);
                    peer.disconnect();
                }
            }
        });
    }
}

fn accept_loop(
    listener: TcpListener,
    service: Service,
    tls: Option<Arc<TlsCertificate>>,
    next_peer_id: Arc<AtomicUsize>,
    shared: Shared,
) -> Result<()> {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(e) => {
                warn!("failed to accept {} connection: {}", service.scheme(), e);
                continue;
            }
        };
        let ip = match stream.peer_addr() {
            Ok(addr) => addr.ip(),
            Err(e) => {
                debug!(
                    "failed to get the address of a {} peer: {}",
                    service.scheme(),
                    e
                );
                continue;
            }
        };
        match shared.limits.connect(ip) {
            Ok(()) => (),
            Err(Refusal::Banned) => {
                debug!("{}: refused, banned", ip);
                continue;
            }
            Err(Refusal::TooManyConnections) => {
                debug!("{}: refused, too many connections", ip);
                continue;
            }
            Err(Refusal::Ban) => {
                warn!(
                    "banning {} for {:?}: too many connections",
                    IpKey::of(ip),
                    shared.limits.ban_duration()
                );
                shared.disconnect_ip(ip);
                continue;
            }
        }
        let peer_id = next_peer_id.fetch_add(1, Ordering::Relaxed);
        let tls = tls.as_ref().map(|certificate| certificate.config());
        let shared = shared.clone();
        spawn("recv_loop", move || {
            let result = match Connection::accept(stream, service, tls.as_ref()) {
                Ok(conn) => recv_loop(peer_id, ip, conn, &shared),
                Err(e) => {
                    debug!(
                        "{}: {} connection setup failed: {:#}",
                        peer_id,
                        service.scheme(),
                        e
                    );
                    Ok(())
                }
            };
            shared.limits.disconnect(ip);
            result
        });
    }
    Ok(())
}

fn recv_loop(peer_id: usize, ip: IpAddr, conn: Connection, shared: &Shared) -> Result<()> {
    let peer = Arc::new(Peer::new(peer_id, ip, conn.writer.clone()));
    debug!("{}: connected from {}", peer_id, ip);
    shared.peers.lock().insert(peer_id, Arc::clone(&peer));
    let result = serve_peer(&peer, conn, shared);
    shared.peers.lock().remove(&peer_id);
    peer.disconnect();
    debug!("{}: disconnected", peer_id);
    result
}

fn serve_peer(peer: &Peer, mut conn: Connection, shared: &Shared) -> Result<()> {
    let mut first = true;
    loop {
        let request = match conn.recv() {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(e) => {
                // the client's doing: a reset connection, or binary data
                // (TLS or other protocols sent to tcp://, scanners)
                debug!("{}: recv failed: {:#}", peer.id, e);
                break;
            }
        };
        debug!("{}: recv {}", peer.id, request);
        if first && is_http_request(&request) {
            // web scanners: no Electrum client sends HTTP here
            debug!("{}: HTTP request, disconnecting", peer.id);
            break;
        }
        first = false;
        if shared.limits.is_banned(peer.ip) {
            break;
        }

        take_waited();
        let start = Instant::now();
        // a notification thread may hold it: waiting, not work
        let mut client = waiting(|| peer.client.lock());
        let (response, calls) = shared.rpc.handle_request(&mut client, &request);
        let work = start.elapsed().saturating_sub(take_waited());
        let bytes = response.len();
        if let Err(e) = peer.send(vec![response]) {
            error!("{}: disconnecting due to {}", peer.id, e);
            break;
        }
        if client.should_disconnect() {
            debug!("{}: disconnecting after reply", peer.id);
            break;
        }
        if let Err(e) = peer.notify(&shared.rpc, &mut client) {
            error!("failed to notify peer {}: {:#}", peer.id, e);
            break;
        }
        drop(client);

        match shared
            .limits
            .charge(peer.ip, RateLimits::request_cost(calls, work, bytes))
        {
            Verdict::Proceed => (),
            Verdict::Throttle(delay) => {
                debug!("{}: {} throttled for {:?}", peer.id, peer.ip, delay);
                std::thread::sleep(delay);
            }
            Verdict::Ban => {
                warn!(
                    "banning {} for {:?}: over the cost hard limit",
                    IpKey::of(peer.ip),
                    shared.limits.ban_duration()
                );
                shared.disconnect_ip(peer.ip);
                break;
            }
        }
    }
    Ok(())
}

/// An HTTP request line (`GET / HTTP/1.1`, the HTTP/2 preface...).
fn is_http_request(line: &str) -> bool {
    const METHODS: &[&str] = &[
        "GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "TRACE ", "PATCH ",
        "PRI ",
    ];
    METHODS.iter().any(|method| line.starts_with(method)) && line.contains(" HTTP/")
}

#[cfg(test)]
mod tests {
    use super::is_http_request;

    #[test]
    fn http_request_lines() {
        assert!(is_http_request("GET / HTTP/1.1"));
        assert!(is_http_request("POST /api HTTP/1.0\r"));
        assert!(is_http_request("PRI * HTTP/2.0"));
        let request = r#"{"id":1,"method":"server.version","params":[]}"#;
        assert!(!is_http_request(request));
        assert!(!is_http_request("GET"));
        assert!(!is_http_request(r#"GET {"id":1}"#));
    }
}
