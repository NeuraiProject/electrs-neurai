use anyhow::{Context, Result};
use crossbeam_channel::{select, unbounded, Sender};
use rayon::prelude::*;

use std::{
    collections::hash_map::HashMap,
    iter::once,
    net::{SocketAddr, TcpListener},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::{
    config::Config,
    electrum::{Client, Rpc},
    metrics::{self, Metrics},
    signals::ExitError,
    thread::spawn,
    transport::{Connection, Service, TlsCertificate, Writer},
};

struct Peer {
    id: usize,
    client: Client,
    writer: Writer,
}

impl Peer {
    fn new(id: usize, writer: Writer) -> Self {
        let client = Client::default();
        Self { id, client, writer }
    }

    fn send(&mut self, values: Vec<String>) -> Result<()> {
        for value in values {
            debug!("{}: send {}", self.id, value);
            self.writer
                .send_message(&value)
                .with_context(|| format!("failed to send response: {:?}", value))?;
        }
        Ok(())
    }

    fn disconnect(self) {
        self.writer.close();
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

fn serve() -> Result<()> {
    let config = Config::from_args();
    let metrics = Metrics::new(config.monitoring_addr)?;

    let (server_tx, server_rx) = unbounded();
    let tls = match (&config.ssl_certfile, &config.ssl_keyfile) {
        (Some(cert), Some(key)) => Some(Arc::new(TlsCertificate::load(cert, key)?)),
        _ => None,
    };
    let next_peer_id = Arc::new(AtomicUsize::new(0));
    for (service, addr) in listeners(&config) {
        let listener = TcpListener::bind(addr)
            .with_context(|| format!("failed to bind {}://{}", service.scheme(), addr))?;
        info!(
            "serving Electrum RPC over {} on {}",
            service.scheme(),
            listener.local_addr()?
        );
        let tx = server_tx.clone();
        let tls = tls.clone();
        let ids = Arc::clone(&next_peer_id);
        spawn("accept_loop", move || accept_loop(listener, service, tls, ids, tx)); // detach accepting thread
    }
    // `server_tx` stays alive here, so the channel never disconnects even when
    // no listener is enabled (`disable_electrum_rpc`).

    let server_batch_size = metrics.histogram_vec(
        "server_batch_size",
        "# of server events handled in a single batch",
        "type",
        metrics::default_size_buckets(),
    );
    let duration = metrics.histogram_vec(
        "server_loop_duration",
        "server loop duration",
        "step",
        metrics::default_duration_buckets(),
    );
    let mut rpc = Rpc::new(&config, metrics)?;

    let new_block_rx = rpc.new_block_notification();
    let mut peers = HashMap::<usize, Peer>::new();
    loop {
        // initial sync and compaction may take a few hours
        while server_rx.is_empty() {
            let done = duration.observe_duration("sync", || rpc.sync().context("sync failed"))?; // sync a batch of blocks
            peers = duration.observe_duration("notify", || notify_peers(&rpc, peers)); // peers are disconnected on error
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
                // Handle Electrum RPC requests
                recv(server_rx) -> event => {
                    let first = once(event.context("server disconnected")?);
                    let rest = server_rx.iter().take(server_rx.len());
                    let events: Vec<Event> = first.chain(rest).collect();
                    server_batch_size.observe("recv", events.len() as f64);
                    duration.observe_duration("handle", || handle_events(&rpc, &mut peers, events));
                },
                default(config.wait_duration) => (), // sync and update
            };
            Ok(())
        })?;
    }
}

fn notify_peers(rpc: &Rpc, peers: HashMap<usize, Peer>) -> HashMap<usize, Peer> {
    peers
        .into_par_iter()
        .filter_map(|(_, mut peer)| match notify_peer(rpc, &mut peer) {
            Ok(()) => Some((peer.id, peer)),
            Err(e) => {
                error!("failed to notify peer {}: {}", peer.id, e);
                peer.disconnect();
                None
            }
        })
        .collect()
}

fn notify_peer(rpc: &Rpc, peer: &mut Peer) -> Result<()> {
    let notifications = rpc
        .update_client(&mut peer.client)
        .context("failed to generate notifications")?;
    peer.send(notifications)
        .context("failed to send notifications")
}

struct Event {
    peer_id: usize,
    msg: Message,
}

enum Message {
    New(Writer),
    Request(String),
    Done,
}

fn handle_events(rpc: &Rpc, peers: &mut HashMap<usize, Peer>, events: Vec<Event>) {
    let mut events_by_peer = HashMap::<usize, Vec<Message>>::new();
    events
        .into_iter()
        .for_each(|e| events_by_peer.entry(e.peer_id).or_default().push(e.msg));
    for (peer_id, messages) in events_by_peer {
        handle_peer_events(rpc, peers, peer_id, messages);
    }
}

fn handle_peer_events(
    rpc: &Rpc,
    peers: &mut HashMap<usize, Peer>,
    peer_id: usize,
    messages: Vec<Message>,
) {
    let mut lines = vec![];
    let mut done = false;
    for msg in messages {
        match msg {
            Message::New(writer) => {
                debug!("{}: connected", peer_id);
                peers.insert(peer_id, Peer::new(peer_id, writer));
            }
            Message::Request(line) => lines.push(line),
            Message::Done => {
                done = true;
                break;
            }
        }
    }
    let result = match peers.get_mut(&peer_id) {
        Some(peer) => {
            let responses = rpc.handle_requests(&mut peer.client, &lines);
            peer.send(responses)
        }
        None => return, // unknown peer
    };
    if let Err(e) = result {
        error!("{}: disconnecting due to {}", peer_id, e);
        peers.remove(&peer_id).unwrap().disconnect();
    } else if peers.get(&peer_id).is_some_and(|p| p.client.should_disconnect()) {
        debug!("{}: disconnecting after reply", peer_id);
        peers.remove(&peer_id).unwrap().disconnect();
    } else if done {
        peers.remove(&peer_id); // already disconnected, just remove from peers' map
    }
}

fn accept_loop(
    listener: TcpListener,
    service: Service,
    tls: Option<Arc<TlsCertificate>>,
    next_peer_id: Arc<AtomicUsize>,
    server_tx: Sender<Event>,
) -> Result<()> {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(e) => {
                warn!("failed to accept {} connection: {}", service.scheme(), e);
                continue;
            }
        };
        let peer_id = next_peer_id.fetch_add(1, Ordering::Relaxed);
        let tx = server_tx.clone();
        let tls = tls.as_ref().map(|certificate| certificate.config());
        spawn("recv_loop", move || {
            let conn = match Connection::accept(stream, service, tls.as_ref()) {
                Ok(conn) => conn,
                Err(e) => {
                    debug!("{}: {} connection setup failed: {:#}", peer_id, service.scheme(), e);
                    return Ok(());
                }
            };
            recv_loop(peer_id, conn, tx)
        });
    }
    Ok(())
}

fn recv_loop(peer_id: usize, mut conn: Connection, server_tx: Sender<Event>) -> Result<()> {
    let msg = Message::New(conn.writer.clone());
    server_tx.send(Event { peer_id, msg })?;

    let mut first = true;
    loop {
        match conn.recv() {
            Ok(Some(request)) => {
                debug!("{}: recv {}", peer_id, request);
                if first && is_http_request(&request) {
                    // web scanners: no Electrum client sends HTTP here
                    debug!("{}: HTTP request, disconnecting", peer_id);
                    break;
                }
                first = false;
                let msg = Message::Request(request);
                server_tx.send(Event { peer_id, msg })?;
            }
            Ok(None) => break,
            Err(e) => {
                // the client's doing: a reset connection, or binary data
                // (TLS or other protocols sent to tcp://, scanners)
                debug!("{}: recv failed: {:#}", peer_id, e);
                break;
            }
        }
    }

    debug!("{}: disconnected", peer_id);
    let msg = Message::Done;
    server_tx.send(Event { peer_id, msg })?;
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
