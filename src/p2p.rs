use anyhow::{Context, Result};
use bitcoin::consensus::Encodable;
use bitcoin::{
    consensus::{
        encode::{self, ReadExt, VarInt},
        Decodable,
    },
    hashes::Hash,
    io,
    p2p::{
        self, address,
        message::{self, CommandString, NetworkMessage},
        message_blockdata::{GetHeadersMessage, Inventory},
        message_network, Magic,
    },
    secp256k1::{self, rand::Rng},
    BlockHash,
};
use crossbeam_channel::{bounded, select, Receiver, Sender};

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::neurai::block::{decode_header, header_len, verify_kawpow_header, NeuraiBlockHeader};
use crate::neurai::NetworkParams;
use crate::types::SerBlock;
use crate::{
    chain::{Chain, NewHeader},
    config::ELECTRS_VERSION,
    metrics::{default_duration_buckets, default_size_buckets, Histogram, Metrics},
};

enum Request {
    GetNewHeaders(GetHeadersMessage),
    GetBlocks(Vec<Inventory>),
}

impl Request {
    fn get_new_headers(chain: &Chain) -> Request {
        Request::GetNewHeaders(GetHeadersMessage::new(
            chain.locator(),
            BlockHash::all_zeros(),
        ))
    }

    fn get_blocks(blockhashes: &[BlockHash]) -> Request {
        Request::GetBlocks(
            blockhashes
                .iter()
                .map(|blockhash| Inventory::WitnessBlock(*blockhash))
                .collect(),
        )
    }
}

pub(crate) struct Connection {
    req_send: Sender<Request>,
    blocks_recv: Receiver<SerBlock>,
    headers_recv: Receiver<Vec<NeuraiBlockHeader>>,
    new_block_recv: Receiver<()>,
    blocks_duration: Histogram,
    params: &'static NetworkParams,
}

impl Connection {
    /// Get new block headers (supporting reorgs).
    /// https://en.bitcoin.it/wiki/Protocol_documentation#getheaders
    pub(crate) fn get_new_headers(&mut self, chain: &Chain) -> Result<Vec<NewHeader>> {
        self.req_send.send(Request::get_new_headers(chain))?;
        let headers = self
            .headers_recv
            .recv()
            .context("failed to get new headers")?;

        debug!("got {} new headers", headers.len());
        let prev_blockhash = match headers.first() {
            None => return Ok(vec![]),
            Some(first) => first.prev_blockhash,
        };
        let new_heights = match chain.get_block_height(&prev_blockhash) {
            Some(last_height) => (last_height + 1)..,
            None => bail!("missing prev_blockhash: {}", prev_blockhash),
        };
        let params = self.params;
        headers
            .into_iter()
            .zip(new_heights)
            .map(|(header, height)| {
                let hash = header
                    .block_hash(params)
                    .context("p2p header must have computable hash")?;
                // Re-run the KAWPOW FFI verifier here — otherwise a header with
                // a corrupt `mix_hash` would still land in `Chain` (and in the
                // responses to `blockchain.block.header{,s}` / `headers.subscribe`)
                // even before the block body is downloaded.
                if !verify_kawpow_header(&header, &hash) {
                    bail!("header at height {height} ({hash}) failed KAWPOW mix_hash verification");
                }
                Ok(NewHeader::new(header, hash, height))
            })
            .collect()
    }

    /// Request and process the specified blocks (in the specified order).
    pub(crate) fn for_blocks<B, F>(&mut self, blockhashes: B, mut func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        self.blocks_duration.observe_duration("total", || {
            let blockhashes: Vec<BlockHash> = blockhashes.into_iter().collect();
            if blockhashes.is_empty() {
                return Ok(());
            }
            self.blocks_duration.observe_duration("request", || {
                debug!("loading {} blocks", blockhashes.len());
                self.req_send.send(Request::get_blocks(&blockhashes))
            })?;

            let params = self.params;
            for hash in blockhashes {
                let block = self.blocks_duration.observe_duration("response", || {
                    let block = self
                        .blocks_recv
                        .recv()
                        .with_context(|| format!("failed to get block {}", hash))?;

                    // Verify the block hash using the Neurai-appropriate algorithm.
                    let hdr_len = header_len(&block, params)
                        .with_context(|| format!("short block received for {}", hash))?;
                    let neurai_hdr = decode_header(&mut &block[..hdr_len], params)
                        .with_context(|| format!("invalid header in block {}", hash))?;
                    let computed = neurai_hdr
                        .block_hash(params)
                        .with_context(|| format!("cannot compute hash for block {}", hash))?;
                    ensure!(computed == hash, "got unexpected block");
                    // `block_hash()` runs KAWPOW but ignores the mix_hash field of the
                    // incoming header — re-run the FFI verifier so a corrupted mix_hash
                    // cannot land in the index alongside an otherwise-valid hash.
                    ensure!(
                        verify_kawpow_header(&neurai_hdr, &computed),
                        "block {} failed KAWPOW mix_hash verification",
                        hash,
                    );

                    Ok(block)
                })?;
                self.blocks_duration
                    .observe_duration("process", || func(hash, block));
            }
            Ok(())
        })
    }

    pub(crate) fn new_block_notification(&self) -> Receiver<()> {
        self.new_block_recv.clone()
    }

    pub(crate) fn connect(
        address: SocketAddr,
        metrics: &Metrics,
        params: &'static NetworkParams,
    ) -> Result<Self> {
        let magic = params.magic;
        let recv_conn = TcpStream::connect(address)
            .with_context(|| format!("p2p failed to connect: {:?}", address))?;
        let mut send_conn = recv_conn
            .try_clone()
            .context("failed to clone connection")?;

        let (tx_send, tx_recv) = bounded::<NetworkMessage>(1);
        let (rx_send, rx_recv) = bounded::<RawNetworkMessage>(1);

        let send_duration = metrics.histogram_vec(
            "p2p_send_duration",
            "Time spent sending p2p messages (in seconds)",
            "step",
            default_duration_buckets(),
        );
        let recv_duration = metrics.histogram_vec(
            "p2p_recv_duration",
            "Time spent receiving p2p messages (in seconds)",
            "step",
            default_duration_buckets(),
        );
        let parse_duration = metrics.histogram_vec(
            "p2p_parse_duration",
            "Time spent parsing p2p messages (in seconds)",
            "step",
            default_duration_buckets(),
        );
        let recv_size = metrics.histogram_vec(
            "p2p_recv_size",
            "Size of p2p messages read (in bytes)",
            "message",
            default_size_buckets(),
        );
        let blocks_duration = metrics.histogram_vec(
            "p2p_blocks_duration",
            "Time spent getting blocks via p2p protocol (in seconds)",
            "step",
            default_duration_buckets(),
        );

        let mut buffer = vec![];
        crate::thread::spawn("p2p_send", move || loop {
            use std::net::Shutdown;
            let msg = match send_duration.observe_duration("wait", || tx_recv.recv()) {
                Ok(msg) => msg,
                Err(_) => {
                    debug!("closing p2p_send thread: no more messages to send");
                    if let Err(e) = send_conn.shutdown(Shutdown::Read) {
                        warn!("failed to shutdown p2p connection: {}", e)
                    }
                    return Ok(());
                }
            };
            send_duration.observe_duration("send", || {
                trace!("send: {:?}", msg);
                let raw_msg = message::RawNetworkMessage::new(magic, msg);
                buffer.clear();
                raw_msg
                    .consensus_encode(&mut buffer)
                    .expect("in-memory writers don't error");
                send_conn
                    .write_all(buffer.as_slice())
                    .context("p2p failed to send")
            })?;
        });

        let mut stream_reader = std::io::BufReader::new(recv_conn);
        crate::thread::spawn("p2p_recv", move || loop {
            let start = Instant::now();
            let raw_msg = RawNetworkMessage::consensus_decode(&mut stream_reader);
            {
                let duration = duration_to_seconds(start.elapsed());
                let label = format!(
                    "recv_{}",
                    raw_msg
                        .as_ref()
                        .map(|msg| msg.cmd.as_ref())
                        .unwrap_or("err")
                );
                recv_duration.observe(&label, duration);
            }
            let raw_msg = match raw_msg {
                Ok(raw_msg) => {
                    recv_size.observe(raw_msg.cmd.as_ref(), raw_msg.raw.len() as f64);
                    if raw_msg.magic != magic {
                        bail!("unexpected magic {} (instead of {})", raw_msg.magic, magic)
                    }
                    raw_msg
                }
                Err(encode::Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!("closing p2p_recv thread: connection closed");
                    return Ok(());
                }
                Err(e) => bail!("failed to recv a message from peer: {}", e),
            };

            recv_duration.observe_duration("wait", || rx_send.send(raw_msg))?;
        });

        let (req_send, req_recv) = bounded::<Request>(1);
        let (blocks_send, blocks_recv) = bounded::<SerBlock>(10);
        let (headers_send, headers_recv) = bounded::<Vec<NeuraiBlockHeader>>(1);
        let (new_block_send, new_block_recv) = bounded::<()>(0);
        let (init_send, init_recv) = bounded::<()>(0);

        tx_send.send(build_version_message())?;

        crate::thread::spawn("p2p_loop", move || loop {
            select! {
                recv(rx_recv) -> result => {
                    let raw_msg = match result {
                        Ok(raw_msg) => raw_msg,
                        Err(_) => {
                            debug!("closing p2p_loop thread: peer has disconnected");
                            return Ok(());
                        }
                    };

                    let label = format!("parse_{}", raw_msg.cmd.as_ref());
                    let msg = match parse_duration.observe_duration(&label, || raw_msg.parse(params)) {
                        Ok(msg) => msg,
                        Err(err) => bail!("failed to parse {err}"),
                    };
                    trace!("recv: {:?}", msg);

                    match msg {
                        ParsedNetworkMessage::Version(version) => {
                            debug!("peer version: {:?}", version);
                            tx_send.send(NetworkMessage::Verack)?;
                        }
                        ParsedNetworkMessage::Inv(inventory) => {
                            debug!("peer inventory: {:?}", inventory);
                            if inventory.iter().any(|inv| matches!(inv, Inventory::Block(_))) {
                                let _ = new_block_send.try_send(());
                            }
                        },
                        ParsedNetworkMessage::Ping(nonce) => {
                            tx_send.send(NetworkMessage::Pong(nonce))?;
                        }
                        ParsedNetworkMessage::Verack => {
                            init_send.send(())?;
                        }
                        ParsedNetworkMessage::Block(block) => blocks_send.send(block)?,
                        ParsedNetworkMessage::Headers(headers) => headers_send.send(headers)?,
                        ParsedNetworkMessage::Ignored => (),
                    }
                }
                recv(req_recv) -> result => {
                    let req = match result {
                        Ok(req) => req,
                        Err(_) => {
                            debug!("closing p2p_loop thread: no more requests to handle");
                            return Ok(());
                        }
                    };
                    let msg = match req {
                        Request::GetNewHeaders(msg) => NetworkMessage::GetHeaders(msg),
                        Request::GetBlocks(inv) => NetworkMessage::GetData(inv),
                    };
                    tx_send.send(msg)?;
                }
            }
        });

        init_recv.recv()?;

        Ok(Connection {
            req_send,
            blocks_recv,
            headers_recv,
            new_block_recv,
            blocks_duration,
            params,
        })
    }
}

fn build_version_message() -> NetworkMessage {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time error")
        .as_secs() as i64;

    let services = p2p::ServiceFlags::NONE;

    NetworkMessage::Version(message_network::VersionMessage {
        version: p2p::PROTOCOL_VERSION,
        services,
        timestamp,
        receiver: address::Address::new(&addr, services),
        sender: address::Address::new(&addr, services),
        nonce: secp256k1::rand::thread_rng().gen(),
        user_agent: format!("/electrs:{}/", ELECTRS_VERSION),
        start_height: 0,
        relay: false,
    })
}

struct RawNetworkMessage {
    magic: Magic,
    cmd: CommandString,
    raw: Vec<u8>,
}

impl RawNetworkMessage {
    fn parse(self, params: &'static NetworkParams) -> Result<ParsedNetworkMessage> {
        let mut raw: &[u8] = &self.raw;
        let payload = match self.cmd.as_ref() {
            "version" => ParsedNetworkMessage::Version(Decodable::consensus_decode(&mut raw)?),
            "verack" => ParsedNetworkMessage::Verack,
            "inv" => ParsedNetworkMessage::Inv(Decodable::consensus_decode(&mut raw)?),
            "block" => ParsedNetworkMessage::Block(self.raw),
            "headers" => {
                // Each entry in the p2p headers message is: serialized_header + VarInt(0)
                let len = VarInt::consensus_decode(&mut raw)?.0;
                let mut headers = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    headers.push(decode_header(&mut raw, params)?);
                    let _tx_count = VarInt::consensus_decode(&mut raw)?; // always 0
                }
                ParsedNetworkMessage::Headers(headers)
            }
            "ping" => ParsedNetworkMessage::Ping(Decodable::consensus_decode(&mut raw)?),
            "pong" => ParsedNetworkMessage::Ignored,
            "addr" => ParsedNetworkMessage::Ignored,
            "alert" => ParsedNetworkMessage::Ignored,
            _ => bail!(
                "unsupported message: command={}, payload={:?}",
                self.cmd,
                self.raw
            ),
        };
        Ok(payload)
    }
}

#[derive(Debug)]
enum ParsedNetworkMessage {
    Version(message_network::VersionMessage),
    Verack,
    Inv(Vec<Inventory>),
    Ping(u64),
    Headers(Vec<NeuraiBlockHeader>),
    Block(SerBlock),
    Ignored,
}

impl Decodable for RawNetworkMessage {
    fn consensus_decode<D: bitcoin::io::Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let magic = Decodable::consensus_decode(d)?;
        let cmd = Decodable::consensus_decode(d)?;

        let len = u32::consensus_decode(d)?;
        let _checksum = <[u8; 4]>::consensus_decode(d)?;
        let mut raw = vec![0u8; len as usize];
        d.read_slice(&mut raw)?;

        Ok(RawNetworkMessage { magic, cmd, raw })
    }
}

/// `duration_to_seconds` converts Duration to seconds.
#[inline]
pub fn duration_to_seconds(d: Duration) -> f64 {
    let nanos = f64::from(d.subsec_nanos()) / 1e9;
    d.as_secs() as f64 + nanos
}
