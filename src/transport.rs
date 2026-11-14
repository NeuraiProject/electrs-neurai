//! Electrum client transports.
//!
//! * `tcp://` and `ssl://` carry newline-delimited JSON-RPC, as every Electrum
//!   server does.
//! * `ws://` and `wss://` carry exactly one JSON-RPC message (or batch) per
//!   WebSocket message, with no trailing newline. Outgoing responses and
//!   notifications are each sent as their own *text* message. This is the
//!   framing ElectrumX uses through aiorpcX 0.22 (`aiorpcx/websocket.py`), so
//!   web clients written for ElectrumX work unchanged.
//!
//! Each connection has one reading thread that blocks on the socket, and a
//! [`Writer`] shared between the server loop (responses, notifications) and
//! that thread (TLS handshake records, WebSocket pongs and close replies).

use anyhow::{bail, Context, Result};
use bitcoin::hashes::{sha1, Hash};
use parking_lot::Mutex;

use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::Arc;

/// Kind of Electrum listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Service {
    Tcp,
    Ssl,
    Ws,
    Wss,
}

impl Service {
    pub(crate) fn uses_tls(self) -> bool {
        matches!(self, Service::Ssl | Service::Wss)
    }

    pub(crate) fn uses_websocket(self) -> bool {
        matches!(self, Service::Ws | Service::Wss)
    }

    /// URL scheme, as used in `server.features` `services`.
    pub(crate) fn scheme(self) -> &'static str {
        match self {
            Service::Tcp => "tcp",
            Service::Ssl => "ssl",
            Service::Ws => "ws",
            Service::Wss => "wss",
        }
    }

    pub(crate) fn from_scheme(scheme: &str) -> Option<Service> {
        match scheme {
            "tcp" => Some(Service::Tcp),
            "ssl" => Some(Service::Ssl),
            "ws" => Some(Service::Ws),
            "wss" => Some(Service::Wss),
            _ => None,
        }
    }
}

/// Load the PEM certificate chain and private key used by `ssl://` and `wss://`.
pub(crate) fn load_tls_config(
    certfile: &Path,
    keyfile: &Path,
) -> Result<Arc<rustls::ServerConfig>> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

    let certs = CertificateDer::pem_file_iter(certfile)
        .with_context(|| format!("failed to read {}", certfile.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("invalid certificate in {}", certfile.display()))?;
    if certs.is_empty() {
        bail!("no certificate found in {}", certfile.display());
    }
    let key = PrivateKeyDer::from_pem_file(keyfile)
        .with_context(|| format!("failed to read private key from {}", keyfile.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("unsupported TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate or key")?;
    Ok(Arc::new(config))
}

// ─── TLS session shared by the reading thread and the writers ────────────────

struct TlsSession {
    conn: rustls::ServerConnection,
    tcp: TcpStream,
}

impl TlsSession {
    fn flush_tls(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.tcp)?;
        }
        Ok(())
    }
}

/// Plaintext reader over a TLS session. Blocks on the socket *without* holding
/// the session lock, so writers are never stalled by an idle client.
struct TlsReader {
    session: Arc<Mutex<TlsSession>>,
    tcp: TcpStream,
    raw: Box<[u8]>,
    start: usize,
    end: usize,
}

impl Read for TlsReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut s = self.session.lock();
                match s.conn.reader().read(out) {
                    Ok(n) => return Ok(n), // 0 = close_notify received
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                    Err(e) => return Err(e),
                }
                if self.start < self.end {
                    let mut pending = &self.raw[self.start..self.end];
                    s.conn.read_tls(&mut pending)?;
                    self.start = self.end - pending.len();
                    if let Err(e) = s.conn.process_new_packets() {
                        let _ = s.flush_tls(); // send the alert, if any
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                    s.flush_tls()?; // handshake records, key updates...
                    continue;
                }
            }
            let n = self.tcp.read(&mut self.raw)?;
            if n == 0 {
                return Ok(0);
            }
            self.start = 0;
            self.end = n;
        }
    }
}

enum Sink {
    Tcp(TcpStream),
    Tls(Arc<Mutex<TlsSession>>),
}

impl Sink {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Sink::Tcp(tcp) => tcp.write_all(data),
            Sink::Tls(session) => {
                let mut s = session.lock();
                let mut data = data;
                while !data.is_empty() {
                    // rustls holds at most its buffer limit (64 KiB) of unsent TLS
                    // records and then accepts nothing more: send them and go on.
                    let mut n = s.conn.writer().write(data)?;
                    if n == 0 {
                        s.flush_tls()?;
                        n = s.conn.writer().write(data)?;
                        if n == 0 {
                            return Err(io::ErrorKind::WriteZero.into());
                        }
                    }
                    data = &data[n..];
                }
                s.flush_tls()
            }
        }
    }

    fn shutdown(&mut self) {
        match self {
            Sink::Tcp(tcp) => {
                let _ = tcp.shutdown(Shutdown::Both);
            }
            Sink::Tls(session) => {
                let mut s = session.lock();
                s.conn.send_close_notify();
                let _ = s.flush_tls();
                let _ = s.tcp.shutdown(Shutdown::Both);
            }
        }
    }
}

/// Write side of a client connection, cheap to clone.
#[derive(Clone)]
pub(crate) struct Writer {
    sink: Arc<Mutex<Sink>>,
    websocket: bool,
}

impl Writer {
    /// Send one JSON-RPC message (response, batch response or notification).
    pub(crate) fn send_message(&self, message: &str) -> io::Result<()> {
        let mut sink = self.sink.lock();
        if self.websocket {
            sink.write_all(&ws_frame(OP_TEXT, message.as_bytes()))
        } else {
            let mut line = Vec::with_capacity(message.len() + 1);
            line.extend_from_slice(message.as_bytes());
            line.push(b'\n');
            sink.write_all(&line)
        }
    }

    fn write_raw(&self, data: &[u8]) -> io::Result<()> {
        self.sink.lock().write_all(data)
    }

    pub(crate) fn close(&self) {
        let mut sink = self.sink.lock();
        if self.websocket {
            let _ = sink.write_all(&ws_frame(OP_CLOSE, &1000u16.to_be_bytes()));
        }
        sink.shutdown();
    }
}

/// An accepted connection, split into its reading half and its [`Writer`].
pub(crate) struct Connection {
    pub(crate) writer: Writer,
    reader: io::BufReader<Box<dyn Read + Send>>,
    websocket: bool,
}

impl Connection {
    /// Wrap an accepted socket. For `wss://`/`ssl://` this sets up (but does
    /// not yet drive) the TLS session; for `ws://`/`wss://` it performs the
    /// HTTP upgrade handshake.
    pub(crate) fn accept(
        tcp: TcpStream,
        service: Service,
        tls: Option<&Arc<rustls::ServerConfig>>,
    ) -> Result<Self> {
        tcp.set_nodelay(true).ok();
        // A client that stops reading must not stall the server loop forever.
        tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
        let read_half = tcp.try_clone().context("failed to clone socket")?;
        let websocket = service.uses_websocket();
        let (sink, reader): (Sink, Box<dyn Read + Send>) = if service.uses_tls() {
            let config = tls.context("TLS listener without TLS configuration")?;
            let conn = rustls::ServerConnection::new(Arc::clone(config))
                .context("failed to create TLS session")?;
            let session = Arc::new(Mutex::new(TlsSession { conn, tcp }));
            let reader = TlsReader {
                session: Arc::clone(&session),
                tcp: read_half,
                raw: vec![0u8; 16 * 1024].into_boxed_slice(),
                start: 0,
                end: 0,
            };
            (Sink::Tls(session), Box::new(reader))
        } else {
            (Sink::Tcp(tcp), Box::new(read_half))
        };
        let mut conn = Connection {
            writer: Writer {
                sink: Arc::new(Mutex::new(sink)),
                websocket,
            },
            reader: io::BufReader::new(reader),
            websocket,
        };
        if websocket {
            ws_handshake(&mut conn.reader, &conn.writer)?;
        }
        Ok(conn)
    }

    /// Next JSON-RPC message from the client, or `None` once it disconnected.
    pub(crate) fn recv(&mut self) -> Result<Option<String>> {
        if self.websocket {
            return read_ws_message(&mut self.reader, &self.writer);
        }
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => {
                while line.ends_with('\n') || line.ends_with('\r') {
                    line.pop();
                }
                Ok(Some(line))
            }
            Err(e) => Err(e.into()),
        }
    }
}

// ─── WebSocket (RFC 6455) ─────────────────────────────────────────────────────

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Same incoming size limit as ElectrumX (`MAX_RECV`, 5 MB).
const MAX_WS_MESSAGE: usize = 5_000_000;
const MAX_HTTP_HEADERS: usize = 16 * 1024;

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_TOO_BIG: u16 = 1009;

/// Server → client frame: FIN set, never masked.
fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | opcode);
    let n = payload.len();
    if n < 126 {
        frame.push(n as u8);
    } else if n <= 0xffff {
        frame.push(126);
        frame.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(n as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

pub(crate) fn websocket_accept_key(key: &str) -> String {
    let digest = sha1::Hash::hash(format!("{}{}", key.trim(), WS_GUID).as_bytes());
    base64_encode(digest.as_byte_array())
}

fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn ws_handshake<R: BufRead>(reader: &mut R, writer: &Writer) -> Result<()> {
    let mut request = Vec::<String>::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .context("failed to read HTTP request")?;
        if n == 0 {
            bail!("connection closed during WebSocket handshake");
        }
        total += n;
        if total > MAX_HTTP_HEADERS {
            bail!("HTTP request headers too large");
        }
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        if line.is_empty() {
            break;
        }
        request.push(line);
    }
    let header = |name: &str| -> Option<&str> {
        request.iter().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
    };
    let has_token = |value: Option<&str>, token: &str| {
        value.is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    let valid = request.first().is_some_and(|l| l.starts_with("GET "))
        && has_token(header("upgrade"), "websocket")
        && has_token(header("connection"), "upgrade")
        && header("sec-websocket-version") == Some("13");
    let key = match (valid, header("sec-websocket-key")) {
        (true, Some(key)) if !key.is_empty() => key.to_owned(),
        _ => {
            let _ = writer.write_raw(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            );
            bail!("invalid WebSocket upgrade request: {:?}", request.first());
        }
    };
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        websocket_accept_key(&key)
    );
    writer.write_raw(response.as_bytes())?;
    Ok(())
}

fn ws_close(writer: &Writer, code: u16, why: &str) -> Result<Option<String>> {
    let _ = writer.write_raw(&ws_frame(OP_CLOSE, &code.to_be_bytes()));
    bail!("closing WebSocket ({}): {}", code, why)
}

/// Read the next complete data message, answering control frames on the way.
fn read_ws_message<R: Read>(reader: &mut R, writer: &Writer) -> Result<Option<String>> {
    let mut message: Option<Vec<u8>> = None;
    loop {
        let mut head = [0u8; 2];
        match reader.read_exact(&mut head) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && message.is_none() => {
                return Ok(None)
            }
            Err(e) => return Err(e.into()),
        }
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        if head[0] & 0x70 != 0 {
            return ws_close(writer, CLOSE_PROTOCOL_ERROR, "reserved bits set");
        }
        if head[1] & 0x80 == 0 {
            return ws_close(writer, CLOSE_PROTOCOL_ERROR, "unmasked client frame");
        }
        let len = match head[1] & 0x7f {
            126 => {
                let mut b = [0u8; 2];
                reader.read_exact(&mut b)?;
                u64::from(u16::from_be_bytes(b))
            }
            127 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b)?;
                u64::from_be_bytes(b)
            }
            n => u64::from(n),
        };
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask)?;
        if opcode >= OP_CLOSE && (!fin || len > 125) {
            return ws_close(writer, CLOSE_PROTOCOL_ERROR, "invalid control frame");
        }
        let buffered = message.as_ref().map_or(0, Vec::len) as u64;
        if buffered + len > MAX_WS_MESSAGE as u64 {
            return ws_close(writer, CLOSE_TOO_BIG, "message too large");
        }
        let mut payload = vec![0u8; len as usize];
        reader.read_exact(&mut payload)?;
        payload
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b ^= mask[i % 4]);

        match opcode {
            OP_TEXT | OP_BINARY => {
                if message.is_some() {
                    return ws_close(
                        writer,
                        CLOSE_PROTOCOL_ERROR,
                        "unfinished fragmented message",
                    );
                }
                message = Some(payload);
            }
            OP_CONTINUATION => match message.as_mut() {
                Some(m) => m.extend_from_slice(&payload),
                None => return ws_close(writer, CLOSE_PROTOCOL_ERROR, "unexpected continuation"),
            },
            OP_PING => {
                writer.write_raw(&ws_frame(OP_PONG, &payload))?;
                continue;
            }
            OP_PONG => continue,
            OP_CLOSE => {
                let code = if payload.len() >= 2 {
                    &payload[..2]
                } else {
                    &[0x03, 0xe8][..]
                };
                let _ = writer.write_raw(&ws_frame(OP_CLOSE, code));
                return Ok(None);
            }
            _ => return ws_close(writer, CLOSE_PROTOCOL_ERROR, "unknown opcode"),
        }
        if fin {
            let data = message.take().expect("data frame sets the message");
            return Ok(Some(String::from_utf8_lossy(&data).into_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc6455_example() {
        // RFC 6455 §1.3
        assert_eq!(
            websocket_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn base64_padding() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// Self-signed P-256 certificate for `localhost`, valid until 2126 (tests only).
    const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBkjCCATigAwIBAgIUDx0PAu2Spp9KUduzdxhs8HYCmCwwCgYIKoZIzj0EAwIw\nFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExNDIzMjc0NVoYDzIxMjYxMDIx\nMjMyNzQ1WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO\nPQMBBwNCAARpVa33PlptV4TCEyf1/kmciLD/y58zq8oUQiHFQDUg+OGrb5NMEF+w\nU41QUIQu5b1r8U0R5GbIlq+3gVW4MPbmo2YwZDAdBgNVHQ4EFgQUeAywKP6DHgB5\nQoLePP0MZvF0RIgwHwYDVR0jBBgwFoAUeAywKP6DHgB5QoLePP0MZvF0RIgwFAYD\nVR0RBA0wC4IJbG9jYWxob3N0MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAw\nRQIhANFhrKcqGc6wOrdGOXkH8BkyL36FcuLi6A+pviLSUGb4AiAp3LPmKITvLVIM\n/ug2HOXlGBJpg8Ir77hvcn6IlXVBUw==\n-----END CERTIFICATE-----\n";
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeLAjFV+6QYuBlT5g\n9XuIw+oN0mgRViF6uEZWikLhTEahRANCAARpVa33PlptV4TCEyf1/kmciLD/y58z\nq8oUQiHFQDUg+OGrb5NMEF+wU41QUIQu5b1r8U0R5GbIlq+3gVW4MPbm\n-----END PRIVATE KEY-----\n";

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let dir = std::env::temp_dir().join(format!("electrs-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert, TEST_CERT).unwrap();
        std::fs::write(&key, TEST_KEY).unwrap();
        let config = load_tls_config(&cert, &key).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        config
    }

    fn tls_client(
        addr: std::net::SocketAddr,
    ) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
        use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(TEST_CERT.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from("localhost").unwrap();
        let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        rustls::StreamOwned::new(conn, TcpStream::connect(addr).unwrap())
    }

    /// Replies larger than rustls's 64 KiB send buffer (2016 headers are ~480 KB)
    /// must reach the client whole, over `ssl://` and `wss://`.
    #[test]
    fn large_tls_messages() {
        for service in [Service::Ssl, Service::Wss] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let config = test_server_config();
            let reply = format!("{{\"result\":\"{}\"}}", "ab".repeat(300_000));
            let expected = reply.clone();
            let server = std::thread::spawn(move || {
                let (tcp, _) = listener.accept().unwrap();
                let mut conn = Connection::accept(tcp, service, Some(&config)).unwrap();
                assert_eq!(conn.recv().unwrap().as_deref(), Some("ping"));
                conn.writer.send_message(&reply).unwrap();
                conn.writer.send_message("bye").unwrap();
            });

            let mut client = tls_client(addr);
            let received = if service == Service::Wss {
                client
                    .write_all(
                        b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
                          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                    )
                    .unwrap();
                let mut reader = io::BufReader::new(client);
                let mut line = String::new();
                while line != "\r\n" {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                }
                let mut masked = vec![0x81, 0x80 | 4, 1, 2, 3, 4];
                masked.extend(
                    b"ping"
                        .iter()
                        .zip([1, 2, 3, 4].iter().cycle())
                        .map(|(b, m)| b ^ m),
                );
                reader.get_mut().write_all(&masked).unwrap();
                let mut header = [0u8; 10];
                reader.read_exact(&mut header).unwrap();
                assert_eq!(&header[..2], &[0x81, 127]);
                let len = u64::from_be_bytes(header[2..10].try_into().unwrap()) as usize;
                let mut payload = vec![0u8; len];
                reader.read_exact(&mut payload).unwrap();
                String::from_utf8(payload).unwrap()
            } else {
                client.write_all(b"ping\n").unwrap();
                let mut reader = io::BufReader::new(client);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                line.trim_end().to_string()
            };
            assert_eq!(received.len(), expected.len(), "{service:?}");
            assert!(received == expected, "{service:?}: reply corrupted");
            server.join().unwrap();
        }
    }

    #[test]
    fn frame_lengths() {
        assert_eq!(&ws_frame(OP_TEXT, b"hi")[..2], &[0x81, 2]);
        let f = ws_frame(OP_TEXT, &[0u8; 300]);
        assert_eq!(&f[..4], &[0x81, 126, 0x01, 0x2c]);
        let f = ws_frame(OP_TEXT, &vec![0u8; 70_000]);
        assert_eq!(f[1], 127);
        assert_eq!(&f[2..10], &70_000u64.to_be_bytes());
    }
}
