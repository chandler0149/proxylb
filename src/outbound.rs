//! Lean SOCKS5h outbound client.
//!
//! Implements just enough of RFC 1928 to issue a CONNECT request with a
//! domain name (ATYP=0x03, i.e. "socks5h") through a SOCKS5 backend.
//! DNS resolution is performed by the backend, not locally.
//!
//! Transports: TCP (`TcpStream`) and Unix domain socket (`UnixStream`) are both
//! supported via the [`BackendStream`] enum.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

use crate::backend::BackendInfo;

/// SOCKS5 protocol constants.
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;

/// Target address to connect to through the SOCKS5h backend.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// Domain name + port (socks5h: DNS resolved by backend).
    Domain(String, u16),
    /// IPv4/IPv6 socket address.
    Ip(SocketAddr),
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetAddr::Domain(host, port) => write!(f, "{}:{}", host, port),
            TargetAddr::Ip(addr) => write!(f, "{}", addr),
        }
    }
}

// ─── Transport abstraction ────────────────────────────────────────────────────

/// A connected stream to a SOCKS5 backend — either TCP or Unix domain socket.
///
/// Both variants carry a fully bi-directional async byte stream.  The enum
/// implements [`AsyncRead`] and [`AsyncWrite`] so that higher-level protocol
/// code is transport-agnostic.
pub enum BackendStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for BackendStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            BackendStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BackendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            BackendStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            BackendStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            BackendStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ─── Entry-point helpers ──────────────────────────────────────────────────────

/// Connect to a SOCKS5h backend and issue a CONNECT to `target`.
///
/// Dispatches to TCP or Unix socket transport based on [`BackendInfo::endpoint`].
/// Returns the stream ready for bidirectional relay.
pub async fn socks5h_connect(
    backend: &BackendInfo,
    target: &TargetAddr,
    timeout: Duration,
) -> io::Result<BackendStream> {
    use crate::backend::BackendEndpoint;

    match &backend.endpoint {
        BackendEndpoint::Tcp { host, port } => {
            let addr = format!("{}:{}", host, port);

            let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend TCP connect timeout"))?
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("backend TCP connect to {}: {}", addr, e))
                })?;

            tcp.set_nodelay(true)?;

            let stream = socks5h_authenticate(BackendStream::Tcp(tcp), backend).await?;
            socks5h_connect_target(stream, target).await
        }
        BackendEndpoint::Unix { path } => {
            socks5h_connect_unix(path, backend, target, timeout).await
        }
    }
}

/// Connect via a Unix domain socket, authenticate, then issue the CONNECT.
pub async fn socks5h_connect_unix(
    socket_path: &str,
    backend: &BackendInfo,
    target: &TargetAddr,
    timeout: Duration,
) -> io::Result<BackendStream> {
    let unix = tokio::time::timeout(timeout, UnixStream::connect(Path::new(socket_path)))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("backend UDS connect timeout: {}", socket_path),
            )
        })?
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("backend UDS connect to {}: {}", socket_path, e),
            )
        })?;

    let stream = socks5h_authenticate(BackendStream::Unix(unix), backend).await?;
    socks5h_connect_target(stream, target).await
}

// ─── Protocol phases ──────────────────────────────────────────────────────────

/// Phase 1: SOCKS5 auth negotiation on an already-connected stream.
///
/// Generic over the transport — works with TCP or Unix streams.
pub async fn socks5h_authenticate<S>(mut stream: S, backend: &BackendInfo) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // === Step 1: Auth negotiation ===
    if backend.requires_auth() {
        // Offer both no-auth and user/pass
        stream
            .write_all(&[SOCKS5_VERSION, 2, AUTH_NONE, AUTH_USER_PASS])
            .await?;
    } else {
        stream.write_all(&[SOCKS5_VERSION, 1, AUTH_NONE]).await?;
    }
    stream.flush().await?;

    // Read method selection response: [version, method]
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("backend returned SOCKS version {}, expected 5", resp[0]),
        ));
    }

    match resp[1] {
        AUTH_NONE => { /* No auth needed */ }
        AUTH_USER_PASS => {
            // RFC 1929: username/password sub-negotiation
            let user = backend
                .username
                .as_deref()
                .ok_or_else(|| io::Error::other("backend wants auth but no username configured"))?;
            let pass = backend
                .password
                .as_deref()
                .ok_or_else(|| io::Error::other("backend wants auth but no password configured"))?;

            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01); // sub-negotiation version
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;
            stream.flush().await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "backend SOCKS5 auth failed",
                ));
            }
        }
        0xFF => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "backend rejected all auth methods",
            ));
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("backend selected unsupported auth method: {:#x}", other),
            ));
        }
    }

    Ok(stream)
}

/// Phase 2: Issue a SOCKS5 CONNECT request to `target` on an already-authenticated stream.
///
/// Generic over the transport — works with TCP or Unix streams.
pub async fn socks5h_connect_target<S>(mut stream: S, target: &TargetAddr) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // === Step 2: CONNECT request ===
    let connect_req = build_connect_request(target);
    stream.write_all(&connect_req).await?;
    stream.flush().await?;

    // === Step 3: Read CONNECT response ===
    // Minimum response: [VER, REP, RSV, ATYP, ...bind_addr..., bind_port]
    let mut resp_header = [0u8; 4];
    stream.read_exact(&mut resp_header).await?;

    if resp_header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 CONNECT response version",
        ));
    }
    if resp_header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed with reply code: {:#x}", resp_header[1]),
        ));
    }

    // Skip the bind address
    match resp_header[3] {
        ATYP_IPV4 => {
            let mut skip = [0u8; 4 + 2]; // IPv4 + port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_IPV6 => {
            let mut skip = [0u8; 16 + 2]; // IPv6 + port
            stream.read_exact(&mut skip).await?;
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut skip = vec![0u8; len_buf[0] as usize + 2]; // domain + port
            stream.read_exact(&mut skip).await?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown ATYP in CONNECT response",
            ));
        }
    }

    Ok(stream)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Build a SOCKS5 CONNECT request packet.
fn build_connect_request(target: &TargetAddr) -> Vec<u8> {
    match target {
        TargetAddr::Domain(host, port) => {
            let host_bytes = host.as_bytes();
            let mut req = Vec::with_capacity(7 + host_bytes.len());
            req.push(SOCKS5_VERSION);
            req.push(CMD_CONNECT);
            req.push(0x00); // RSV
            req.push(ATYP_DOMAIN);
            req.push(host_bytes.len() as u8);
            req.extend_from_slice(host_bytes);
            req.push((port >> 8) as u8);
            req.push(*port as u8);
            req
        }
        TargetAddr::Ip(addr) => {
            let mut req = Vec::with_capacity(10);
            req.push(SOCKS5_VERSION);
            req.push(CMD_CONNECT);
            req.push(0x00); // RSV
            match addr {
                SocketAddr::V4(v4) => {
                    req.push(ATYP_IPV4);
                    req.extend_from_slice(&v4.ip().octets());
                    req.push((v4.port() >> 8) as u8);
                    req.push(v4.port() as u8);
                }
                SocketAddr::V6(v6) => {
                    req.push(ATYP_IPV6);
                    req.extend_from_slice(&v6.ip().octets());
                    req.push((v6.port() >> 8) as u8);
                    req.push(v6.port() as u8);
                }
            }
            req
        }
    }
}
