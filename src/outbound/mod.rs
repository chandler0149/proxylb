//! Combined outbound proxy and direct client interfaces.
//!
//! Submodules implement SOCKS5 client, Shadowsocks client, and Direct TCP outbounds.

pub mod socks5;
pub mod shadowsocks;
pub mod direct;

// Re-export key outbound client functions for clean top-level usage
pub use socks5::{socks5h_authenticate, socks5h_connect, socks5h_connect_target};
pub use shadowsocks::{ss_connect_fresh, ss_connect_pooled};
pub use direct::direct_connect;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

/// Target address to connect to.
#[derive(Debug, Clone)]
pub enum TargetAddr {
    /// Domain name + port (DNS resolved by backend or directly resolved).
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

// ─── Combined async I/O trait ────────────────────────────────────────────────

/// Combines `AsyncRead` and `AsyncWrite` into a single trait object-safe trait.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWrite for T {}

// ─── Transport abstraction ────────────────────────────────────────────────────

/// A connected stream to a SOCKS5 backend, Shadowsocks client, or direct TCP connection.
pub enum BackendStream {
    Tcp(TcpStream),
    Unix(UnixStream),
    /// Type-erased stream; used to hold a shadowsocks/custom client connection.
    Boxed(Pin<Box<dyn AsyncReadWrite>>),
}

// SAFETY: TcpStream and UnixStream are Unpin. The Boxed variant is accessed
// only through `Pin::as_mut()` in poll_* impls; the inner value is never moved.
impl Unpin for BackendStream {}

impl AsyncRead for BackendStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            BackendStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
            BackendStream::Boxed(s) => s.as_mut().poll_read(cx, buf),
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
            BackendStream::Boxed(s) => s.as_mut().poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            BackendStream::Unix(s) => Pin::new(s).poll_flush(cx),
            BackendStream::Boxed(s) => s.as_mut().poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            BackendStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            BackendStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
            BackendStream::Boxed(s) => s.as_mut().poll_shutdown(cx),
        }
    }
}
