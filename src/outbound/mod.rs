//! Combined outbound proxy and direct client interfaces.
//!
//! Submodules implement SOCKS5 client, Shadowsocks client, and Direct TCP outbounds.

pub mod direct;
pub mod shadowsocks;
pub mod socks5;

// Re-export key outbound client functions for clean top-level usage
pub use direct::direct_connect;
pub use shadowsocks::{ss_connect_fresh, ss_connect_pooled};
pub use socks5::{socks5h_authenticate, socks5h_connect, socks5h_connect_target};

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

/// Helper function to platform-conditionally bind a socket descriptor to a network interface.
#[cfg(target_os = "linux")]
fn bind_socket_to_device(
    fd: std::os::unix::io::RawFd,
    interface: &str,
    _is_ipv6: bool,
) -> std::io::Result<()> {
    use std::ffi::CString;
    let iface_c = CString::new(interface)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            iface_c.as_ptr() as *const libc::c_void,
            iface_c.to_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn bind_socket_to_device(
    fd: std::os::unix::io::RawFd,
    interface: &str,
    is_ipv6: bool,
) -> std::io::Result<()> {
    use std::ffi::CString;
    let iface_c = CString::new(interface)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let index = unsafe { libc::if_nametoindex(iface_c.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("network interface '{}' not found", interface),
        ));
    }

    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;

    let res = unsafe {
        if is_ipv6 {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_BOUND_IF,
                &index as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        } else {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                IP_BOUND_IF,
                &index as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        }
    };

    if res == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn bind_socket_to_device(
    _fd: std::os::unix::io::RawFd,
    _interface: &str,
    _is_ipv6: bool,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "outbound interface binding is only supported on Linux and macOS",
    ))
}

/// Establish an outbound TCP connection bound to an optional network interface.
pub async fn tcp_connect_raw<A: tokio::net::ToSocketAddrs>(
    addr: A,
    bind_interface: Option<&str>,
    timeout: std::time::Duration,
) -> io::Result<TcpStream> {
    use std::os::unix::io::AsRawFd;
    use tokio::net::TcpSocket;

    let addrs = tokio::net::lookup_host(addr).await?;
    let mut last_err = None;

    for socket_addr in addrs {
        let is_ipv6 = socket_addr.is_ipv6();
        let socket = match socket_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };

        if let Some(iface) = bind_interface {
            let fd = socket.as_raw_fd();
            bind_socket_to_device(fd, iface, is_ipv6)?;
        }

        match tokio::time::timeout(timeout, socket.connect(socket_addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection timed out",
                ))
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "could not resolve address or no addresses found",
        )
    }))
}

/// Establish an outbound connection (TCP or Unix Domain Socket) to a backend endpoint.
pub async fn connect_endpoint(
    info: &crate::backend::BackendInfo,
    timeout: std::time::Duration,
) -> io::Result<BackendStream> {
    let bind_interface = info.bind_interface.as_deref();
    let stream = match &info.endpoint {
        crate::backend::BackendEndpoint::Tcp { host, port } => {
            let addr = format!("{}:{}", host, port);
            let tcp = tcp_connect_raw(&addr, bind_interface, timeout).await?;
            tcp.set_nodelay(true)?;
            BackendStream::Tcp(tcp)
        }
        crate::backend::BackendEndpoint::Unix { path } => {
            let unix = tokio::time::timeout(timeout, UnixStream::connect(path))
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("UDS connect timeout to {}", path),
                    )
                })??;
            BackendStream::Unix(unix)
        }
        crate::backend::BackendEndpoint::Direct => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Direct backend has no endpoint address",
            ));
        }
    };

    if let Some(tls) = &info.tls_connector {
        let server_name = info
            .server_name
            .clone()
            .unwrap_or_else(|| match &info.endpoint {
                crate::backend::BackendEndpoint::Tcp { host, .. } => host.clone(),
                _ => "localhost".to_string(),
            });

        // Use rustls::pki_types::ServerName
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.clone())
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Invalid SNI: {}", server_name),
                    )
                })?
                .to_owned();

        let tls_stream = tls.connect(server_name, stream).await?;
        Ok(BackendStream::Boxed(Box::pin(tls_stream)))
    } else {
        Ok(stream)
    }
}
