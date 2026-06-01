//! Shadowsocks outbound client.
//!
//! Handles establishing a connection to a Shadowsocks server, setting up the
//! AEAD encryption layer, and transmitting the target destination address.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use shadowsocks::config::ServerConfig as SsServerConfig;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::proxy_stream::client::ProxyClientStream;
use tokio::net::TcpStream;

use super::{BackendStream, TargetAddr};

/// Convert our [`TargetAddr`] to the shadowsocks [`SsAddress`] type.
fn to_ss_address(target: &TargetAddr) -> SsAddress {
    match target {
        TargetAddr::Domain(host, port) => SsAddress::DomainNameAddress(host.clone(), *port),
        TargetAddr::Ip(addr) => SsAddress::SocketAddress(*addr),
    }
}

/// Connect **fresh** to a Shadowsocks server and wrap the stream for `target`.
pub async fn ss_connect_fresh(
    host: &str,
    port: u16,
    svr_cfg: &Arc<SsServerConfig>,
    ctx: SharedContext,
    target: &TargetAddr,
    timeout: Duration,
) -> io::Result<BackendStream> {
    let addr = format!("{}:{}", host, port);
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SS backend TCP connect timeout"))?
        .map_err(|e| {
            io::Error::new(e.kind(), format!("SS backend TCP connect to {}: {}", addr, e))
        })?;
    tcp.set_nodelay(true)?;

    let ss_addr = to_ss_address(target);
    let client_stream = ProxyClientStream::from_stream(ctx, tcp, svr_cfg.as_ref(), ss_addr);
    Ok(BackendStream::Boxed(Box::pin(client_stream)))
}

/// Wrap an **already-established** raw TCP stream (from the connection pool)
/// with the Shadowsocks AEAD layer for `target`.
pub fn ss_connect_pooled(
    raw: TcpStream,
    svr_cfg: &Arc<SsServerConfig>,
    ctx: SharedContext,
    target: &TargetAddr,
) -> BackendStream {
    let ss_addr = to_ss_address(target);
    let client_stream = ProxyClientStream::from_stream(ctx, raw, svr_cfg.as_ref(), ss_addr);
    BackendStream::Boxed(Box::pin(client_stream))
}
