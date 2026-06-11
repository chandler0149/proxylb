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
    backend: &crate::backend::BackendInfo,
    svr_cfg: &Arc<SsServerConfig>,
    ctx: SharedContext,
    target: &TargetAddr,
    timeout: Duration,
) -> io::Result<BackendStream> {
    let raw = crate::outbound::connect_endpoint(backend, timeout).await?;
    let ss_addr = to_ss_address(target);
    let client_stream = ProxyClientStream::from_stream(ctx, raw, svr_cfg.as_ref(), ss_addr);
    Ok(BackendStream::Boxed(Box::pin(client_stream)))
}

/// Wrap an **already-established** raw stream (from the connection pool)
/// with the Shadowsocks AEAD layer for `target`.
pub fn ss_connect_pooled<S>(
    raw: S,
    svr_cfg: &Arc<SsServerConfig>,
    ctx: SharedContext,
    target: &TargetAddr,
) -> BackendStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let ss_addr = to_ss_address(target);
    let client_stream = ProxyClientStream::from_stream(ctx, raw, svr_cfg.as_ref(), ss_addr);
    BackendStream::Boxed(Box::pin(client_stream))
}
