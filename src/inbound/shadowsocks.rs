//! Shadowsocks inbound listener.
//!
//! Accepts Shadowsocks AEAD encrypted connections using the `shadowsocks` crate,
//! decrypts the stream, extracts the target address, connects through a healthy
//! SOCKS5h backend, and relays data bidirectionally.

use std::net::SocketAddr;
use std::sync::Arc;

use shadowsocks::config::ServerConfig as SsServerConfig;
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream;
use tokio_util::sync::CancellationToken;

use super::BoundListener;
use crate::backend::BackendPool;
use crate::outbound::TargetAddr;
use crate::relay::AsRawStreamRef;
use crate::tls::MaybeTlsStream;

/// Run the Shadowsocks inbound listener (TCP or UDS, selected by address prefix).
pub async fn run_shadowsocks_inbound(
    listen_addr: String,
    password: String,
    method_str: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
    tls_cfg: Option<crate::config::TlsServerConfig>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let method: CipherKind = method_str
        .parse()
        .map_err(|_| anyhow::anyhow!("unsupported cipher: {}", method_str))?;

    let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let ss_config = SsServerConfig::new(dummy_addr, &password, method)
        .map_err(|e| anyhow::anyhow!("shadowsocks config error: {}", e))?;
    let key: Arc<[u8]> = ss_config.key().into();

    let context: SharedContext = Context::new_shared(shadowsocks::config::ServerType::Server);

    let tls_acceptor = tls_cfg
        .as_ref()
        .map(|c| crate::tls::create_tls_acceptor(c))
        .transpose()?
        .map(Arc::new);

    let listener = BoundListener::bind(&listen_addr).await?;
    tracing::info!(listen = %listen_addr, method = %method_str, "Shadowsocks inbound listener started");

    crate::inbound::run_accept_loop(listener, cancel, "Shadowsocks", move |stream, addr| {
        let pool = pool.clone();
        let context = context.clone();
        let key = Arc::clone(&key);
        let stats = Arc::clone(&stats);
        let tls_acceptor = tls_acceptor.clone();
        async move {
            if let Err(e) = handle_ss_connection(
                stream,
                addr.clone(),
                context,
                method,
                &key,
                pool,
                stats,
                filter_enabled,
                tls_acceptor.as_deref().cloned(),
            )
            .await
            {
                tracing::debug!(client = %addr, error = %e, "Shadowsocks connection failed");
            }
        }
    })
    .await
}




/// Handle a single Shadowsocks connection.
async fn handle_ss_connection<S>(
    stream: S,
    client_addr: String,
    context: SharedContext,
    method: CipherKind,
    key: &[u8],
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + AsRawStreamRef + 'static,
{
    let stream = if let Some(ref acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await?;
        MaybeTlsStream::Tls(tls_stream)
    } else {
        MaybeTlsStream::Plain(stream)
    };

    // Wrap the raw stream in the Shadowsocks decryption layer.
    let mut ss_stream = ProxyServerStream::from_stream(context, stream, method, key);

    // Handshake: decrypt the first chunk and extract the target address.
    let address = ss_stream
        .handshake()
        .await
        .map_err(|e| anyhow::anyhow!("SS handshake error: {}", e))?;

    let target = convert_ss_address(&address);

    tracing::debug!(
        client = %client_addr,
        target = %target,
        "Shadowsocks CONNECT request"
    );

    let is_private = crate::inbound::is_private_target(&target).await;
    if crate::inbound::likely(filter_enabled) && crate::inbound::unlikely(is_private) {
        tracing::warn!(target = %target, "Shadowsocks connection rejected: private target");
        return Err(anyhow::anyhow!(
            "private address target is rejected by filter"
        ));
    }

    if pool.adblock_manager.is_blocked(&target) {
        tracing::warn!(target = %target, "Shadowsocks connection blocked by adblock");
        return Err(anyhow::anyhow!("connection blocked by AdBlock rules"));
    }

    // Try backends in order with fallback.
    let (backend_stream, chosen_traffic) =
        match crate::inbound::route_and_connect(&pool, &target).await {
            Ok((s, t)) => (s, t),
            Err(e) => {
                tracing::warn!(
                    client = %client_addr,
                    target = %target,
                    error = %e,
                    "all backends failed"
                );
                return Err(anyhow::anyhow!("all backends unavailable"));
            }
        };

    crate::inbound::relay_and_track(
        ss_stream,
        backend_stream,
        chosen_traffic,
        Some(stats),
        &target,
        "Shadowsocks",
    )
    .await
}

/// Convert a shadowsocks `Address` to our `TargetAddr`.
fn convert_ss_address(addr: &Address) -> TargetAddr {
    match addr {
        Address::SocketAddress(socket_addr) => TargetAddr::Ip(*socket_addr),
        Address::DomainNameAddress(host, port) => TargetAddr::Domain(host.clone(), *port),
    }
}

#[cfg(unix)]
impl<S> crate::relay::AsRawStreamRef
    for shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream<S>
{
    fn as_raw_stream_ref(&self) -> Option<crate::relay::RawStreamRef<'_>> {
        None
    }
}
