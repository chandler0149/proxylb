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
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    tls_cfg: Option<crate::config::TlsServerConfig>,
    route_idx: Option<usize>,
    cancel: CancellationToken,
    prebound_uds: Option<std::os::unix::net::UnixListener>,
    udp_enabled: bool,
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

    let listener = BoundListener::bind(&listen_addr, prebound_uds).await?;
    tracing::info!(listen = %listen_addr, method = %method_str, "Shadowsocks inbound listener started");

    if udp_enabled {
        let listen_addr_clone = listen_addr.clone();
        let password_clone = password.clone();
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = run_shadowsocks_udp(listen_addr_clone, password_clone, method, pool_clone, route_idx).await {
                tracing::error!("Shadowsocks UDP error: {}", e);
            }
        });
    }

    crate::inbound::run_accept_loop(listener, cancel, "Shadowsocks", move |stream, client_id| {
        let pool = pool.clone();
        let context = context.clone();
        let key = Arc::clone(&key);
        let stats = Arc::clone(&stats);
        let tls_acceptor = tls_acceptor.clone();
        let local_filter_manager = local_filter_manager.clone();
        async move {
            if let Err(e) = handle_ss_connection(
                stream,
                client_id.clone(),
                context,
                method,
                &key,
                pool,
                stats,
                local_filter_manager.clone(),
                tls_acceptor.as_deref().cloned(),
                route_idx,
            )
            .await
            {
                tracing::debug!(client = %client_id, error = %e, "Shadowsocks connection failed");
            }
        }
    })
    .await
}

async fn run_shadowsocks_udp(
    listen_addr: String,
    password: String,
    method: CipherKind,
    pool: BackendPool,
    route_idx: Option<usize>,
) -> anyhow::Result<()> {
    let listen_socket: SocketAddr = listen_addr.parse().map_err(|_| anyhow::anyhow!("Shadowsocks UDP listener must be an IP address: {}", listen_addr))?;
    let ss_config = SsServerConfig::new(listen_socket, &password, method)?;
    let context = shadowsocks::context::Context::new_shared(shadowsocks::config::ServerType::Server);
    
    let udp_listener = Arc::new(shadowsocks::relay::udprelay::ProxySocket::bind(context, &ss_config).await?);
    tracing::info!(listen = %listen_addr, "Shadowsocks UDP inbound listener started");

    use dashmap::DashMap;
    // Map from (ClientAddr, TargetAddr) -> UdpBackendSession
    let backend_map: Arc<DashMap<(SocketAddr, TargetAddr), Arc<crate::udp::UdpBackendSession>>> = Arc::new(DashMap::new());

    let mut buf = vec![0u8; 65536];
    loop {
        let (len, client_addr, target_addr, _) = match udp_listener.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                tracing::debug!("Shadowsocks UDP recv error: {}", e);
                continue;
            }
        };

        let target = match target_addr {
            shadowsocks::relay::socks5::Address::SocketAddress(sa) => TargetAddr::Ip(sa),
            shadowsocks::relay::socks5::Address::DomainNameAddress(host, port) => TargetAddr::Domain(host, port),
        };

        let key = (client_addr, target.clone());
        let session = if let Some(session) = backend_map.get(&key) {
            session.clone()
        } else {
            match crate::inbound::route_and_connect_udp(&pool, &target, route_idx).await {
                Ok((session, _traffic)) => {
                    let session = Arc::new(session);
                    backend_map.insert(key.clone(), session.clone());

                    let session_clone = session.clone();
                    let inbound_clone = udp_listener.clone();
                    let target_clone = target.clone();
                    
                    tokio::spawn(async move {
                        let mut back_buf = vec![0u8; 65536];
                        loop {
                            match session_clone.recv_from(&mut back_buf).await {
                                Ok((n, _)) => {
                                    let ss_addr = match &target_clone {
                                        TargetAddr::Ip(sa) => shadowsocks::relay::socks5::Address::SocketAddress(*sa),
                                        TargetAddr::Domain(host, port) => shadowsocks::relay::socks5::Address::DomainNameAddress(host.clone(), *port),
                                    };
                                    let _ = inbound_clone.send_to(client_addr, &ss_addr, &back_buf[..n]).await;
                                }
                                Err(_) => break,
                            }
                        }
                    });

                    session
                }
                Err(e) => {
                    tracing::error!("Shadowsocks UDP route failed for {}: {}", target, e);
                    continue;
                }
            }
        };

        let _ = session.send_to(&buf[..len], &target).await;
    }
}

/// Handle a single Shadowsocks connection.
async fn handle_ss_connection<S>(
    stream: S,
    client_id: crate::stats::ClientId,
    context: SharedContext,
    method: CipherKind,
    key: &[u8],
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    route_idx: Option<usize>,
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
        client = %client_id,
        target = %target,
        "Shadowsocks CONNECT request"
    );

    let is_blocked = if let Some(ref m) = local_filter_manager {
        m.is_blocked(&target)
    } else {
        pool.filter_manager.is_blocked(&target)
    };

    if is_blocked {
        tracing::debug!(target = %target, "Shadowsocks connection blocked by filter");
        return Err(anyhow::anyhow!("connection blocked by filter rules"));
    }

    // Try backends in order with fallback.
    let (backend_stream, chosen_traffic) =
        match crate::inbound::route_and_connect(&pool, &target, route_idx).await {
            Ok((s, t)) => (s, t),
            Err(e) => {
                tracing::warn!(
                    client = %client_id,
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
        client_id,
        &target,
        "Shadowsocks",
        &pool,
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

#[cfg(target_os = "linux")]
impl<S> crate::relay::AsRawStreamRef
    for shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream<S>
{
    fn as_raw_stream_ref(&self) -> Option<crate::relay::RawStreamRef<'_>> {
        None
    }
}
