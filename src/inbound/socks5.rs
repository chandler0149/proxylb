//! SOCKS5 inbound listener.
//!
//! Accepts SOCKS5 CONNECT requests using the `fast-socks5` crate with
//! command execution disabled — we intercept the target address and
//! forward through our SOCKS5h backend pool instead of connecting directly.

use fast_socks5::consts;
#[allow(deprecated)]
use fast_socks5::server::{Config, DenyAuthentication, SimpleUserPassword, Socks5Socket};
use fast_socks5::util::target_addr::TargetAddr as FastTargetAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::BoundListener;
use crate::backend::BackendPool;
use crate::outbound::TargetAddr;
use crate::relay::AsRawStreamRef;
use crate::tls::MaybeTlsStream;

/// Run the SOCKS5 inbound listener (TCP or UDS, selected by address prefix).
pub async fn run_socks5_inbound(
    listen_addr: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
    tls_cfg: Option<crate::config::TlsServerConfig>,
    username: Option<String>,
    password: Option<String>,
    route_idx: Option<usize>,
    cancel: CancellationToken,
    prebound_uds: Option<std::os::unix::net::UnixListener>,
) -> anyhow::Result<()> {
    let tls_acceptor = tls_cfg
        .as_ref()
        .map(|c| crate::tls::create_tls_acceptor(c))
        .transpose()?
        .map(Arc::new);

    let listener = BoundListener::bind(&listen_addr, prebound_uds).await?;
    tracing::info!(listen = %listen_addr, "SOCKS5 inbound listener started");

    if let (Some(u), Some(p)) = (username, password) {
        let mut config = Config::<DenyAuthentication>::default();
        config.set_execute_command(false);
        config.set_dns_resolve(false);
        let config = config.with_authentication(SimpleUserPassword {
            username: u.clone(),
            password: p.clone(),
        });
        let arc_config = std::sync::Arc::new(config);

        crate::inbound::run_accept_loop(listener, cancel, "SOCKS5", move |stream, addr| {
            let pool = pool.clone();
            let stats = Arc::clone(&stats);
            let tls_acceptor = tls_acceptor.clone();
            let arc_config = arc_config.clone();
            async move {
                if let Err(e) = handle_socks5_connection(
                    stream,
                    pool,
                    stats,
                    filter_enabled,
                    tls_acceptor.as_deref().cloned(),
                    arc_config,
                    route_idx,
                )
                .await
                {
                    tracing::debug!(client = %addr, error = %e, "SOCKS5 connection failed");
                }
            }
        })
        .await
    } else {
        let mut config = Config::<DenyAuthentication>::default();
        config.set_execute_command(false);
        config.set_dns_resolve(false);
        let arc_config = std::sync::Arc::new(config);

        crate::inbound::run_accept_loop(listener, cancel, "SOCKS5", move |stream, addr| {
            let pool = pool.clone();
            let stats = Arc::clone(&stats);
            let tls_acceptor = tls_acceptor.clone();
            let arc_config = arc_config.clone();
            async move {
                if let Err(e) = handle_socks5_connection(
                    stream,
                    pool,
                    stats,
                    filter_enabled,
                    tls_acceptor.as_deref().cloned(),
                    arc_config,
                    route_idx,
                )
                .await
                {
                    tracing::debug!(client = %addr, error = %e, "SOCKS5 connection failed");
                }
            }
        })
        .await
    }
}

/// Handle a single SOCKS5 connection.
#[allow(deprecated)]
async fn handle_socks5_connection<S, A>(
    stream: S,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    config: Arc<Config<A>>,
    route_idx: Option<usize>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + AsRawStreamRef + 'static,
    A: fast_socks5::server::Authentication + Send + Sync + 'static,
{
    // Apply TLS if configured.
    let stream = if let Some(ref acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await?;
        MaybeTlsStream::Tls(tls_stream)
    } else {
        MaybeTlsStream::Plain(stream)
    };

    let socks5_socket = Socks5Socket::new(stream, config);
    handle_socks5_handshake(socks5_socket, pool, stats, filter_enabled, route_idx).await
}

#[allow(deprecated)]
async fn handle_socks5_handshake<S, A>(
    socks5_socket: Socks5Socket<S, A>,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
    route_idx: Option<usize>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + AsRawStreamRef + 'static,
    A: fast_socks5::server::Authentication + Send + Sync + 'static,
{
    // Perform the SOCKS5 handshake (auth + read command), but don't connect.
    let socks5_socket = socks5_socket
        .upgrade_to_socks5()
        .await
        .map_err(|e| anyhow::anyhow!("SOCKS5 handshake error: {}", e))?;

    // Check it's a CONNECT command.
    if socks5_socket.cmd() != &Some(fast_socks5::Socks5Command::TCPConnect) {
        tracing::debug!("unsupported SOCKS5 command: {:?}", socks5_socket.cmd());
        return Ok(());
    }

    // Extract target address.
    let target = match socks5_socket.target_addr() {
        Some(addr) => convert_target_addr(addr),
        None => {
            tracing::debug!("SOCKS5 request missing target address");
            return Ok(());
        }
    };

    tracing::debug!(target = %target, "SOCKS5 CONNECT request");

    let is_private = crate::inbound::is_private_target(&target).await;
    if crate::inbound::likely(filter_enabled) && crate::inbound::unlikely(is_private) {
        tracing::warn!(target = %target, "SOCKS5 connection rejected: private target");
        let mut client_stream = socks5_socket.into_inner();
        let reply = build_socks5_reply(consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED);
        let _ = client_stream.write_all(&reply).await;
        return Ok(());
    }

    if pool.adblock_manager.is_blocked(&target) {
        tracing::warn!(target = %target, "SOCKS5 connection blocked by adblock");
        let mut client_stream = socks5_socket.into_inner();
        let reply = build_socks5_reply(consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED);
        let _ = client_stream.write_all(&reply).await;
        return Ok(());
    }

    // Get the raw stream back from the socks5 socket.
    let mut client_stream = socks5_socket.into_inner();

    // Try backends in order with fallback.
    let (backend_stream, chosen_traffic) =
        match crate::inbound::route_and_connect(&pool, &target, route_idx).await {
            Ok((s, t)) => (s, t),
            Err(e) => {
                tracing::warn!(target = %target, error = %e, "all backends failed");
                let reply = build_socks5_reply(consts::SOCKS5_REPLY_HOST_UNREACHABLE);
                let _ = client_stream.write_all(&reply).await;
                return Ok(());
            }
        };

    // Send SOCKS5 success reply to the client.
    let reply = build_socks5_reply(consts::SOCKS5_REPLY_SUCCEEDED);
    client_stream.write_all(&reply).await?;
    client_stream.flush().await?;

    crate::inbound::relay_and_track(
        client_stream,
        backend_stream,
        chosen_traffic,
        Some(stats),
        &target,
        "SOCKS5",
    )
    .await
}

/// Build a minimal SOCKS5 reply: VER=5, REP, RSV=0, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
fn build_socks5_reply(reply_code: u8) -> [u8; 10] {
    [
        0x05,       // VER
        reply_code, // REP
        0x00,       // RSV
        0x01,       // ATYP = IPv4
        0, 0, 0, 0, // BND.ADDR = 0.0.0.0
        0, 0, // BND.PORT = 0
    ]
}

/// Convert fast-socks5 target address to our TargetAddr.
fn convert_target_addr(addr: &FastTargetAddr) -> TargetAddr {
    match addr {
        FastTargetAddr::Ip(socket_addr) => TargetAddr::Ip(*socket_addr),
        FastTargetAddr::Domain(host, port) => TargetAddr::Domain(host.clone(), *port),
    }
}
