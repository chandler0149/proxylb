//! SOCKS5 inbound listener.
//!
//! Accepts SOCKS5 CONNECT requests using the `fast-socks5` crate with
//! command execution disabled — we intercept the target address and
//! forward through our SOCKS5h backend pool instead of connecting directly.

#[allow(deprecated)]
use fast_socks5::server::{Config, DenyAuthentication, Socks5Socket};
use fast_socks5::util::target_addr::TargetAddr as FastTargetAddr;
use fast_socks5::consts;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener};

use crate::backend::BackendPool;
use crate::outbound::TargetAddr;


/// Run SOCKS5 inbound over a Unix domain socket.
pub async fn run_socks5_uds_inbound(
    listen_path: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(&listen_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if std::fs::metadata(&listen_path).is_ok() {
        let _ = std::fs::remove_file(&listen_path);
    }

    let listener = UnixListener::bind(&listen_path)?;
    tracing::info!(listen = %listen_path, "SOCKS5 UDS inbound listener started");

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let pool = pool.clone();
                let stats = Arc::clone(&stats);
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_connection(stream, pool, stats, filter_enabled).await {
                        tracing::debug!(
                            client = ?client_addr,
                            error = %e,
                            "SOCKS5 UDS connection failed"
                        );
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "SOCKS5 UDS accept error");
            }
        }
    }
}

/// Run SOCKS5 inbound over TCP.
pub async fn run_socks5_tcp_inbound(
    listen_addr: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(listen = %listen_addr, "SOCKS5 TCP inbound listener started");

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let pool = pool.clone();
                let stats = Arc::clone(&stats);
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    if let Err(e) = handle_socks5_connection(stream, pool, stats, filter_enabled).await {
                        tracing::debug!(
                            client = %client_addr,
                            error = %e,
                            "SOCKS5 TCP connection failed"
                        );
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "SOCKS5 TCP accept error");
            }
        }
    }
}

/// Run the SOCKS5 inbound listener.
pub async fn run_socks5_inbound(
    listen_addr: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
) -> anyhow::Result<()> {
    if let Some(path) = listen_addr.strip_prefix("unix://") {
        run_socks5_uds_inbound(path.to_string(), pool, stats, filter_enabled).await
    } else {
        run_socks5_tcp_inbound(listen_addr, pool, stats, filter_enabled).await
    }
}

/// Handle a single SOCKS5 connection.
///
/// We use fast-socks5 with `execute_command = false` and `dns_resolve = false`
/// so it performs the auth handshake and reads the CONNECT request, but does NOT
/// connect to the target or do DNS resolution. We then take the target address
/// and forward through our SOCKS5h backend pool instead of connecting directly.
/// 

#[allow(deprecated)]
async fn handle_socks5_connection<S>(
    stream: S,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Configure fast-socks5 to NOT execute the command or resolve DNS.

    let mut config = Config::<DenyAuthentication>::default();
    config.set_execute_command(false);
    config.set_dns_resolve(false);

    let socks5_socket = Socks5Socket::new(stream, std::sync::Arc::new(config));

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
        let reply = build_socks5_reply(consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED); // Connection not allowed by ruleset
        let _ = client_stream.write_all(&reply).await;
        return Ok(());
    }


    // Get the raw stream back from the socks5 socket.
    let mut client_stream = socks5_socket.into_inner();


    // Try backends in order with fallback.
    let (backend_stream, chosen_traffic) = match crate::inbound::route_and_connect(&pool, &target).await {
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

    crate::inbound::relay_and_track(client_stream, backend_stream, chosen_traffic, Some(stats), &target, "SOCKS5").await

}

/// Build a minimal SOCKS5 reply: VER=5, REP, RSV=0, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
fn build_socks5_reply(reply_code: u8) -> [u8; 10] {
    [
        0x05,       // VER
        reply_code, // REP
        0x00,       // RSV
        0x01,       // ATYP = IPv4
        0, 0, 0, 0, // BND.ADDR = 0.0.0.0
        0, 0,       // BND.PORT = 0
    ]
}

/// Convert fast-socks5 target address to our TargetAddr.
fn convert_target_addr(addr: &FastTargetAddr) -> TargetAddr {
    match addr {
        FastTargetAddr::Ip(socket_addr) => TargetAddr::Ip(*socket_addr),
        FastTargetAddr::Domain(host, port) => TargetAddr::Domain(host.clone(), *port),
    }
}
