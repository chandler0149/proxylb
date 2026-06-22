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
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    tls_cfg: Option<crate::config::TlsServerConfig>,
    username: Option<String>,
    password: Option<String>,
    route_idx: Option<usize>,
    cancel: CancellationToken,
    prebound_uds: Option<std::os::unix::net::UnixListener>,
    udp_enabled: bool,
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

        crate::inbound::run_accept_loop(listener, cancel, "SOCKS5", move |stream, client_id| {
            let pool = pool.clone();
            let stats = Arc::clone(&stats);
            let tls_acceptor = tls_acceptor.clone();
            let arc_config = arc_config.clone();
            let local_filter_manager = local_filter_manager.clone();
            async move {
                if let Err(e) = handle_socks5_connection(
                    stream,
                    pool,
                    stats,
                    local_filter_manager.clone(),
                    tls_acceptor.as_deref().cloned(),
                    arc_config,
                    route_idx,
                    client_id.clone(),
                    udp_enabled,
                )
                .await
                {
                    tracing::debug!(client = %client_id, error = %e, "SOCKS5 connection failed");
                }
            }
        })
        .await
    } else {
        let mut config = Config::<DenyAuthentication>::default();
        config.set_execute_command(false);
        config.set_dns_resolve(false);
        let arc_config = std::sync::Arc::new(config);

        crate::inbound::run_accept_loop(listener, cancel, "SOCKS5", move |stream, client_id| {
            let pool = pool.clone();
            let stats = Arc::clone(&stats);
            let tls_acceptor = tls_acceptor.clone();
            let arc_config = arc_config.clone();
            let local_filter_manager = local_filter_manager.clone();
            async move {
                if let Err(e) = handle_socks5_connection(
                    stream,
                    pool,
                    stats,
                    local_filter_manager.clone(),
                    tls_acceptor.as_deref().cloned(),
                    arc_config,
                    route_idx,
                    client_id.clone(),
                    udp_enabled,
                )
                .await
                {
                    tracing::debug!(client = %client_id, error = %e, "SOCKS5 connection failed");
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
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    config: Arc<Config<A>>,
    route_idx: Option<usize>,
    client_id: crate::stats::ClientId,
    udp_enabled: bool,
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
    handle_socks5_handshake(
        socks5_socket,
        pool,
        stats,
        local_filter_manager,
        route_idx,
        client_id,
        udp_enabled,
    )
    .await
}

#[allow(deprecated)]
async fn handle_socks5_handshake<S, A>(
    socks5_socket: Socks5Socket<S, A>,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    route_idx: Option<usize>,
    client_id: crate::stats::ClientId,
    udp_enabled: bool,
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

    // Check command
    if let Some(fast_socks5::Socks5Command::UDPAssociate) = socks5_socket.cmd() {
        if !udp_enabled {
            let mut client_stream = socks5_socket.into_inner();
            let reply = build_socks5_reply(consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED);
            let _ = client_stream.write_all(&reply).await;
            return Ok(());
        }
        return handle_udp_associate(socks5_socket.into_inner(), pool, route_idx).await;
    } else if let Some(fast_socks5::Socks5Command::TCPConnect) = socks5_socket.cmd() {
        // TCP connect, continue
    } else {
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

    let is_blocked = if let Some(ref m) = local_filter_manager {
        m.is_blocked(&target)
    } else {
        pool.filter_manager.is_blocked(&target)
    };

    if is_blocked {
        tracing::debug!(target = %target, "SOCKS5 connection blocked by filter");
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

    crate::inbound::relay_and_track(
        client_stream,
        backend_stream,
        chosen_traffic,
        Some(stats),
        client_id,
        &target,
        "SOCKS5",
        &pool,
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

pub fn parse_target_addr_from_buf(buf: &[u8]) -> std::io::Result<(TargetAddr, usize)> {
    if buf.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty buffer",
        ));
    }
    match buf[0] {
        0x01 => {
            // IPv4
            if buf.len() < 7 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete IPv4 address",
                ));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                    port,
                )),
                7,
            ))
        }
        0x04 => {
            // IPv6
            if buf.len() < 19 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete IPv6 address",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                TargetAddr::Ip(std::net::SocketAddr::new(
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                    port,
                )),
                19,
            ))
        }
        0x03 => {
            // Domain
            if buf.len() < 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete domain length",
                ));
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete domain or port",
                ));
            }
            let host = String::from_utf8_lossy(&buf[2..2 + len]).to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((TargetAddr::Domain(host, port), 2 + len + 2))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown ATYP",
        )),
    }
}

async fn handle_udp_associate<S>(
    mut client_stream: S,
    pool: BackendPool,
    route_idx: Option<usize>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use dashmap::DashMap;
    use std::sync::Arc;

    let inbound_udp = Arc::new(crate::udp::create_tuned_udp_socket()?);
    let local_addr = inbound_udp.local_addr()?;

    let mut reply = vec![consts::SOCKS5_VERSION, consts::SOCKS5_REPLY_SUCCEEDED, 0x00];
    let mut addr_buf = [0u8; 259];
    let target = TargetAddr::Ip(local_addr);
    if let Ok(len) = crate::outbound::socks5::write_target_addr_to_buf(&target, &mut addr_buf) {
        reply.extend_from_slice(&addr_buf[..len]);
    }
    client_stream.write_all(&reply).await?;

    let backend_map: Arc<DashMap<TargetAddr, Arc<crate::udp::UdpBackendSession>>> =
        Arc::new(DashMap::new());
    let tcp_abort = Arc::new(tokio::sync::Notify::new());
    let tcp_abort_clone = tcp_abort.clone();

    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1];
        let _ = client_stream.read(&mut buf).await;
        tcp_abort_clone.notify_waiters();
    });

    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            _ = tcp_abort.notified() => {
                break;
            }
            res = inbound_udp.recv_from(&mut buf) => {
                let (len, client_addr) = match res {
                    Ok(x) => x,
                    Err(_) => break,
                };

                if len < 4 || buf[2] != 0 { continue; }
                let (target, header_len) = match parse_target_addr_from_buf(&buf[3..len]) {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                let payload = &buf[3+header_len..len];

                let session = if let Some(session) = backend_map.get(&target) {
                    session.clone()
                } else {
                    match crate::inbound::route_and_connect_udp(&pool, &target, route_idx).await {
                        Ok((session, _traffic)) => {
                            let session = Arc::new(session);
                            backend_map.insert(target.clone(), session.clone());

                            let session_clone = session.clone();
                            let inbound_clone = inbound_udp.clone();
                            let target_clone = target.clone();
                            tokio::spawn(async move {
                                let mut back_buf = vec![0u8; 65536];
                                loop {
                                    match session_clone.recv_from(&mut back_buf).await {
                                        Ok((n, _)) => {
                                            let mut packet = vec![0u8; 3];
                                            let mut addr_buf = [0u8; 259];
                                            if let Ok(addr_len) = crate::outbound::socks5::write_target_addr_to_buf(&target_clone, &mut addr_buf) {
                                                packet.extend_from_slice(&addr_buf[..addr_len]);
                                                packet.extend_from_slice(&back_buf[..n]);
                                                let _ = inbound_clone.send_to(&packet, client_addr).await;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });

                            session
                        }
                        Err(e) => {
                            tracing::error!("UDP route failed for {}: {}", target, e);
                            continue;
                        }
                    }
                };

                let _ = session.send_to(payload, &target).await;
            }
        }
    }
    Ok(())
}
