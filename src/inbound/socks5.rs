//! SOCKS5 inbound listener.
//!
//! Accepts SOCKS5 CONNECT requests using the `fast-socks5` crate with
//! command execution disabled — we intercept the target address and
//! forward through our SOCKS5h backend pool instead of connecting directly.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use fast_socks5::server::{Config, DenyAuthentication, Socks5Socket};
use fast_socks5::util::target_addr::TargetAddr as FastTargetAddr;
use fast_socks5::consts;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::backend::{BackendPool, TrafficCounters};
use crate::outbound::{socks5h_connect, socks5h_connect_target, TargetAddr};
use crate::relay;


/// Run the SOCKS5 inbound listener.
pub async fn run_socks5_inbound(listen_addr: String, pool: BackendPool) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(listen = %listen_addr, "SOCKS5 inbound listener started");

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let pool = pool.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    if let Err(e) = handle_socks5_connection(stream, pool).await {
                        tracing::debug!(
                            client = %client_addr,
                            error = %e,
                            "SOCKS5 connection failed"
                        );
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "SOCKS5 accept error");
            }
        }
    }
}

/// Handle a single SOCKS5 connection.
///
/// We use fast-socks5 with `execute_command = false` and `dns_resolve = false`
/// so it performs the auth handshake and reads the CONNECT request, but does NOT
/// connect to the target or do DNS resolution. We then take the target address
/// and forward through our backend pool.
async fn handle_socks5_connection(stream: TcpStream, pool: BackendPool) -> anyhow::Result<()> {
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

    // Get the raw stream back from the socks5 socket.
    let mut client_stream = socks5_socket.into_inner();

    // Try backends in order with fallback.
    let backend_timeout = Duration::from_secs(10);
    let backends = pool.get_backends_in_order().await;

    let mut backend_stream: Option<TcpStream> = None;
    // Traffic Arc carried from pool acquisition — zero additional RwLock reads on the hot path.
    let mut chosen_traffic: Option<Arc<TrafficCounters>> = None;

    // First pass: try healthy backends.
    for (index, info, healthy) in &backends {
        if !healthy {
            continue;
        }
        // Single RwLock read: yields both the pooled stream (if any) and the traffic Arc.
        let pc = pool.get_pooled_connection(*index).await;
        let (pool_stream, traffic) = match pc {
            Some(pc) => (pc.stream, Some(pc.traffic)),
            None => (None, None), // OOB — never happens
        };

        let conn_res = match pool_stream {
            Some(stream) => {
                tracing::debug!(backend = %info.name, "using pooled connection");
                match socks5h_connect_target(stream, &target).await {
                    Ok(s) => {
                        if let Some(ref tc) = traffic {
                            tc.pool_hits.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(s)
                    }
                    Err(e) => {
                        if let Some(ref tc) = traffic {
                            tc.pool_stale.fetch_add(1, Ordering::Relaxed);
                        }
                        tracing::debug!(
                            backend = %info.name,
                            error = %e,
                            "pooled connection was stale, retrying with fresh connection"
                        );
                        socks5h_connect(info, &target, backend_timeout).await
                    }
                }
            }
            None => {
                if let Some(ref tc) = traffic {
                    tc.pool_misses.fetch_add(1, Ordering::Relaxed);
                }
                socks5h_connect(info, &target, backend_timeout).await
            }
        };

        match conn_res {
            Ok(stream) => {
                tracing::debug!(backend = %info.name, target = %target, "connected through backend");
                backend_stream = Some(stream);
                chosen_traffic = traffic;
                break;
            }
            Err(e) => {
                tracing::debug!(backend = %info.name, error = %e, "backend connect failed, trying next");
                pool.mark_unhealthy(*index, &format!("connect failed: {}", e))
                    .await;
            }
        }
    }

    // Second pass: try unhealthy backends as last resort.
    // Rare slow-path: one extra get_traffic_counters call is acceptable here.
    if backend_stream.is_none() {
        for (index, info, healthy) in &backends {
            if *healthy {
                continue;
            }
            if let Ok(stream) = socks5h_connect(info, &target, backend_timeout).await {
                tracing::debug!(backend = %info.name, target = %target, "connected through unhealthy backend (fallback)");
                backend_stream = Some(stream);
                chosen_traffic = pool.get_traffic_counters(*index).await;
                break;
            }
        }
    }

    let mut backend_stream = match backend_stream {
        Some(s) => s,
        None => {
            tracing::warn!(target = %target, "all backends failed");
            let reply = build_socks5_reply(consts::SOCKS5_REPLY_HOST_UNREACHABLE);
            let _ = client_stream.write_all(&reply).await;
            return Ok(());
        }
    };

    // Send SOCKS5 success reply to the client.
    let reply = build_socks5_reply(consts::SOCKS5_REPLY_SUCCEEDED);
    client_stream.write_all(&reply).await?;
    client_stream.flush().await?;

    // All remaining counter updates go through the Arc — zero RwLock reads from here on.
    if let Some(ref tc) = chosen_traffic {
        tc.total_connections.fetch_add(1, Ordering::Relaxed);
        tc.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    // Bidirectional relay.
    match relay::relay(&mut client_stream, &mut backend_stream).await {
        Ok((up, down)) => {
            tracing::debug!(target = %target, up_bytes = up, down_bytes = down, "SOCKS5 relay complete");
            if let Some(ref tc) = chosen_traffic {
                tc.bytes_up.fetch_add(up, Ordering::Relaxed);
                tc.bytes_down.fetch_add(down, Ordering::Relaxed);
            }
        }
        Err(e) => {
            tracing::debug!(target = %target, error = %e, "SOCKS5 relay error");
        }
    }
    if let Some(ref tc) = chosen_traffic {
        tc.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    let _ = client_stream.shutdown().await;
    let _ = backend_stream.shutdown().await;

    Ok(())
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
