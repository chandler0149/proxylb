//! Shadowsocks inbound listener.
//!
//! Accepts Shadowsocks AEAD encrypted connections using the `shadowsocks` crate,
//! decrypts the stream, extracts the target address, connects through a healthy
//! SOCKS5h backend, and relays data bidirectionally.

use std::net::SocketAddr;
use std::time::Duration;

use shadowsocks::config::ServerConfig as SsServerConfig;
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::backend::{BackendPool, TrafficCounters};
use crate::outbound::{socks5h_connect, socks5h_connect_target, TargetAddr};
use crate::relay;
use std::sync::Arc;
use std::sync::atomic::Ordering;


/// Run the Shadowsocks inbound listener.
pub async fn run_shadowsocks_inbound(
    listen_addr: String,
    password: String,
    method_str: String,
    pool: BackendPool,
) -> anyhow::Result<()> {
    let method: CipherKind = method_str
        .parse()
        .map_err(|_| anyhow::anyhow!("unsupported cipher: {}", method_str))?;

    // Use ServerConfig to properly derive the encryption key from password.
    // We use a dummy address since we're only using it for key derivation.
    let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let ss_config = SsServerConfig::new(dummy_addr, &password, method)
        .map_err(|e| anyhow::anyhow!("shadowsocks config error: {}", e))?;
    let key = ss_config.key().to_vec();

    let context: SharedContext = Context::new_shared(shadowsocks::config::ServerType::Server);

    let listener = TcpListener::bind(&listen_addr).await?;
    tracing::info!(
        listen = %listen_addr,
        method = %method_str,
        "Shadowsocks inbound listener started"
    );

    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let pool = pool.clone();
                let context = context.clone();
                let key = key.clone();

                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);

                    if let Err(e) =
                        handle_ss_connection(stream, client_addr, context, method, &key, pool).await
                    {
                        tracing::debug!(
                            client = %client_addr,
                            error = %e,
                            "Shadowsocks connection failed"
                        );
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "Shadowsocks accept error");
            }
        }
    }
}

/// Handle a single Shadowsocks connection.
async fn handle_ss_connection(
    stream: TcpStream,
    client_addr: std::net::SocketAddr,
    context: SharedContext,
    method: CipherKind,
    key: &[u8],
    pool: BackendPool,
) -> anyhow::Result<()> {
    // Wrap the raw TCP stream in the Shadowsocks decryption layer.
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

    // Fallback: try unhealthy backends as last resort.
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
            tracing::warn!(
                client = %client_addr,
                target = %target,
                "all backends failed"
            );
            return Err(anyhow::anyhow!("all backends unavailable"));
        }
    };

    // Fetch traffic counters for the chosen backend (lock-free thereafter).
    if let Some(ref tc) = chosen_traffic {
        tc.total_connections.fetch_add(1, Ordering::Relaxed);
        tc.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    // Bidirectional relay: SS decrypted stream <-> SOCKS5h backend.
    match relay::relay(&mut ss_stream, &mut backend_stream).await {
        Ok((up, down)) => {
            tracing::debug!(
                target = %target,
                up_bytes = up,
                down_bytes = down,
                "Shadowsocks relay complete"
            );
            if let Some(ref tc) = chosen_traffic {
                tc.bytes_up.fetch_add(up, Ordering::Relaxed);
                tc.bytes_down.fetch_add(down, Ordering::Relaxed);
            }
        }
        Err(e) => {
            tracing::debug!(target = %target, error = %e, "Shadowsocks relay error");
        }
    }
    if let Some(ref tc) = chosen_traffic {
        tc.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    let _ = backend_stream.shutdown().await;

    Ok(())
}

/// Convert a shadowsocks `Address` to our `TargetAddr`.
fn convert_ss_address(addr: &Address) -> TargetAddr {
    match addr {
        Address::SocketAddress(socket_addr) => TargetAddr::Ip(*socket_addr),
        Address::DomainNameAddress(host, port) => TargetAddr::Domain(host.clone(), *port),
    }
}
