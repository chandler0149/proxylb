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
use tokio::net::{TcpListener, TcpStream};

use crate::backend::BackendPool;
use crate::outbound::TargetAddr;


/// Run the Shadowsocks inbound listener.
pub async fn run_shadowsocks_inbound(
    listen_addr: String,
    password: String,
    method_str: String,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
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
                let stats = Arc::clone(&stats);

                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);

                    if let Err(e) =
                        handle_ss_connection(stream, client_addr, context, method, &key, pool, stats, filter_enabled).await

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
    stats: Arc<crate::backend::InboundStats>,
    filter_enabled: bool,
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

    let is_private = crate::inbound::is_private_target(&target).await;
    if crate::inbound::likely(filter_enabled) && crate::inbound::unlikely(is_private) {
        tracing::warn!(target = %target, "Shadowsocks connection rejected: private target");
        return Err(anyhow::anyhow!("private address target is rejected by filter"));
    }



    // Try backends in order with fallback.
    let (backend_stream, chosen_traffic) = match crate::inbound::route_and_connect(&pool, &target).await {
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


    crate::inbound::relay_and_track(ss_stream, backend_stream, chosen_traffic, Some(stats), &target, "Shadowsocks").await
}

/// Convert a shadowsocks `Address` to our `TargetAddr`.
fn convert_ss_address(addr: &Address) -> TargetAddr {
    match addr {
        Address::SocketAddress(socket_addr) => TargetAddr::Ip(*socket_addr),
        Address::DomainNameAddress(host, port) => TargetAddr::Domain(host.clone(), *port),
    }
}
