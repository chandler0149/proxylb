pub mod pool;
pub mod protocol;
pub mod session;
pub mod stream;

pub use pool::AnytlsManager;

use crate::backend::BackendInfo;
use crate::outbound::BackendStream;
use crate::outbound::TargetAddr;
use std::sync::Arc;

/// Establishes a fresh underlying TCP+TLS session, adds it to the manager, and opens a stream.
pub async fn anytls_connect_fresh(info: &BackendInfo) -> std::io::Result<BackendStream> {
    let manager = info.anytls_manager.as_ref().unwrap();

    // Fast path: reuse existing session
    if let Some(session) = manager.get_session().await {
        let stream = session.open_stream().await;
        return Ok(BackendStream::boxed(Box::pin(stream)));
    }

    // Slow path: establish new TCP+TLS connection
    let (addr, bind_interface) = match &info.endpoint {
        crate::backend::BackendEndpoint::Tcp { host, port } => {
            (format!("{}:{}", host, port), info.bind_interface.as_deref())
        }
        crate::backend::BackendEndpoint::Unix { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AnyTLS requires TCP",
            ));
        }
        crate::backend::BackendEndpoint::Direct => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "AnyTLS requires an endpoint",
            ));
        }
    };

    let tcp = crate::outbound::tcp_connect_raw(
        &addr,
        bind_interface,
        std::time::Duration::from_secs(10),
        info.tcp_congestion.as_deref(),
    )
    .await?;
    let _ = tcp.set_nodelay(true);
    let stream = BackendStream::tcp(tcp);
    let tls_connector = info.tls_connector.as_ref().unwrap();
    let domain = info.server_name.clone().unwrap_or_default();
    let domain_pki = tokio_rustls::rustls::pki_types::ServerName::try_from(domain)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid SNI"))?
        .to_owned();

    tracing::debug!("anytls_connect_fresh: starting tls connect");
    let tls = tls_connector
        .connect(domain_pki, stream)
        .await
        .map_err(|e| {
            tracing::error!("anytls_connect_fresh tls error: {:?}", e);
            e
        })?;
    tracing::debug!("anytls_connect_fresh: tls connect ok, starting session connect");
    let session = session::Session::connect(manager.password(), tls)
        .await
        .map_err(|e| {
            tracing::error!("anytls_connect_fresh session connect error: {:?}", e);
            e
        })?;
    tracing::debug!("anytls_connect_fresh: session connect ok");
    let session_arc = Arc::new(session);
    manager.add_session(session_arc.clone()).await;

    let stream = session_arc.open_stream().await;
    Ok(BackendStream::boxed(Box::pin(stream)))
}

/// Writes the target address to the AnyTLS stream using AsyncWrite.
pub async fn anytls_connect_target(
    mut stream: BackendStream,
    target: &TargetAddr,
) -> std::io::Result<BackendStream> {
    let mut addr_bytes = Vec::new();
    let (target_host, target_port) = match target {
        TargetAddr::Domain(h, p) => (h.clone(), *p),
        TargetAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
    };

    const SOCKS5_ADDR_IPV4: u8 = 0x01;
    const SOCKS5_ADDR_DOMAIN: u8 = 0x03;
    const SOCKS5_ADDR_IPV6: u8 = 0x04;

    use std::net::{Ipv4Addr, Ipv6Addr};
    if let Ok(ipv4) = target_host.parse::<Ipv4Addr>() {
        addr_bytes.push(SOCKS5_ADDR_IPV4);
        addr_bytes.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target_host.parse::<Ipv6Addr>() {
        addr_bytes.push(SOCKS5_ADDR_IPV6);
        addr_bytes.extend_from_slice(&ipv6.octets());
    } else {
        let domain_bytes = target_host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Domain name too long",
            ));
        }
        addr_bytes.push(SOCKS5_ADDR_DOMAIN);
        addr_bytes.push(domain_bytes.len() as u8);
        addr_bytes.extend_from_slice(domain_bytes);
    }
    addr_bytes.extend_from_slice(&target_port.to_be_bytes());

    use tokio::io::AsyncWriteExt;
    stream.write_all(&addr_bytes).await?;
    stream.flush().await?;
    Ok(stream)
}
