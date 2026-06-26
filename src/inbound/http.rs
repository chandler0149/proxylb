//! HTTP inbound listener.
//!
//! Accepts HTTP CONNECT and standard HTTP proxy requests, extracts the target address
//! using the `httparse` crate, forwards through a healthy SOCKS5h backend,
//! and relays data bidirectionally.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::BoundListener;
use crate::backend::BackendPool;
use crate::outbound::TargetAddr;
use crate::relay::AsRawStreamRef;
use crate::tls::MaybeTlsStream;

/// Run the HTTP inbound listener (TCP or UDS, selected by address prefix).
pub async fn run_http_inbound(
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
) -> anyhow::Result<()> {
    let tls_acceptor = tls_cfg
        .as_ref()
        .map(|c| crate::tls::create_tls_acceptor(c))
        .transpose()?
        .map(Arc::new);
    let username = username.map(Arc::new);
    let password = password.map(Arc::new);

    let listener = BoundListener::bind(&listen_addr, prebound_uds).await?;
    tracing::info!(listen = %listen_addr, "HTTP inbound listener started");

    crate::inbound::run_accept_loop(listener, cancel, "HTTP", move |stream, client_id| {
        let pool = pool.clone();
        let stats = Arc::clone(&stats);
        let tls_acceptor = tls_acceptor.clone();
        let username = username.clone();
        let password = password.clone();
        let local_filter_manager = local_filter_manager.clone();
        async move {
            
            let client_stats = pool.client_manager.get_or_create(&client_id);
            if let Err(e) = handle_http_connection(
                stream,
                client_id.clone(),
                pool,
                stats,
                local_filter_manager.clone(),
                tls_acceptor.as_deref().cloned(),
                username,
                password,
                route_idx,
                client_stats,
            )
            .await
            {
                tracing::debug!(client = %client_id, error = %e, "HTTP connection failed");
            }
        }
    })
    .await
}

/// Handle a single HTTP connection.
async fn handle_http_connection<S>(
    stream: S,
    client_id: crate::backend::ClientId,
    pool: BackendPool,
    stats: Arc<crate::backend::InboundStats>,
    local_filter_manager: Option<Arc<crate::filter::FilterManager>>,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    username: Option<Arc<String>>,
    password: Option<Arc<String>>,
    route_idx: Option<usize>,
    client_stats: Arc<crate::backend::ClientStats>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + AsRawStreamRef + 'static,
{
    let mut client_stream = if let Some(ref acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await?;
        MaybeTlsStream::Tls(tls_stream)
    } else {
        MaybeTlsStream::Plain(stream)
    };

    // Read HTTP headers up to \r\n\r\n.
    let (buf, pos) = match read_headers(&mut client_stream).await {
        Ok(res) => res,
        Err(e) => {
            tracing::debug!(client = %client_id, error = %e, "failed to read HTTP headers");
            return Ok(());
        }
    };

    // Parse request using httparse
    let (method, target, headers) = match parse_http_request_with_headers(&buf[..pos]) {
        Some(res) => res,
        None => {
            tracing::debug!(client = %client_id, "invalid HTTP proxy request or unsupported headers");
            let _ = client_stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    if let (Some(u), Some(p)) = (username, password) {
        let expected_auth = format!("{}:{}", u, p);
        use base64::Engine;
        let expected_base64 = base64::engine::general_purpose::STANDARD.encode(expected_auth);
        let expected_header = format!("Basic {}", expected_base64);

        let mut auth_ok = false;
        for (name, value) in headers {
            if name.eq_ignore_ascii_case("proxy-authorization") {
                if let Ok(v) = std::str::from_utf8(value) {
                    if v == expected_header {
                        auth_ok = true;
                        break;
                    }
                }
            }
        }

        if !auth_ok {
            tracing::debug!(client = %client_id, "HTTP Proxy Authentication failed");
            let _ = client_stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ProxyLB\"\r\nConnection: close\r\n\r\n").await;
            return Ok(());
        }
    }

    let is_blocked = if let Some(ref m) = local_filter_manager {
        m.is_blocked(&target)
    } else {
        pool.filter_manager.is_blocked(&target)
    };

    if is_blocked {
        tracing::debug!(target = %target, "HTTP connection blocked by filter");
        let _ = client_stream
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nBlocked by Filter rules.\r\n",
            )
            .await;
        return Ok(());
    }

    tracing::debug!(client = %client_id, method = %method, target = %target, "HTTP CONNECT request" );

    // Try backends in order with fallback.
    let (mut backend_stream, chosen_traffic) =
        match crate::inbound::route_and_connect(&pool, &target, route_idx).await {
            Ok((s, t)) => (s, t),
            Err(e) => {
                tracing::warn!(
                    client = %client_id,
                    target = %target,
                    error = %e,
                    "all backends failed"
                );
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

    // If CONNECT, respond with 200 Connection Established.
    // Otherwise, we forward the read buffer (headers + any extra read data) to the SOCKS5h backend first.
    if method == "CONNECT" {
        client_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        backend_stream.write_all(&buf).await?;
    }

    crate::inbound::relay_and_track(
        client_stream,
        backend_stream,
        chosen_traffic,
        Some(stats),
        Some(client_stats),
        &target,
        "HTTP",
    )
    .await
}

/// Read HTTP headers until \r\n\r\n, up to max 8192 bytes.
async fn read_headers<S>(stream: &mut S) -> std::io::Result<(Vec<u8>, usize)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 1024];
    let mut bytes_read = 0;
    loop {
        if bytes_read >= buf.len() {
            if buf.len() >= 8192 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP headers too long",
                ));
            }
            buf.resize(buf.len() * 2, 0);
        }
        let n = stream.read(&mut buf[bytes_read..]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before headers received",
            ));
        }
        bytes_read += n;
        if let Some(pos) = find_crlf_crlf(&buf[..bytes_read]) {
            buf.truncate(bytes_read);
            return Ok((buf, pos));
        }
    }
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

/// Parse the target address from an HTTP header buffer.
#[allow(dead_code)]
pub fn parse_http_request(headers_raw: &[u8]) -> Option<(String, TargetAddr)> {
    parse_http_request_with_headers(headers_raw).map(|(m, t, _)| (m, t))
}

pub fn parse_http_request_with_headers<'a>(
    headers_raw: &'a [u8],
) -> Option<(String, TargetAddr, Vec<(&'a str, &'a [u8])>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let status = req.parse(headers_raw).ok()?;
    if !status.is_complete() {
        return None;
    }
    let method = req.method?.to_uppercase();
    let path = req.path?;

    let parsed_headers: Vec<_> = req.headers.iter().map(|h| (h.name, h.value)).collect();

    if method == "CONNECT" {
        let (host, port) = parse_host_port(path, 443)?;
        let target = parse_target_addr(&host, port);
        return Some((method, target, parsed_headers));
    }

    // Standard HTTP proxy: can have absolute path (e.g. http://google.com/path) or relative path with Host header
    let target = if path.starts_with("http://") {
        let host_port_part = path
            .strip_prefix("http://")?
            .split('/')
            .next()?
            .split('?')
            .next()?
            .split('#')
            .next()?;
        let (host, port) = parse_host_port(host_port_part, 80)?;
        parse_target_addr(&host, port)
    } else if path.starts_with("https://") {
        let host_port_part = path
            .strip_prefix("https://")?
            .split('/')
            .next()?
            .split('?')
            .next()?
            .split('#')
            .next()?;
        let (host, port) = parse_host_port(host_port_part, 443)?;
        parse_target_addr(&host, port)
    } else {
        // Look for Host header
        let mut host_val = None;
        for header in req.headers.iter() {
            if header.name.eq_ignore_ascii_case("host") {
                host_val = Some(std::str::from_utf8(header.value).ok()?);
                break;
            }
        }
        let host_str = host_val?;
        let (host, port) = parse_host_port(host_str, 80)?;
        parse_target_addr(&host, port)
    };

    Some((method, target, parsed_headers))
}

fn parse_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    if s.starts_with('[') {
        if let Some(end_bracket) = s.find(']') {
            let host = &s[1..end_bracket];
            let rest = &s[end_bracket + 1..];
            if rest.starts_with(':') {
                let port = rest[1..].parse::<u16>().ok()?;
                return Some((host.to_string(), port));
            } else {
                return Some((host.to_string(), default_port));
            }
        }
    }

    if let Some(last_colon) = s.rfind(':') {
        let port_part = &s[last_colon + 1..];
        if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = port_part.parse::<u16>() {
                return Some((s[..last_colon].to_string(), port));
            }
        }
    }

    Some((s.to_string(), default_port))
}

fn parse_target_addr(host: &str, port: u16) -> TargetAddr {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        TargetAddr::Ip(std::net::SocketAddr::new(ip, port))
    } else {
        TargetAddr::Domain(host.to_string(), port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect() {
        let req = b"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n";
        let (method, target) = parse_http_request(req).unwrap();
        assert_eq!(method, "CONNECT");
        assert_eq!(target.to_string(), "google.com:443");
    }

    #[test]
    fn test_parse_get_absolute() {
        let req = b"GET http://example.com/foo?bar=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (method, target) = parse_http_request(req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target.to_string(), "example.com:80");
    }

    #[test]
    fn test_parse_get_relative_with_host() {
        let req = b"GET /bar HTTP/1.1\r\nHost: test.org:8080\r\nUser-Agent: curl/7.68.0\r\n\r\n";
        let (method, target) = parse_http_request(req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target.to_string(), "test.org:8080");
    }

    #[test]
    fn test_parse_ipv6_connect() {
        let req = b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n";
        let (method, target) = parse_http_request(req).unwrap();
        assert_eq!(method, "CONNECT");
        assert_eq!(target.to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn test_parse_ipv4_host_get() {
        let req = b"GET / HTTP/1.1\r\nHost: 1.1.1.1\r\n\r\n";
        let (method, target) = parse_http_request(req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(target.to_string(), "1.1.1.1:80");
    }
}
