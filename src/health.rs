//! Periodic health checker for SOCKS5h backends.
//!
//! Spawns a background task that probes each backend at a configurable interval
//! by performing a full SOCKS5 CONNECT to a known target (e.g. www.google.com:80).
//! Measures round-trip latency and updates the backend pool health state.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::backend::BackendPool;
use crate::config::HealthCheckConfig;
use crate::outbound::{socks5h_connect, TargetAddr};

/// Target for the health check probe.
#[derive(Clone)]
struct ProbeTarget {
    addr: TargetAddr,
    host: String,
    path: String,
    is_https: bool,
}

/// Start the health checker background task.
pub async fn run_health_checker(pool: BackendPool, config: HealthCheckConfig) {
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);

    // Parse the check target into a ProbeTarget.
    let check_target = match parse_check_target(&config.check_target) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(target = %config.check_target, error = %e, "failed to parse health check target; using default");
            parse_check_target("http://www.google.com:80/").unwrap()
        }
    };

    tracing::info!(
        interval_secs = config.interval_secs,
        timeout_secs = config.timeout_secs,
        target = %config.check_target,
        "health checker started"
    );

    let mut ticker = time::interval(interval);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        check_all_backends(&pool, &check_target, timeout).await;
    }
}

/// Probe all backends concurrently.
async fn check_all_backends(pool: &BackendPool, target: &ProbeTarget, timeout: Duration) {
    let backends = pool.get_backends_in_order().await;

    // Pre-initialize TLS config if needed to avoid repeating it for each backend.
    let tls_config = if target.is_https {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Some(Arc::new(config))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(backends.len());

    for (index, info, _healthy) in backends {
        let pool = pool.clone();
        let target = target.clone();
        let info = info.clone();
        let tls_config = tls_config.clone();

        handles.push(tokio::spawn(async move {
            let start = Instant::now();

            let result = async {
                let stream = socks5h_connect(&info, &target.addr, timeout).await?;
                if let Some(config) = tls_config {
                    let connector = TlsConnector::from(config);
                    let domain = ServerName::try_from(target.host.clone())
                        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid DNS name"))?;
                    let mut tls_stream = connector.connect(domain, stream).await?;
                    perform_http_get(&mut tls_stream, &target).await
                } else {
                    let mut stream = stream;
                    perform_http_get(&mut stream, &target).await
                }
            };

            match tokio::time::timeout(timeout, result).await {
                Ok(Ok(_)) => {
                    let latency = start.elapsed();
                    tracing::debug!(
                        backend = %info.name,
                        latency_ms = latency.as_millis() as u64,
                        "health check passed"
                    );
                    pool.mark_healthy(index, latency).await;
                }
                Ok(Err(e)) => {
                    tracing::debug!(
                        backend = %info.name,
                        error = %e,
                        "health check failed"
                    );
                    pool.mark_unhealthy(index, &e.to_string()).await;
                }
                Err(_) => {
                    tracing::debug!(
                        backend = %info.name,
                        "health check timed out"
                    );
                    pool.mark_unhealthy(index, "health check timed out").await;
                }
            }
        }));
    }

    // Wait for all checks to complete.
    for handle in handles {
        let _ = handle.await;
    }
}

/// Perform a minimal HTTP/1.1 GET request on the stream.
async fn perform_http_get<S>(stream: &mut S, target: &ProbeTarget) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: curl/8.7.1\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\r\n",
        target.path, target.host
    );

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await?;

    if buf.starts_with(b"HTTP/1.1 ") || buf.starts_with(b"HTTP/1.0 ") {
        let status_str = std::str::from_utf8(&buf[9..12]).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP status code")
        })?;
        let status: u16 = status_str.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid HTTP status code")
        })?;

        if (200..400).contains(&status) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP check failed with status: {}", status),
            ))
        }
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP response",
        ))
    }
}

/// Parse a URL or "host:port" string into a ProbeTarget.
fn parse_check_target(target_str: &str) -> anyhow::Result<ProbeTarget> {
    let url = if target_str.contains("://") {
        Url::parse(target_str)?
    } else {
        Url::parse(&format!("http://{}", target_str))?
    };

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host in target URL"))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let is_https = url.scheme() == "https";

    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    Ok(ProbeTarget {
        addr: TargetAddr::Domain(host.clone(), port),
        host,
        path: if path.is_empty() {
            "/".to_string()
        } else {
            path
        },
        is_https,
    })
}
