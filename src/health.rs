//! Periodic health checker for SOCKS5h backends.
//!
//! Spawns a background task that probes each backend at a configurable interval
//! by performing a full SOCKS5 CONNECT to a known target (e.g. www.google.com:80).
//! Measures round-trip latency and updates the backend pool health state.

use std::time::{Duration, Instant};

use tokio::time;

use crate::backend::BackendPool;
use crate::config::HealthCheckConfig;
use crate::outbound::{socks5h_connect, TargetAddr};

/// Start the health checker background task.
pub async fn run_health_checker(pool: BackendPool, config: HealthCheckConfig) {
    let interval = Duration::from_secs(config.interval_secs);
    let timeout = Duration::from_secs(config.timeout_secs);

    // Parse the check target into a TargetAddr.
    let check_target = parse_check_target(&config.check_target);

    tracing::info!(
        interval_secs = config.interval_secs,
        timeout_secs = config.timeout_secs,
        target = %config.check_target,
        "health checker started"
    );

    let mut ticker = time::interval(interval);
    // The first tick fires immediately; skip it and do initial check after a short delay.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        check_all_backends(&pool, &check_target, timeout).await;
    }
}

/// Probe all backends concurrently.
async fn check_all_backends(pool: &BackendPool, target: &TargetAddr, timeout: Duration) {
    let backends = pool.get_backends_in_order().await;

    // Check all backends concurrently for faster health check cycles.
    let mut handles = Vec::with_capacity(backends.len());

    for (index, info, _healthy) in backends {
        let pool = pool.clone();
        let target = target.clone();
        let info = info.clone();

        handles.push(tokio::spawn(async move {
            let start = Instant::now();

            match tokio::time::timeout(timeout, socks5h_connect(&info, &target, timeout)).await {
                Ok(Ok(_stream)) => {
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

/// Parse a "host:port" string into a TargetAddr.
fn parse_check_target(target: &str) -> TargetAddr {
    if let Some(pos) = target.rfind(':') {
        let host = target[..pos].to_string();
        let port: u16 = target[pos + 1..].parse().unwrap_or(80);
        TargetAddr::Domain(host, port)
    } else {
        TargetAddr::Domain(target.to_string(), 80)
    }
}
