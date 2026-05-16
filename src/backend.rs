//! Backend pool management with health state tracking.
//!
//! Maintains an ordered list of SOCKS5h backends, their health status,
//! a ring-buffer of recent health check results, and cumulative traffic
//! counters updated atomically by the relay tasks.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::config::BackendConfig;
use crate::outbound::socks5h_authenticate;

/// Lock-free per-backend traffic counters.
///
/// Stored behind an `Arc` so inbound relay tasks can hold a clone without
/// acquiring the pool's `RwLock` on every byte count update.
#[derive(Debug, Default)]
pub struct TrafficCounters {
    /// Bytes relayed from client → backend (cumulative).
    pub bytes_up: AtomicU64,
    /// Bytes relayed from backend → client (cumulative).
    pub bytes_down: AtomicU64,
    /// Currently active relay sessions (signed so a race never wraps).
    pub active_connections: AtomicI64,
    /// Total connections ever accepted through this backend.
    pub total_connections: AtomicU64,
    // --- Connection pool stats ---
    /// Worker grabbed a pooled connection and it succeeded.
    pub pool_hits: AtomicU64,
    /// Pool was empty; worker fell back to a fresh on-demand connection.
    pub pool_misses: AtomicU64,
    /// Pooled connection was stale; worker transparently retried with a fresh one.
    pub pool_stale: AtomicU64,
}

/// Maximum number of health check history entries per backend.
const MAX_HISTORY: usize = 10;

/// Parsed backend information.
#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub pool_size: usize,
}

impl BackendInfo {
    pub fn from_config(cfg: &BackendConfig, index: usize) -> anyhow::Result<Self> {
        let addr = &cfg.address;
        // Parse "host:port"
        let (host, port) = if let Some(pos) = addr.rfind(':') {
            let host = addr[..pos].to_string();
            let port: u16 = addr[pos + 1..]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port in backend address: {}", addr))?;
            (host, port)
        } else {
            anyhow::bail!("backend address must be in host:port format: {}", addr);
        };

        let name = cfg
            .name
            .clone()
            .unwrap_or_else(|| format!("backend-{}", index));

        Ok(Self {
            name,
            host,
            port,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            pool_size: cfg.pool_size,
        })
    }

    /// Returns true if this backend requires authentication.
    pub fn requires_auth(&self) -> bool {
        self.username.is_some() && self.password.is_some()
    }
}

/// A single health check result.
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheckResult {
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Current status of a backend.
#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub healthy: bool,
    pub last_check: Option<Instant>,
    pub last_latency: Option<Duration>,
    pub consecutive_failures: u32,
    pub history: VecDeque<HealthCheckResult>,
}

impl Default for BackendStatus {
    fn default() -> Self {
        Self {
            // Assume healthy initially — the first health check will confirm.
            healthy: true,
            last_check: None,
            last_latency: None,
            consecutive_failures: 0,
            history: VecDeque::with_capacity(MAX_HISTORY),
        }
    }
}

/// A single backend entry: info + status + traffic counters.
#[derive(Debug)]
pub struct BackendEntry {
    pub info: BackendInfo,
    pub status: BackendStatus,
    pub traffic: Arc<TrafficCounters>,
    /// Pre-authenticated connection pool.
    /// `flume::Receiver` is Clone + Send + Sync, so no Mutex is needed.
    pub pool_rx: flume::Receiver<TcpStream>,
}

/// Serializable backend status for the web API.
#[derive(Debug, Serialize)]
pub struct BackendStatusView {
    pub name: String,
    pub address: String,
    pub healthy: bool,
    pub last_latency_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub history: Vec<HealthCheckResult>,
    // Traffic stats
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub active_connections: i64,
    pub total_connections: u64,
    // Connection pool stats
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub pool_stale: u64,
}

/// Result of a single pool acquisition attempt.
///
/// Returned by `BackendPool::get_pooled_connection` in a single RwLock read,
/// so callers never need a separate `get_traffic_counters` call.
pub struct PooledConn {
    /// A pre-authenticated stream, or `None` if the pool was empty.
    pub stream: Option<TcpStream>,
    /// Traffic counters for this backend — cheap to clone (Arc).
    pub traffic: Arc<TrafficCounters>,
}

/// Thread-safe backend pool.
#[derive(Clone)]
pub struct BackendPool {
    inner: Arc<RwLock<Vec<BackendEntry>>>,
}

impl BackendPool {
    /// Create a new backend pool from config.
    pub fn new(configs: &[BackendConfig]) -> anyhow::Result<Self> {
        let mut entries = Vec::with_capacity(configs.len());
        for (i, cfg) in configs.iter().enumerate() {
            let info = BackendInfo::from_config(cfg, i)?;
            let (tx, rx) = flume::bounded(info.pool_size.max(1));

            let entry = BackendEntry {
                info: info.clone(),
                status: BackendStatus::default(),
                traffic: Arc::new(TrafficCounters::default()),
                pool_rx: rx,
            };
            entries.push(entry);

            // Spawn refill task for this backend.
            tokio::spawn(refill_pool_task(info, tx));
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(entries)),
        })
    }

    /// Try to acquire a connection from the pre-authenticated pool.
    ///
    /// Returns a [`PooledConn`] containing:
    /// - `stream`: the pooled `TcpStream` if one was available, or `None` if the pool was empty.
    /// - `traffic`: an `Arc` to the backend's counters, obtained in the **same** lock acquisition.
    ///
    /// Callers must not call `get_traffic_counters` separately; use the returned `Arc` directly.
    /// Returns `None` only if `index` is out of bounds (never happens in practice).
    pub async fn get_pooled_connection(&self, index: usize) -> Option<PooledConn> {
        let guard = self.inner.read().await;
        guard.get(index).map(|e| PooledConn {
            stream: e.pool_rx.try_recv().ok(),
            traffic: Arc::clone(&e.traffic),
        })
    }

    /// Return a clone of the `Arc<TrafficCounters>` for the given backend index.
    ///
    /// Callers hold this `Arc` across the relay lifetime and update it directly
    /// without taking the pool lock again.
    pub async fn get_traffic_counters(&self, index: usize) -> Option<Arc<TrafficCounters>> {
        let guard = self.inner.read().await;
        guard.get(index).map(|e| Arc::clone(&e.traffic))
    }

    /// Get the info of all backends with their index and current health.
    /// Returns (index, BackendInfo, is_healthy) for each backend in priority order.
    pub async fn get_backends_in_order(&self) -> Vec<(usize, BackendInfo, bool)> {
        let guard = self.inner.read().await;
        guard
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.info.clone(), e.status.healthy))
            .collect()
    }

    /// Mark a backend as healthy with measured latency.
    pub async fn mark_healthy(&self, index: usize, latency: Duration) {
        let mut guard = self.inner.write().await;
        if let Some(entry) = guard.get_mut(index) {
            let was_unhealthy = !entry.status.healthy;
            entry.status.healthy = true;
            entry.status.last_check = Some(Instant::now());
            entry.status.last_latency = Some(latency);
            entry.status.consecutive_failures = 0;

            let result = HealthCheckResult {
                timestamp: Utc::now(),
                success: true,
                latency_ms: Some(latency.as_millis() as u64),
                error: None,
            };
            push_history(&mut entry.status.history, result);

            if was_unhealthy {
                tracing::info!(
                    backend = %entry.info.name,
                    latency_ms = latency.as_millis() as u64,
                    "backend recovered"
                );
            }
        }
    }

    /// Mark a backend as unhealthy with an error message.
    pub async fn mark_unhealthy(&self, index: usize, error: &str) {
        let mut guard = self.inner.write().await;
        if let Some(entry) = guard.get_mut(index) {
            let was_healthy = entry.status.healthy;
            entry.status.healthy = false;
            entry.status.last_check = Some(Instant::now());
            entry.status.consecutive_failures += 1;

            let result = HealthCheckResult {
                timestamp: Utc::now(),
                success: false,
                latency_ms: None,
                error: Some(error.to_string()),
            };
            push_history(&mut entry.status.history, result);

            if was_healthy {
                tracing::warn!(
                    backend = %entry.info.name,
                    error = %error,
                    "backend became unhealthy"
                );
            }
        }
    }

    /// Get status views for the web dashboard.
    pub async fn status_views(&self) -> Vec<BackendStatusView> {
        let guard = self.inner.read().await;
        guard
            .iter()
            .map(|e| BackendStatusView {
                name: e.info.name.clone(),
                address: format!("{}:{}", e.info.host, e.info.port),
                healthy: e.status.healthy,
                last_latency_ms: e.status.last_latency.map(|d| d.as_millis() as u64),
                consecutive_failures: e.status.consecutive_failures,
                history: e.status.history.iter().cloned().collect(),
                bytes_up: e.traffic.bytes_up.load(Ordering::Relaxed),
                bytes_down: e.traffic.bytes_down.load(Ordering::Relaxed),
                active_connections: e.traffic.active_connections.load(Ordering::Relaxed),
                total_connections: e.traffic.total_connections.load(Ordering::Relaxed),
                pool_hits: e.traffic.pool_hits.load(Ordering::Relaxed),
                pool_misses: e.traffic.pool_misses.load(Ordering::Relaxed),
                pool_stale: e.traffic.pool_stale.load(Ordering::Relaxed),
            })
            .collect()
    }
}

fn push_history(history: &mut VecDeque<HealthCheckResult>, result: HealthCheckResult) {
    if history.len() >= MAX_HISTORY {
        history.pop_front();
    }
    history.push_back(result);
}

/// Background task that keeps the SOCKS5 connection pool filled for a backend.
async fn refill_pool_task(info: BackendInfo, tx: flume::Sender<TcpStream>) {
    let backend_addr = format!("{}:{}", info.host, info.port);
    let retry_interval = Duration::from_secs(5);

    loop {
        // Attempt to establish and authenticate a new connection.
        let result = async {
            let stream = TcpStream::connect(&backend_addr).await?;
            stream.set_nodelay(true)?;
            socks5h_authenticate(stream, &info).await
        }
        .await;

        match result {
            Ok(stream) => {
                // send_async blocks (async) until there is space in the channel,
                // providing natural back-pressure without an explicit reserve step.
                if tx.send_async(stream).await.is_err() {
                    break; // Receiver dropped — pool is shutting down.
                }
                tracing::trace!(backend = %info.name, "pool refilled with new connection");
            }
            Err(e) => {
                tracing::debug!(
                    backend = %info.name,
                    error = %e,
                    "failed to refill connection pool; retrying in {}s",
                    retry_interval.as_secs()
                );
                tokio::time::sleep(retry_interval).await;
            }
        }
    }
}
