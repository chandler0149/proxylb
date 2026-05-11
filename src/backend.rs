//! Backend pool management with health state tracking.
//!
//! Maintains an ordered list of SOCKS5h backends, their health status,
//! and a ring-buffer of recent health check results for the web dashboard.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::config::BackendConfig;

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

/// A single backend entry: info + status.
#[derive(Debug)]
pub struct BackendEntry {
    pub info: BackendInfo,
    pub status: BackendStatus,
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
            entries.push(BackendEntry {
                info,
                status: BackendStatus::default(),
            });
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(entries)),
        })
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
