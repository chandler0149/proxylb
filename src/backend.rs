//! Backend pool management with health state tracking.
//!
//! Maintains an ordered list of SOCKS5h backends, their health status,
//! a ring-buffer of recent health check results, and cumulative traffic
//! counters updated atomically by the relay tasks.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::Serialize;
use shadowsocks::config::ServerConfig as SsServerConfig;
use shadowsocks::context::{Context as SsContext, SharedContext};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::config::{BackendConfig, GroupConfig};
use crate::outbound::BackendStream;
use crate::scheduler::*;
use std::collections::HashMap;
use tokio_rustls::TlsConnector;

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

/// How the load balancer connects to a SOCKS5 backend.
#[derive(Debug, Clone)]
pub enum BackendEndpoint {
    /// Classic TCP connection to `host:port`.
    Tcp { host: String, port: u16 },
    /// Unix domain socket at the given filesystem path.
    Unix { path: String },
    /// Direct connection outbound.
    Direct,
}

impl BackendEndpoint {
    /// Human-readable address string (used in the web dashboard).
    pub fn display(&self) -> String {
        match self {
            BackendEndpoint::Tcp { host, port } => format!("{}:{}", host, port),
            BackendEndpoint::Unix { path } => format!("unix:{}", path),
            BackendEndpoint::Direct => "direct".to_string(),
        }
    }
}

/// Parsed backend information.
#[derive(Clone)]
pub struct BackendInfo {
    pub name: String,
    pub endpoint: BackendEndpoint,
    pub username: Option<String>,
    pub password: Option<String>,
    pub pool_size: usize,
    /// Set when this backend is a Shadowsocks server.
    /// Contains the pre-derived key material (cheap to clone — inner is `Arc`).
    pub ss_config: Option<Arc<SsServerConfig>>,
    /// Shared Shadowsocks context — one per backend, reused across pool connections.
    pub ss_context: Option<SharedContext>,
    pub bind_interface: Option<String>,
    pub tls_connector: Option<TlsConnector>,
    pub server_name: Option<String>,
    pub enabled: Option<bool>,
    pub force_healthy: bool,
    pub max_fails: u32,
}

impl std::fmt::Debug for BackendInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendInfo")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl BackendInfo {
    pub fn from_config(
        cfg: &BackendConfig,
        index: usize,
        global_bind_interface: Option<&str>,
    ) -> anyhow::Result<Self> {
        let is_direct = cfg.backend_type == "direct";

        let endpoint = match cfg.backend_type.as_str() {
            "direct" => BackendEndpoint::Direct,
            "socks5" | "ss" | "shadowsocks" | "uds" => {
                let addr = cfg
                    .address
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("backend must specify address"))?;
                if addr.starts_with("unix://") {
                    let path = addr.strip_prefix("unix://").unwrap().to_string();
                    BackendEndpoint::Unix { path }
                } else if addr.starts_with('/')
                    || addr.starts_with("./")
                    || addr.starts_with("../")
                    || cfg.backend_type == "uds"
                {
                    let path = if let Some(stripped) = addr.strip_prefix("unix://") {
                        stripped.to_string()
                    } else {
                        addr.clone()
                    };
                    BackendEndpoint::Unix { path }
                } else {
                    // Parse "host:port"
                    if let Some(pos) = addr.rfind(':') {
                        let host = addr[..pos].to_string();
                        let port: u16 = addr[pos + 1..].parse().map_err(|_| {
                            anyhow::anyhow!("invalid port in backend address: {}", addr)
                        })?;
                        BackendEndpoint::Tcp { host, port }
                    } else {
                        anyhow::bail!(
                            "backend address must be in host:port or unix://path format: {}",
                            addr
                        );
                    }
                }
            }
            other => anyhow::bail!("unknown backend type: {}", other),
        };

        let name = cfg.name.clone().unwrap_or_else(|| {
            if is_direct {
                format!("direct-{}", index)
            } else {
                format!("backend-{}", index)
            }
        });

        // Build Shadowsocks config if this is an SS backend.
        let (ss_config, ss_context) =
            if cfg.backend_type == "ss" || cfg.backend_type == "shadowsocks" {
                let method_str = cfg.username.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("ss backend must specify method in username field")
                })?;
                let pass = cfg.password.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("ss backend must specify password in password field")
                })?;
                let addr = cfg
                    .address
                    .as_deref()
                    .expect("ss backend must have address");
                let dummy_sock: std::net::SocketAddr = if addr.starts_with("unix://")
                    || addr.starts_with('/')
                    || addr.starts_with("./")
                    || addr.starts_with("../")
                {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    addr.parse()
                        .or_else(|_| {
                            if let Some(pos) = addr.rfind(':') {
                                let port: u16 = addr[pos + 1..].parse()?;
                                let host_str = &addr[..pos];
                                let ip: std::net::IpAddr = host_str.parse().unwrap_or(
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                );
                                Ok(std::net::SocketAddr::new(ip, port))
                            } else {
                                Err(anyhow::anyhow!("invalid address"))
                            }
                        })
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                };

                let method: shadowsocks::crypto::CipherKind = method_str
                    .parse()
                    .map_err(|_| anyhow::anyhow!("unsupported ss_method: {}", method_str))?;

                let ss_cfg = SsServerConfig::new(dummy_sock, pass, method).map_err(|e| {
                    anyhow::anyhow!("shadowsocks config error for backend '{}': {}", name, e)
                })?;

                let ctx = SsContext::new_shared(shadowsocks::config::ServerType::Local);
                (Some(Arc::new(ss_cfg)), Some(ctx))
            } else {
                (None, None)
            };

        let pool_size = if is_direct { 0 } else { cfg.pool_size };
        let bind_interface = cfg
            .bind_interface
            .clone()
            .or_else(|| global_bind_interface.map(String::from));

        let tls_connector = if let Some(tls) = &cfg.tls {
            Some(crate::tls::create_tls_connector(tls.insecure)?)
        } else {
            None
        };

        let server_name = cfg.tls.as_ref().and_then(|tls| tls.server_name.clone());

        Ok(Self {
            name,
            endpoint,
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            pool_size,
            ss_config,
            ss_context,
            bind_interface,
            tls_connector,
            server_name,
            enabled: cfg.enabled,
            force_healthy: cfg.force_healthy,
            max_fails: cfg.max_fails,
        })
    }

    /// Returns `true` if this is a Shadowsocks backend.
    pub fn is_shadowsocks(&self) -> bool {
        self.ss_config.is_some()
    }

    /// Returns `true` if this is a direct connection outbound backend.
    pub fn is_direct(&self) -> bool {
        matches!(self.endpoint, BackendEndpoint::Direct)
    }

    /// Returns true if this backend requires SOCKS5 authentication.
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
    pub handshake_latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Current status of a backend.
#[derive(Debug, Clone)]
pub struct BackendStatus {
    pub healthy: bool,
    pub enabled: bool,
    pub last_check: Option<Instant>,
    pub last_latency: Option<Duration>,
    pub last_handshake_latency: Option<Duration>,
    pub consecutive_failures: u32,
    pub history: VecDeque<HealthCheckResult>,
}

impl Default for BackendStatus {
    fn default() -> Self {
        Self {
            // Assume healthy initially — the first health check will confirm.
            healthy: true,
            enabled: true,
            last_check: None,
            last_latency: None,
            last_handshake_latency: None,
            consecutive_failures: 0,
            history: VecDeque::with_capacity(MAX_HISTORY),
        }
    }
}

/// A single backend entry: info + status + traffic counters.
#[derive(Debug)]
pub struct BackendEntry {
    pub info: Arc<BackendInfo>,
    pub status: Arc<parking_lot::Mutex<BackendStatus>>,
    pub traffic: Arc<TrafficCounters>,
    /// Pre-authenticated connection pool.
    /// `flume::Receiver` is Clone + Send + Sync, so no Mutex is needed.
    pub pool_rx: flume::Receiver<BackendStream>,
    /// Cancels this entry's `refill_pool_task` when the backend is removed.
    pub cancel: CancellationToken,
    pub enabled_tx: tokio::sync::watch::Sender<bool>,
    pub rt_chg_signal: tokio::sync::watch::Receiver<u64>,
}

/// Serializable backend status for the web API.
#[derive(Debug, Clone, Serialize)]
pub struct BackendStatusView {
    pub name: String,
    pub address: String,
    pub healthy: bool,
    pub enabled: bool,
    pub last_latency_ms: Option<u64>,
    pub handshake_latency_ms: Option<u64>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Serializable tree node representing routing topology.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum TreeItem {
    #[serde(rename = "backend")]
    Backend { status: BackendStatusView },
    #[serde(rename = "group")]
    Group {
        name: String,
        strategy: String,
        members: Vec<TreeItem>,
    },
}

/// Result of a single pool acquisition attempt.
///
/// Returned by `BackendPool::get_pooled_connection` in a single RwLock read,
/// so callers never need a separate `get_traffic_counters` call.
pub struct PooledConn {
    /// A pre-authenticated stream, or `None` if the pool was empty.
    pub stream: Option<BackendStream>,
    /// Traffic counters for this backend — cheap to clone (Arc).
    pub traffic: Arc<TrafficCounters>,
}

#[derive(Debug)]
pub struct InboundStats {
    pub name: String,
    pub listen: String,
    pub inbound_type: String,
    pub total_connections: AtomicU64,
    pub active_connections: AtomicI64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InboundStatsView {
    pub name: String,
    pub listen: String,
    pub inbound_type: String,
    pub total_connections: u64,
    pub active_connections: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

struct BackendPoolInner {
    entries: Vec<BackendEntry>,
    groups: Vec<Group>,
    failover_order: Vec<Target>,
}

#[derive(Clone)]
pub struct BackendHotPath {
    pub pool_rx: flume::Receiver<BackendStream>,
    pub traffic: Arc<TrafficCounters>,
    pub status: Arc<parking_lot::Mutex<BackendStatus>>,
    pub info_name: Arc<str>,
    pub force_healthy: bool,
    pub max_fails: u32,
}

/// Thread-safe backend pool.

#[derive(Clone)]
pub struct BackendPool {
    inner: Arc<RwLock<BackendPoolInner>>,
    cached: Arc<ArcSwap<CachedCandidates>>,
    route_map: Arc<HashMap<String, usize>>,
    route_caches: Arc<ArcSwap<Vec<Arc<CachedCandidates>>>>,
    pub hot_paths: Arc<ArcSwap<Vec<BackendHotPath>>>,
    pub inbound_stats: Arc<parking_lot::Mutex<Vec<Arc<InboundStats>>>>,
    pub rt_chg_signal: tokio::sync::watch::Receiver<u64>,
    pub filter_manager: Arc<crate::filter::FilterManager>,
    pub ancillary_handle: tokio::runtime::Handle,
    pub client_manager: crate::stats::ClientStatsManager,
    pub domain_manager: crate::stats::DomainStatsManager,
}

impl BackendPool {
    /// Create a new backend pool from config.
    pub fn new(
        configs: &[BackendConfig],
        group_configs: &[GroupConfig],
        failover_order_cfg: Option<&Vec<String>>,
        global_bind_interface: Option<&str>,
        rt_chg_signal: tokio::sync::watch::Receiver<u64>,
        filter_config: &crate::config::FilterConfig,
        ancillary_handle: tokio::runtime::Handle,
        active_routes: std::collections::HashSet<String>,
    ) -> anyhow::Result<Self> {
        let mut entries = Vec::with_capacity(configs.len());
        for (i, cfg) in configs.iter().enumerate() {
            let info = BackendInfo::from_config(cfg, i, global_bind_interface)?;
            let cancel = CancellationToken::new();
            let (tx, rx) = flume::bounded(info.pool_size.max(1));
            let initial_enabled = info.enabled.unwrap_or(true);
            let (enabled_tx, enabled_signal) = tokio::sync::watch::channel(initial_enabled);

            let mut status = BackendStatus::default();
            status.enabled = initial_enabled;

            let traffic = Arc::new(TrafficCounters::default());
            let entry = BackendEntry {
                info: Arc::new(info.clone()),
                status: Arc::new(parking_lot::Mutex::new(status)),
                traffic: traffic.clone(),
                pool_rx: rx.clone(),
                cancel: cancel.clone(),
                enabled_tx,
                rt_chg_signal: rt_chg_signal.clone(),
            };
            entries.push(entry);

            // Spawn refill task for this backend.
            ancillary_handle.spawn(refill_pool_task(
                info,
                enabled_signal,
                tx,
                rx,
                cancel,
                rt_chg_signal.clone(),
            ));
        }

        let (groups, failover_order) =
            build_groups_and_failover_order(&entries, group_configs, failover_order_cfg);
        let (cached_healthy, cached_unhealthy) =
            calculate_candidates(&entries, &groups, &failover_order);

        let cached = Arc::new(ArcSwap::from_pointee(CachedCandidates {
            strategy: crate::config::GroupStrategy::Failover,
            hash_ring: Vec::new(),
            wrr_choices: Vec::new(),
            healthy: cached_healthy.clone(),
            unhealthy: cached_unhealthy.clone(),
        }));

        let hot_paths = entries
            .iter()
            .map(|e| BackendHotPath {
                pool_rx: e.pool_rx.clone(),
                traffic: Arc::clone(&e.traffic),
                status: Arc::clone(&e.status),
                info_name: Arc::from(e.info.name.as_str()),
                force_healthy: e.info.force_healthy,
                max_fails: e.info.max_fails,
            })
            .collect::<Vec<_>>();
        let hot_paths = Arc::new(ArcSwap::from_pointee(hot_paths));

        let filter_config = filter_config.clone();

        let mut route_map = HashMap::new();
        for (i, route) in active_routes.into_iter().enumerate() {
            route_map.insert(route, i);
        }
        let route_map = Arc::new(route_map);
        let route_caches = Arc::new(ArcSwap::from_pointee(vec![
            Arc::new(CachedCandidates {
                strategy: crate::config::GroupStrategy::Failover,
                hash_ring: Vec::new(),
                wrr_choices: Vec::new(),
                healthy: vec![],
                unhealthy: vec![]
            });
            route_map.len()
        ]));

        Ok(Self {
            inner: Arc::new(RwLock::new(BackendPoolInner {
                entries,
                groups,
                failover_order,
            })),
            cached,
            route_map,
            route_caches,
            hot_paths,
            inbound_stats: Arc::new(parking_lot::Mutex::new(Vec::new())),
            rt_chg_signal,
            filter_manager: Arc::new(crate::filter::FilterManager::new(
                &filter_config,
                Some("proxylb.db"),
            )),
            ancillary_handle,
            client_manager: crate::stats::ClientStatsManager::new(),
            domain_manager: crate::stats::DomainStatsManager::new(),
        })
    }

    /// Register a new inbound listener dynamically or return existing stats if already registered.
    pub fn register_inbound(
        &self,
        name: String,
        listen: String,
        inbound_type: String,
    ) -> Arc<InboundStats> {
        let mut stats_list = self.inbound_stats.lock();
        if let Some(existing) = stats_list.iter().find(|s| s.listen == listen) {
            return Arc::clone(existing);
        }
        let stats = Arc::new(InboundStats {
            name,
            listen,
            inbound_type,
            total_connections: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        });
        stats_list.push(Arc::clone(&stats));
        stats
    }

    /// Retrieve a snapshot of the stats for all registered inbounds.
    pub fn get_inbound_stats(&self) -> Vec<InboundStatsView> {
        let stats_list = self.inbound_stats.lock();
        stats_list
            .iter()
            .map(|s| InboundStatsView {
                name: s.name.clone(),
                listen: s.listen.clone(),
                inbound_type: s.inbound_type.clone(),
                total_connections: s.total_connections.load(Ordering::Relaxed),
                active_connections: s.active_connections.load(Ordering::Relaxed),
                tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Hot-reload the backend list from new configs.
    ///
    /// - Backends whose endpoint + name match an existing entry keep their
    ///   `Arc<TrafficCounters>` and pool channel (warm pool, preserved history).
    /// - New backends are cold-started with fresh counters and a new pool.
    /// - Removed backends have their `CancellationToken` cancelled, which causes
    ///   `refill_pool_task` to exit cleanly after its current iteration.
    ///
    /// Returns `(added, removed, kept)` counts for logging.
    pub async fn reload(
        &self,
        new_configs: &[BackendConfig],
        group_configs: &[GroupConfig],
        failover_order_cfg: Option<&Vec<String>>,
        global_bind_interface: Option<&str>,
    ) -> anyhow::Result<(usize, usize, usize)> {
        let mut guard = self.inner.write().await;

        let mut new_entries: Vec<BackendEntry> = Vec::with_capacity(new_configs.len());
        let mut added = 0usize;
        let mut kept = 0usize;

        for (i, cfg) in new_configs.iter().enumerate() {
            let new_info = BackendInfo::from_config(cfg, i, global_bind_interface)?;

            // Look for a matching existing entry (same endpoint + name).
            let existing_pos = guard.entries.iter().position(|e| {
                e.info.name == new_info.name
                    && e.info.endpoint.display() == new_info.endpoint.display()
            });

            if let Some(pos) = existing_pos {
                // Reuse the existing entry — just update pool_size on the info.
                // We swap it out of the vec to move it into new_entries.
                let mut entry = guard.entries.swap_remove(pos);

                let creds_or_pool_changed = entry.info.username != new_info.username
                    || entry.info.password != new_info.password
                    || entry.info.pool_size != new_info.pool_size;

                if let Some(new_enabled) = new_info.enabled {
                    let _ = entry.enabled_tx.send(new_enabled);
                    entry.status.lock().enabled = new_enabled;
                    if !new_enabled {
                        while entry.pool_rx.try_recv().is_ok() {}
                    }
                }

                entry.info = Arc::new(new_info.clone());

                if creds_or_pool_changed {
                    // Cancel old refill task
                    entry.cancel.cancel();

                    // Create fresh cancel token and channel
                    let new_cancel = CancellationToken::new();
                    let (tx, rx) = flume::bounded(new_info.pool_size.max(1));

                    entry.pool_rx = rx.clone();
                    entry.cancel = new_cancel.clone();

                    let enabled_signal = entry.enabled_tx.subscribe();
                    // Spawn the new refill task with new configuration and channel
                    self.ancillary_handle.spawn(refill_pool_task(
                        new_info,
                        enabled_signal,
                        tx,
                        rx,
                        new_cancel,
                        entry.rt_chg_signal.clone(),
                    ));
                }

                new_entries.push(entry);
                kept += 1;
            } else {
                // Brand-new backend.
                let cancel = CancellationToken::new();
                let (tx, rx) = flume::bounded(new_info.pool_size.max(1));
                let initial_enabled = new_info.enabled.unwrap_or(true);
                let (enabled_tx, enabled_signal) = tokio::sync::watch::channel(initial_enabled);

                let mut status = BackendStatus::default();
                status.enabled = initial_enabled;

                let traffic = Arc::new(TrafficCounters::default());
                let entry = BackendEntry {
                    info: Arc::new(new_info.clone()),
                    status: Arc::new(parking_lot::Mutex::new(status)),
                    traffic: traffic.clone(),
                    pool_rx: rx.clone(),
                    cancel: cancel.clone(),
                    enabled_tx,
                    rt_chg_signal: self.rt_chg_signal.clone(),
                };
                new_entries.push(entry);
                self.ancillary_handle.spawn(refill_pool_task(
                    new_info,
                    enabled_signal,
                    tx,
                    rx,
                    cancel,
                    self.rt_chg_signal.clone(),
                ));
                added += 1;
            }
        }

        // Whatever remains in `guard.entries` was not matched — cancel their refill tasks.
        let removed = guard.entries.len();
        for old_entry in guard.entries.drain(..) {
            old_entry.cancel.cancel();
        }

        let (groups, failover_order) =
            build_groups_and_failover_order(&new_entries, group_configs, failover_order_cfg);
        let (cached_healthy, cached_unhealthy) =
            calculate_candidates(&new_entries, &groups, &failover_order);

        self.cached.store(Arc::new(CachedCandidates {
            strategy: crate::config::GroupStrategy::Failover,
            hash_ring: Vec::new(),
            wrr_choices: Vec::new(),
            healthy: cached_healthy.clone(),
            unhealthy: cached_unhealthy.clone(),
        }));

        let hot_paths_vec = new_entries
            .iter()
            .map(|e| BackendHotPath {
                pool_rx: e.pool_rx.clone(),
                traffic: Arc::clone(&e.traffic),
                status: Arc::clone(&e.status),
                info_name: Arc::from(e.info.name.as_str()),
                force_healthy: e.info.force_healthy,
                max_fails: e.info.max_fails,
            })
            .collect::<Vec<_>>();
        self.hot_paths.store(Arc::new(hot_paths_vec));

        guard.entries = new_entries;
        guard.groups = groups;
        guard.failover_order = failover_order;

        Ok((added, removed, kept))
    }

    /// Try to acquire a connection from the pre-authenticated pool.
    ///
    /// Returns a [`PooledConn`] containing:
    /// - `stream`: the pooled `BackendStream` if one was available, or `None` if the pool was empty.
    /// - `traffic`: an `Arc` to the backend's counters, obtained in the **same** lock acquisition.
    ///
    /// Callers must not call `get_traffic_counters` separately; use the returned `Arc` directly.
    /// Returns `None` only if `index` is out of bounds (never happens in practice).
    pub fn get_pooled_connection(&self, index: usize) -> Option<PooledConn> {
        let hot_paths = self.hot_paths.load();
        hot_paths.get(index).map(|hp| PooledConn {
            stream: hp.pool_rx.try_recv().ok(),
            traffic: Arc::clone(&hp.traffic),
        })
    }

    /// Return a clone of the `Arc<TrafficCounters>` for the given backend index.
    ///
    /// Callers hold this `Arc` across the relay lifetime and update it directly
    /// without taking the pool lock again.
    pub fn get_traffic_counters(&self, index: usize) -> Option<Arc<TrafficCounters>> {
        let hot_paths = self.hot_paths.load();
        hot_paths.get(index).map(|hp| Arc::clone(&hp.traffic))
    }

    /// Get the info of all backends with their index, current health, and enabled state.
    /// Returns (index, BackendInfo, is_healthy, is_enabled) for each backend in priority order.
    pub async fn get_backends_in_order(&self) -> Vec<(usize, Arc<BackendInfo>, bool, bool)> {
        let guard = self.inner.read().await;
        guard
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let status = e.status.lock();
                (i, e.info.clone(), status.healthy, status.enabled)
            })
            .collect()
    }

    #[allow(dead_code)]
    pub async fn get_candidates(
        &self,
    ) -> (
        Vec<(usize, Arc<BackendInfo>)>,
        Vec<(usize, Arc<BackendInfo>)>,
    ) {
        let guard = self.cached.load();
        (guard.healthy.clone(), guard.unhealthy.clone())
    }

    /// Get the array index for a given route name to use in O(1) lookups.
    pub fn get_route_index(&self, route: &str) -> Option<usize> {
        self.route_map.get(route).copied()
    }

    /// Get a lock-free guard to cached candidates for a specific route index.
    /// Falls back to global candidates if no route index is provided.
    pub fn get_route_candidates(&self, route_idx: Option<usize>) -> Arc<CachedCandidates> {
        if let Some(idx) = route_idx {
            let caches = self.route_caches.load();
            if let Some(cached) = caches.get(idx) {
                return cached.clone();
            }
        }
        self.cached.load_full()
    }

    /// Mark a backend as healthy with measured latency.
    ///
    /// Lock-free: accesses status via the `hot_paths` ArcSwap, avoiding the async RwLock.
    pub fn mark_healthy(
        &self,
        index: usize,
        latency: Duration,
        handshake_latency: Option<Duration>,
    ) {
        let hot_paths = self.hot_paths.load();
        if let Some(hp) = hot_paths.get(index) {
            let mut status = hp.status.lock();
            let was_unhealthy = !status.healthy;
            status.healthy = true;
            status.last_check = Some(Instant::now());
            status.last_latency = Some(latency);
            if handshake_latency.is_some() {
                status.last_handshake_latency = handshake_latency;
            }
            status.consecutive_failures = 0;

            let result = HealthCheckResult {
                timestamp: Utc::now(),
                success: true,
                latency_ms: Some(latency.as_millis() as u64),
                handshake_latency_ms: handshake_latency.map(|d| d.as_millis() as u64),
                error: None,
            };
            push_history(&mut status.history, result);

            if was_unhealthy {
                tracing::info!(
                    backend = %hp.info_name,
                    latency_ms = latency.as_millis() as u64,
                    "backend recovered"
                );
            }
        }
    }

    /// Mark a backend as unhealthy with an error message.
    ///
    /// Lock-free: accesses status via the `hot_paths` ArcSwap, avoiding the async RwLock.
    pub fn mark_unhealthy(&self, index: usize, error: &str) {
        let hot_paths = self.hot_paths.load();
        if let Some(hp) = hot_paths.get(index) {
            if hp.force_healthy {
                return;
            }
            let mut status = hp.status.lock();
            let was_healthy = status.healthy;
            // status.healthy will be set to false only if max_fails is reached
            status.last_check = Some(Instant::now());
            status.consecutive_failures += 1;
            if status.consecutive_failures >= hp.max_fails {
                status.healthy = false;
            }

            let result = HealthCheckResult {
                timestamp: Utc::now(),
                success: false,
                latency_ms: None,
                handshake_latency_ms: None,
                error: Some(error.to_string()),
            };
            push_history(&mut status.history, result);

            if was_healthy && !status.healthy {
                tracing::warn!(
                    backend = %hp.info_name,
                    error = %error,
                    "backend became unhealthy"
                );
            }
        }
    }

    /// Dynamically enable or disable a backend by name.
    /// Returns `Ok(true)` if found, `Ok(false)` if not found.
    pub async fn set_backend_enabled(&self, name: &str, enabled: bool) -> anyhow::Result<bool> {
        let guard = self.inner.read().await;
        let mut found = false;
        let mut changed = false;
        for entry in &guard.entries {
            if entry.info.name == name {
                found = true;

                // Idempotent: skip if already in the desired state.
                let current = entry.status.lock().enabled;
                if current == enabled {
                    break;
                }

                // Set the flag via the watch channel
                let _ = entry.enabled_tx.send(enabled);

                // Update the status for the health/candidate selection
                let mut status = entry.status.lock();
                status.enabled = enabled;

                if !enabled {
                    // Drain the connection pool immediately from the control thread.
                    // This instantly unblocks any blocking `tx.send_async` in the refill task.
                    while entry.pool_rx.try_recv().is_ok() {}
                }

                changed = true;
                break;
            }
        }

        if changed {
            drop(guard);
            self.recalculate_candidates().await;
        }

        Ok(found)
    }

    /// Recalculate candidates and cache them.
    pub async fn recalculate_candidates(&self) {
        let guard = self.inner.read().await;
        let (ch, cu) = calculate_candidates(&guard.entries, &guard.groups, &guard.failover_order);
        self.cached.store(Arc::new(CachedCandidates {
            strategy: crate::config::GroupStrategy::Failover,
            hash_ring: Vec::new(),
            wrr_choices: Vec::new(),
            healthy: ch,
            unhealthy: cu,
        }));

        let old_route_caches = self.route_caches.load();
        let mut new_route_caches = vec![
            Arc::new(CachedCandidates {
                strategy: crate::config::GroupStrategy::Failover,
                hash_ring: Vec::new(),
                wrr_choices: Vec::new(),
                healthy: vec![],
                unhealthy: vec![]
            });
            self.route_map.len()
        ];
        for (name, &idx) in self.route_map.iter() {
            let (strategy, gh, gu) =
                calculate_route_candidates(name, &guard.entries, &guard.groups);

            let hash_ring = if strategy == crate::config::GroupStrategy::ConsistentHashing {
                let old_cache = old_route_caches.get(idx);
                let same_healthy = old_cache.map_or(false, |old| {
                    old.healthy.len() == gh.len()
                        && old.healthy.iter().zip(gh.iter()).all(|(a, b)| a.0 == b.0)
                });
                if same_healthy {
                    old_cache.unwrap().hash_ring.clone()
                } else {
                    build_hash_ring(&gh)
                }
            } else {
                Vec::new()
            };

            new_route_caches[idx] = Arc::new(CachedCandidates {
                strategy,
                hash_ring,
                wrr_choices: crate::scheduler::build_wrr_choices(&gh, &guard.entries),
                healthy: gh,
                unhealthy: gu,
            });
        }
        self.route_caches.store(Arc::new(new_route_caches));
    }

    /// Get status views for the web dashboard.
    pub async fn status_views(&self) -> Vec<BackendStatusView> {
        let guard = self.inner.read().await;
        let mut views = Vec::with_capacity(guard.entries.len());
        for (i, e) in guard.entries.iter().enumerate() {
            // Find the most immediate group containing this backend
            let group_name = guard
                .groups
                .iter()
                .find(|g| {
                    g.members
                        .iter()
                        .any(|m| matches!(m, GroupMember::Backend(idx) if *idx == i))
                })
                .map(|g| g.name.clone());

            let status = e.status.lock();
            let handshake_latency_ms = status.last_handshake_latency.map(|d| d.as_millis() as u64);

            views.push(BackendStatusView {
                name: e.info.name.clone(),
                address: e.info.endpoint.display(),
                healthy: status.healthy,
                enabled: status.enabled,
                last_latency_ms: status.last_latency.map(|d| d.as_millis() as u64),
                consecutive_failures: status.consecutive_failures,
                history: status.history.iter().cloned().collect(),
                bytes_up: e.traffic.bytes_up.load(Ordering::Relaxed),
                bytes_down: e.traffic.bytes_down.load(Ordering::Relaxed),
                active_connections: e.traffic.active_connections.load(Ordering::Relaxed),
                total_connections: e.traffic.total_connections.load(Ordering::Relaxed),
                pool_hits: e.traffic.pool_hits.load(Ordering::Relaxed),
                pool_misses: e.traffic.pool_misses.load(Ordering::Relaxed),
                pool_stale: e.traffic.pool_stale.load(Ordering::Relaxed),
                handshake_latency_ms,
                group: group_name,
            });
        }
        views
    }

    /// Get hierarchical status tree of backends for the web dashboard.
    pub async fn status_tree(&self) -> Vec<TreeItem> {
        let guard = self.inner.read().await;
        let mut tree = Vec::with_capacity(guard.failover_order.len());

        let mut views = Vec::with_capacity(guard.entries.len());
        for (i, e) in guard.entries.iter().enumerate() {
            let group_name = guard
                .groups
                .iter()
                .find(|g| {
                    g.members
                        .iter()
                        .any(|m| matches!(m, GroupMember::Backend(idx) if *idx == i))
                })
                .map(|g| g.name.clone());

            let status = e.status.lock();
            let handshake_latency_ms = status.last_handshake_latency.map(|d| d.as_millis() as u64);

            views.push(BackendStatusView {
                name: e.info.name.clone(),
                address: e.info.endpoint.display(),
                healthy: status.healthy,
                enabled: status.enabled,
                last_latency_ms: status.last_latency.map(|d| d.as_millis() as u64),
                consecutive_failures: status.consecutive_failures,
                history: status.history.iter().cloned().collect(),
                bytes_up: e.traffic.bytes_up.load(Ordering::Relaxed),
                bytes_down: e.traffic.bytes_down.load(Ordering::Relaxed),
                active_connections: e.traffic.active_connections.load(Ordering::Relaxed),
                total_connections: e.traffic.total_connections.load(Ordering::Relaxed),
                pool_hits: e.traffic.pool_hits.load(Ordering::Relaxed),
                pool_misses: e.traffic.pool_misses.load(Ordering::Relaxed),
                pool_stale: e.traffic.pool_stale.load(Ordering::Relaxed),
                handshake_latency_ms,
                group: group_name,
            });
        }

        fn build_tree_node(
            target: &Target,
            groups: &[Group],
            views: &[BackendStatusView],
        ) -> Option<TreeItem> {
            match target {
                Target::Backend(idx) => {
                    if let Some(status) = views.get(*idx) {
                        Some(TreeItem::Backend {
                            status: status.clone(),
                        })
                    } else {
                        None
                    }
                }
                Target::Group(g_idx) => {
                    if let Some(group) = groups.get(*g_idx) {
                        let mut members = Vec::new();
                        for member in &group.members {
                            let member_target = match member {
                                GroupMember::Backend(idx) => Target::Backend(*idx),
                                GroupMember::Group(idx) => Target::Group(*idx),
                            };
                            if let Some(node) = build_tree_node(&member_target, groups, views) {
                                members.push(node);
                            }
                        }
                        let strategy_str = match group.strategy {
                            crate::config::GroupStrategy::Failover => "failover",
                            crate::config::GroupStrategy::UrlTest => "urltest",
                            crate::config::GroupStrategy::LoadBalance => "loadbalance",
                            crate::config::GroupStrategy::ConsistentHashing => "consistent_hashing",
                            crate::config::GroupStrategy::WeightedRoundRobin => {
                                "weighted_round_robin"
                            }
                        }
                        .to_string();

                        Some(TreeItem::Group {
                            name: group.name.clone(),
                            strategy: strategy_str,
                            members,
                        })
                    } else {
                        None
                    }
                }
            }
        }

        for target in &guard.failover_order {
            if let Some(node) = build_tree_node(target, &guard.groups, &views) {
                tree.push(node);
            }
        }

        tree
    }
}

fn push_history(history: &mut VecDeque<HealthCheckResult>, result: HealthCheckResult) {
    if history.len() >= MAX_HISTORY {
        history.pop_front();
    }
    history.push_back(result);
}

/// Run the background candidate selector task.
///
/// Recalculates and updates the cached candidate list periodically (every 3 seconds)
/// so that dynamic load balancing states are kept up-to-date with minimal latency
/// and completely lock-free for the connection handling worker threads.
pub async fn run_candidate_selector(
    pool: BackendPool,
    cancel: tokio_util::sync::CancellationToken,
) {
    let interval = std::time::Duration::from_secs(1);
    let mut ticker = tokio::time::interval(interval);

    // Skip the immediate tick so we tick 1s later
    ticker.tick().await;

    tracing::info!("candidate selector worker started");

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                tracing::debug!("candidate selector cancelled");
                return;
            }
            _ = ticker.tick() => {
                pool.recalculate_candidates().await;
            }
        }
    }
}

/// Drain all pre-connected connections from the pool channel.
fn drain_pool(rx: &flume::Receiver<BackendStream>) {
    while rx.try_recv().is_ok() {}
}

/// Background task that keeps the connection pool filled for a backend.
///
/// **SOCKS5 backends**: performs TCP connect + auth handshake, storing an
/// already-authenticated stream.  `socks5h_connect_target` runs on the hot path.
///
/// **Shadowsocks backends**: performs only TCP connect (no AEAD handshake — the
/// target address is not known yet).  The raw `TcpStream` is stored; wrapping
/// with `ProxyClientStream` happens in `route_and_connect` when the target is
/// known.  This is the "handshake as early as possible" design: we spend the
/// TCP RTT in the background so the hot path only pays for the in-memory crypto
/// setup.
///
/// Exits cleanly when `cancel` is cancelled (backend removed during hot reload).
#[inline]
async fn allocate_backend_resource(info: &BackendInfo) -> std::io::Result<BackendStream> {
    let start = std::time::Instant::now();
    let connect = crate::outbound::connect_endpoint(info, Duration::from_secs(10)).await;
    let mut stream = match connect {
        Err(e) => return Err(e),
        Ok(stream) if info.is_shadowsocks() => stream,
        Ok(stream) => crate::outbound::socks5h_authenticate(stream, info).await?,
    };
    stream.base_latency = start.elapsed();

    #[cfg(target_os = "linux")]
    let mut stream = stream;

    #[cfg(target_os = "linux")]
    {
        if crate::relay::ZERO_COPY_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
            use crate::relay::AsRawStreamRef;
            if let Some(_) = stream.as_raw_stream_ref() {
                if let Some(pipes) = crate::relay::create_preallocated_pipes() {
                    stream.pipes = Some(pipes);
                }
            }
        }
    }

    Ok(stream)
}

async fn refill_pool_task(
    info: BackendInfo,
    mut enabled_signal: tokio::sync::watch::Receiver<bool>,
    tx: flume::Sender<BackendStream>,
    rx: flume::Receiver<BackendStream>,
    cancel: CancellationToken,
    mut rt_chg_signal: tokio::sync::watch::Receiver<u64>,
) {
    if info.is_direct() {
        return;
    }

    let mut join_set = tokio::task::JoinSet::new();
    let target = info.pool_size.max(1);
    let mut pending_stream: Option<BackendStream> = None;

    loop {
        // Maintain concurrent connection attempts
        while join_set.len() < target && pending_stream.is_none() && *enabled_signal.borrow() {
            let info = info.clone();
            join_set.spawn(async move {
                let res = allocate_backend_resource(&info).await;
                if res.is_err() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                res
            });
        }

        if !*enabled_signal.borrow() {
            drain_pool(&rx);
            join_set.abort_all();
            pending_stream = None;
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return,
                res = enabled_signal.changed() => if res.is_err() { return; },
                res = rt_chg_signal.changed() => if res.is_err() { return; },
            }
            continue;
        }

        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            res = enabled_signal.changed() => {
                if res.is_err() { return; }
            }
            res = rt_chg_signal.changed() => {
                if res.is_err() { return; }
                drain_pool(&rx);
                join_set.abort_all();
                pending_stream = None;
                tracing::info!(backend = %info.name, "connection pool drained due to route change");
            }
            res = async {
                if let Some(stream) = pending_stream.take() {
                    tx.send_async(stream).await.map_err(|e| e.into_inner())
                } else {
                    std::future::pending().await
                }
            } => {
                if res.is_err() { return; } // channel closed
                tracing::trace!(backend = %info.name, "pool refilled");
            }
            Some(res) = join_set.join_next(), if pending_stream.is_none() => {
                match res {
                    Ok(Ok(stream)) => {
                        pending_stream = Some(stream);
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(
                            backend = %info.name, error = %e,
                            "connect failed; retrying in 5s"
                        );
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GroupStrategy;

    fn make_cfg(addr: &str, name: &str) -> BackendConfig {
        BackendConfig {
            backend_type: "socks5".to_string(),
            address: Some(addr.to_string()),
            username: None,
            password: None,
            name: Some(name.to_string()),
            pool_size: 1,
            bind_interface: None,
            tls: None,
            enabled: None,
            force_healthy: false,
        }
    }

    fn new_test_pool(
        configs: &[BackendConfig],
        group_configs: &[GroupConfig],
        failover_order_cfg: Option<&Vec<String>>,
        global_bind_interface: Option<&str>,
    ) -> anyhow::Result<BackendPool> {
        let (_tx, rx) = tokio::sync::watch::channel(0u64);
        BackendPool::new(
            configs,
            group_configs,
            failover_order_cfg,
            global_bind_interface,
            rx,
            &crate::config::FilterConfig::default(),
            tokio::runtime::Handle::current(),
            std::collections::HashSet::new(),
        )
    }

    #[tokio::test]
    async fn test_urltest_and_failover_strategy() {
        let b1 = make_cfg("127.0.0.1:8081", "b1");
        let b2 = make_cfg("127.0.0.1:8082", "b2");
        let b3 = make_cfg("127.0.0.1:8083", "b3");

        // Group 1 uses urltest
        let g1 = GroupConfig {
            name: "group-urltest".to_string(),
            strategy: GroupStrategy::UrlTest,
            members: vec!["b1".to_string(), "b2".to_string()],
        };

        // Group 2 uses failover
        let g2 = GroupConfig {
            name: "group-failover".to_string(),
            strategy: GroupStrategy::Failover,
            members: vec!["b2".to_string(), "b3".to_string()],
        };

        let pool = new_test_pool(
            &[b1, b2, b3],
            &[g1, g2],
            Some(&vec![
                "group-urltest".to_string(),
                "group-failover".to_string(),
            ]),
            None,
        )
        .unwrap();

        // 1. Initially all backends are healthy by default on startup.
        let (healthy, unhealthy) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 3);
        assert!(unhealthy.is_empty());
        assert_eq!(healthy[0].1.name, "b1");
        assert_eq!(healthy[1].1.name, "b2");
        assert_eq!(healthy[2].1.name, "b3");

        // Explicitly mark b3 unhealthy to test both passes.
        pool.mark_unhealthy(2, "connection error");
        pool.recalculate_candidates().await;

        let (healthy, unhealthy) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        assert_eq!(unhealthy.len(), 1);
        assert_eq!(unhealthy[0].1.name, "b3");

        // 2. Mark b1 healthy with 50ms latency, and b2 healthy with 20ms latency.
        // Since group-urltest contains [b1, b2], and is urltest strategy,
        // it should select b2 first (20ms) then b1 (50ms).
        pool.mark_healthy(0, Duration::from_millis(50));
        pool.mark_healthy(1, Duration::from_millis(20));
        pool.recalculate_candidates().await;

        let (healthy, unhealthy) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].1.name, "b2"); // b2 first because lower latency!
        assert_eq!(healthy[1].1.name, "b1");

        // b3 is still unhealthy.
        assert_eq!(unhealthy.len(), 1);
        assert_eq!(unhealthy[0].1.name, "b3");

        // 3. Mark b3 healthy too. Group 2 uses failover strategy.
        // Let's test failover order with a different pool where group-failover is first.
        let pool_fo = new_test_pool(
            &[
                make_cfg("127.0.0.1:8081", "b1"),
                make_cfg("127.0.0.1:8082", "b2"),
            ],
            &[GroupConfig {
                name: "group-fo".to_string(),
                strategy: GroupStrategy::Failover,
                members: vec!["b2".to_string(), "b1".to_string()],
            }],
            Some(&vec!["group-fo".to_string()]),
            None,
        )
        .unwrap();

        pool_fo.mark_healthy(0, Duration::from_millis(10)); // b1: 10ms
        pool_fo.mark_healthy(1, Duration::from_millis(100)); // b2: 100ms
        pool_fo.recalculate_candidates().await;

        // Since strategy is failover, it should keep configured order [b2, b1] regardless of latency!
        let (healthy, _) = pool_fo.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].1.name, "b2");
        assert_eq!(healthy[1].1.name, "b1");
    }

    #[tokio::test]
    async fn test_loadbalance_strategy() {
        let b1 = make_cfg("127.0.0.1:8081", "b1");
        let b2 = make_cfg("127.0.0.1:8082", "b2");

        let g = GroupConfig {
            name: "group-lb".to_string(),
            strategy: GroupStrategy::LoadBalance,
            members: vec!["b1".to_string(), "b2".to_string()],
        };

        let pool =
            new_test_pool(&[b1, b2], &[g], Some(&vec!["group-lb".to_string()]), None).unwrap();

        // Simulate b1 has more historical connections (total_connections = 10) than b2 (total_connections = 5)
        {
            let guard = pool.inner.read().await;
            guard.entries[0]
                .traffic
                .total_connections
                .store(10, Ordering::Relaxed);
            guard.entries[1]
                .traffic
                .total_connections
                .store(5, Ordering::Relaxed);
        }

        // Recalculate candidates (which runs `calculate_candidates` and caches results)
        pool.recalculate_candidates().await;

        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        // b2 should be first because it has fewer historical connections (5 < 10)
        assert_eq!(healthy[0].1.name, "b2");
        assert_eq!(healthy[1].1.name, "b1");

        // Now simulate b2 also getting up to 10 connections, but b1 having fewer active connections
        {
            let guard = pool.inner.read().await;
            guard.entries[1]
                .traffic
                .total_connections
                .store(10, Ordering::Relaxed);
            // b1 active connections = 1, b2 active connections = 2
            guard.entries[0]
                .traffic
                .active_connections
                .store(1, Ordering::Relaxed);
            guard.entries[1]
                .traffic
                .active_connections
                .store(2, Ordering::Relaxed);
        }

        pool.recalculate_candidates().await;
        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        // b1 should be first because active connections 1 < 2 (since total_connections are equal)
        assert_eq!(healthy[0].1.name, "b1");
        assert_eq!(healthy[1].1.name, "b2");
    }

    #[tokio::test]
    async fn test_default_global_failover_order() {
        let b1 = make_cfg("127.0.0.1:8081", "b1");
        let b2 = make_cfg("127.0.0.1:8082", "b2");
        let b3 = make_cfg("127.0.0.1:8083", "b3");

        // g1 is loadbalance (dynamic)
        let g1 = GroupConfig {
            name: "g-lb".to_string(),
            strategy: GroupStrategy::LoadBalance,
            members: vec!["b1".to_string()],
        };

        // g2 is failover (static)
        let g2 = GroupConfig {
            name: "g-fo".to_string(),
            strategy: GroupStrategy::Failover,
            members: vec!["b2".to_string()],
        };

        // b3 is standalone (not in any group)

        // When we build the pool WITHOUT failover_order, the default failover order must be:
        // g-fo (Failover group) first, then g-lb (LoadBalance group) and b3 (standalone)
        let pool = new_test_pool(
            &[b1, b2, b3],
            &[g1, g2],
            None, // No explicit failover order
            None,
        )
        .unwrap();

        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 3);
        // Order of healthy backends should be: b2 (from g-fo), b1 (from g-lb), b3 (standalone)
        assert_eq!(healthy[0].1.name, "b2");
        assert_eq!(healthy[1].1.name, "b1");
        assert_eq!(healthy[2].1.name, "b3");
    }

    #[tokio::test]
    async fn test_reload_adds_backend_to_group() {
        let b1 = make_cfg("127.0.0.1:8081", "b1");
        let b2 = make_cfg("127.0.0.1:8082", "b2");

        let g1 = GroupConfig {
            name: "group-1".to_string(),
            strategy: GroupStrategy::Failover,
            members: vec!["b1".to_string()],
        };

        let pool = new_test_pool(
            &[b1.clone()],
            &[g1.clone()],
            Some(&vec!["group-1".to_string()]),
            None,
        )
        .unwrap();

        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].1.name, "b1");

        // Reload with b2 added and b2 added to group-1
        let g1_new = GroupConfig {
            name: "group-1".to_string(),
            strategy: GroupStrategy::Failover,
            members: vec!["b1".to_string(), "b2".to_string()],
        };

        let (added, removed, kept) = pool
            .reload(
                &[b1, b2],
                &[g1_new],
                Some(&vec!["group-1".to_string()]),
                None,
            )
            .await
            .unwrap();

        assert_eq!(added, 1);
        assert_eq!(removed, 0);
        assert_eq!(kept, 1);

        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].1.name, "b1");
        assert_eq!(healthy[1].1.name, "b2");
    }

    #[tokio::test]
    async fn test_reload_restarts_refill_task_on_config_change() {
        let b1 = make_cfg("127.0.0.1:8081", "b1");

        let pool = new_test_pool(&[b1.clone()], &[], None, None).unwrap();

        let original_cancel = {
            let guard = pool.inner.read().await;
            assert_eq!(guard.entries[0].info.pool_size, 1);
            assert_eq!(guard.entries[0].info.username, None);
            guard.entries[0].cancel.clone()
        };

        // Reload with b1 having updated pool_size and credentials
        let b1_updated = BackendConfig {
            backend_type: "socks5".to_string(),
            address: Some("127.0.0.1:8081".to_string()),
            username: Some("new-user".to_string()),
            password: Some("new-pass".to_string()),
            name: Some("b1".to_string()),
            pool_size: 3,
            bind_interface: None,
            tls: None,
            enabled: None,
            force_healthy: false,
        };

        let (added, removed, kept) = pool.reload(&[b1_updated], &[], None, None).await.unwrap();

        assert_eq!(added, 0);
        assert_eq!(removed, 0);
        assert_eq!(kept, 1);

        let guard = pool.inner.read().await;
        assert_eq!(guard.entries[0].info.pool_size, 3);
        assert_eq!(guard.entries[0].info.username.as_deref(), Some("new-user"));
        assert_eq!(guard.entries[0].info.password.as_deref(), Some("new-pass"));

        let new_cancel = guard.entries[0].cancel.clone();

        // Assert the old refill task cancellation token is cancelled
        assert!(original_cancel.is_cancelled());
        // Assert the new refill task cancellation token is NOT cancelled
        assert!(!new_cancel.is_cancelled());
    }

    #[tokio::test]
    async fn test_bind_interface_fallback() {
        let mut b1 = make_cfg("127.0.0.1:8081", "b1");
        b1.bind_interface = None;

        let mut b2 = make_cfg("127.0.0.1:8082", "b2");
        b2.bind_interface = Some("eno1".to_string());

        // Pool constructed with a global bind interface "eno0"
        let pool = new_test_pool(&[b1, b2], &[], None, Some("eno0")).unwrap();

        let guard = pool.inner.read().await;
        // b1 should resolve to the global bind interface "eno0"
        assert_eq!(
            guard.entries[0].info.bind_interface.as_deref(),
            Some("eno0")
        );
        // b2 should resolve to the backend-specific bind interface "eno1" (override)
        assert_eq!(
            guard.entries[1].info.bind_interface.as_deref(),
            Some("eno1")
        );
    }

    #[tokio::test]
    async fn test_dynamic_enable_disable() {
        let b1 = make_cfg("127.0.0.1:8081", "b1");
        let b2 = make_cfg("127.0.0.1:8082", "b2");

        let pool = new_test_pool(&[b1, b2], &[], None, None).unwrap();

        // 1. Initially, both should be enabled and in candidates list.
        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].1.name, "b1");
        assert_eq!(healthy[1].1.name, "b2");

        // 2. Disable b1
        let found = pool.set_backend_enabled("b1", false).await.unwrap();
        assert!(found);

        // b1 should be removed from candidates immediately.
        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].1.name, "b2");

        // 3. Enable b1 again
        let found = pool.set_backend_enabled("b1", true).await.unwrap();
        assert!(found);

        // b1 should return immediately.
        let (healthy, _) = pool.get_candidates().await;
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].1.name, "b1");
        assert_eq!(healthy[1].1.name, "b2");

        // 4. Try enabling/disabling a non-existent backend
        let found = pool
            .set_backend_enabled("nonexistent", false)
            .await
            .unwrap();
        assert!(!found);
    }

    #[test]
    fn test_uds_backend_endpoint_resolution() {
        // Test UDS resolution for socks5
        let cfg_s5 = BackendConfig {
            backend_type: "socks5".to_string(),
            address: Some("unix:///tmp/s5.sock".to_string()),
            username: None,
            password: None,
            name: None,
            pool_size: 1,
            bind_interface: None,
            tls: None,
            enabled: None,
            force_healthy: false,
        };
        let info = BackendInfo::from_config(&cfg_s5, 0, None).unwrap();
        match &info.endpoint {
            BackendEndpoint::Unix { path } => assert_eq!(path, "/tmp/s5.sock"),
            _ => panic!("Expected UDS endpoint"),
        }

        // Test UDS resolution for shadowsocks (ss)
        let cfg_ss = BackendConfig {
            backend_type: "ss".to_string(),
            address: Some("unix:///tmp/ss.sock".to_string()),
            username: Some("chacha20-ietf-poly1305".to_string()),
            password: Some("pass".to_string()),
            name: None,
            pool_size: 1,
            bind_interface: None,
            tls: None,
            enabled: None,
            force_healthy: false,
        };
        let info = BackendInfo::from_config(&cfg_ss, 0, None).unwrap();
        match &info.endpoint {
            BackendEndpoint::Unix { path } => assert_eq!(path, "/tmp/ss.sock"),
            _ => panic!("Expected UDS endpoint"),
        }

        // Test legacy uds type
        let cfg_legacy = BackendConfig {
            backend_type: "uds".to_string(),
            address: Some("/tmp/legacy.sock".to_string()),
            username: None,
            password: None,
            name: None,
            pool_size: 1,
            bind_interface: None,
            tls: None,
            enabled: None,
            force_healthy: false,
        };
        let info = BackendInfo::from_config(&cfg_legacy, 0, None).unwrap();
        match &info.endpoint {
            BackendEndpoint::Unix { path } => assert_eq!(path, "/tmp/legacy.sock"),
            _ => panic!("Expected UDS endpoint"),
        }

        // Test TCP resolution
        let cfg_tcp = BackendConfig {
            backend_type: "socks5".to_string(),
            address: Some("127.0.0.1:1080".to_string()),
            username: None,
            password: None,
            name: None,
            pool_size: 1,
            bind_interface: None,
            tls: None,
            enabled: None,
            force_healthy: false,
        };
        let info = BackendInfo::from_config(&cfg_tcp, 0, None).unwrap();
        match &info.endpoint {
            BackendEndpoint::Tcp { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(*port, 1080);
            }
            _ => panic!("Expected TCP endpoint"),
        }
    }
}
