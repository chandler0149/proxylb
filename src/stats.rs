use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum ClientId {
    Ip(std::net::IpAddr),
    Unix,
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientId::Ip(ip) => write!(f, "{}", ip),
            ClientId::Unix => write!(f, "unix"),
        }
    }
}

#[derive(Default)]
pub struct ClientStats {
    pub total_connections: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

#[derive(Serialize)]
pub struct ClientStatsView {
    pub ip: String,
    pub total_connections: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

#[derive(Clone)]
pub struct ClientStatsManager {
    map: Arc<DashMap<ClientId, Arc<ClientStats>>>,
}

impl ClientStatsManager {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    pub fn get_or_create(&self, id: &ClientId) -> Arc<ClientStats> {
        self.map
            .entry(id.clone())
            .or_insert_with(|| Arc::new(ClientStats::default()))
            .clone()
    }

    pub fn get_views(&self) -> Vec<ClientStatsView> {
        let mut views: Vec<_> = self
            .map
            .iter()
            .map(|entry| {
                let stats = entry.value();
                ClientStatsView {
                    ip: entry.key().to_string(),
                    total_connections: stats.total_connections.load(Ordering::Relaxed),
                    tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
                    rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
                }
            })
            .collect();
        // Sort by data usage (tx + rx) descending
        views.sort_unstable_by_key(|v| std::cmp::Reverse(v.tx_bytes + v.rx_bytes));
        views.truncate(100);
        views
    }
}

#[derive(Default)]
pub struct DomainStats {
    pub total_connections: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
}

#[derive(Serialize)]
pub struct DomainStatsView {
    pub domain: String,
    pub total_connections: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

use std::sync::atomic::AtomicBool;

#[derive(Clone)]
pub struct DomainStatsManager {
    map: Arc<DashMap<String, Arc<DomainStats>>>,
    is_pruning: Arc<AtomicBool>,
}

impl DomainStatsManager {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
            is_pruning: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn get_or_create(&self, domain: &str) -> Arc<DomainStats> {
        if let Some(stats) = self.map.get(domain) {
            return stats.clone();
        }

        // Amortize pruning to avoid iterating on every single insert once we hit 15.
        // If it grows to 30, we prune it back down to the top 15 to save memory.
        // Use an AtomicBool to prevent race conditions (multiple threads pruning at once).
        if self.map.len() >= 30 {
            if !self.is_pruning.swap(true, Ordering::Acquire) {
                self.prune_to(15);
                self.is_pruning.store(false, Ordering::Release);
            }
        }

        self.map
            .entry(domain.to_string())
            .or_insert_with(|| Arc::new(DomainStats::default()))
            .clone()
    }

    fn prune_to(&self, limit: usize) {
        if self.map.len() <= limit {
            return;
        }

        let mut entries: Vec<_> = self
            .map
            .iter()
            .map(|entry| {
                let stats = entry.value();
                let score = stats.tx_bytes.load(Ordering::Relaxed)
                    + stats.rx_bytes.load(Ordering::Relaxed)
                    + stats.total_connections.load(Ordering::Relaxed);
                (entry.key().clone(), score)
            })
            .collect();

        // Sort descending by score
        entries.sort_unstable_by_key(|(_, score)| std::cmp::Reverse(*score));

        // Remove elements that fall outside the top 'limit'
        for (domain, _) in entries.into_iter().skip(limit) {
            self.map.remove(&domain);
        }
    }

    pub fn increment_block(&self, domain: &str) {
        let stats = self.get_or_create(domain);
        stats.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_views(&self) -> Vec<DomainStatsView> {
        let mut views: Vec<_> = self
            .map
            .iter()
            .map(|entry| {
                let stats = entry.value();
                DomainStatsView {
                    domain: entry.key().clone(),
                    total_connections: stats.total_connections.load(Ordering::Relaxed),
                    tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
                    rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
                }
            })
            .collect();
        // Sort by data usage (tx + rx) or connection count descending
        views.sort_unstable_by_key(|v| {
            std::cmp::Reverse(v.tx_bytes + v.rx_bytes + v.total_connections)
        });
        views.truncate(15);
        views
    }
}
