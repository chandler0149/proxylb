use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

use super::session::Session;

pub struct AnytlsManager {
    sessions: RwLock<Vec<Arc<Session>>>,
    rr_counter: AtomicUsize,
    pool_size: usize,
    password: String,
}

impl AnytlsManager {
    pub fn new(password: String, pool_size: usize) -> Self {
        Self {
            sessions: RwLock::new(Vec::with_capacity(pool_size)),
            rr_counter: AtomicUsize::new(0),
            pool_size: std::cmp::max(1, pool_size),
            password,
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub async fn add_session(&self, session: Arc<Session>) {
        let mut sessions = self.sessions.write().await;
        if sessions.len() < self.pool_size {
            sessions.push(session);
        }
    }

    pub async fn get_session(&self) -> Option<Arc<Session>> {
        let mut sessions = self.sessions.write().await;
        sessions.retain(|s| s.is_alive());

        if sessions.is_empty() || sessions.len() < self.pool_size {
            return None; // Force caller to establish a new TCP+TLS connection
        }

        // Round-robin load balance across the active distinct sessions
        let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % sessions.len();
        Some(sessions[idx].clone())
    }
}
