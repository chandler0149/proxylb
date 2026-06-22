//! Web status RESTful API for backend health monitoring.
//!
//! Provides JSON API endpoints for real-time status query and enabling/disabling backends.

use axum::{
    Router,
    extract::State,
    response::{IntoResponse, Json},
    routing::get,
};
use memory_stats::memory_stats;
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};

use crate::backend::BackendPool;

/// Memory statistics.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct MemStats {
    pub rss: usize,
    pub vmsize: usize,
}

pub fn get_memory_usage() -> MemStats {
    if let Some(usage) = memory_stats() {
        MemStats {
            rss: usage.physical_mem,
            vmsize: usage.virtual_mem,
        }
    } else {
        MemStats { rss: 0, vmsize: 0 }
    }
}

#[derive(Serialize)]
struct AdBlockStatusView {
    enabled: bool,
    block_rules_count: usize,
    allow_rules_count: usize,
    blocked_requests: u64,
}

/// JSON API response.
#[derive(Serialize)]
struct ApiResponse {
    backends: Vec<crate::backend::BackendStatusView>,
    tree: Vec<crate::backend::TreeItem>,
    memory: MemStats,
    inbounds: Vec<crate::backend::InboundStatsView>,
    adblock: AdBlockStatusView,
}

/// Create the axum router.
pub fn create_router(pool: BackendPool) -> Router {
    use axum::routing::post;
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_private_network(true);

    Router::new()
        .route("/", get(api_info))
        .route("/api/status", get(api_status))
        .route("/api/backends/{name}/enable", post(api_enable_backend))
        .route("/api/backends/{name}/disable", post(api_disable_backend))
        .layer(cors)
        .with_state(pool)
}

/// GET /
async fn api_info() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "name": "ProxyLB API",
        "version": concat!(env!("CARGO_PKG_VERSION"), "-", env!("GIT_HASH"))
    }))
}

/// POST /api/backends/:name/enable
async fn api_enable_backend(
    State(pool): State<BackendPool>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    match pool.set_backend_enabled(&name, true).await {
        Ok(found) => {
            if found {
                axum::http::StatusCode::OK
            } else {
                axum::http::StatusCode::NOT_FOUND
            }
        }
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// POST /api/backends/:name/disable
async fn api_disable_backend(
    State(pool): State<BackendPool>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    match pool.set_backend_enabled(&name, false).await {
        Ok(found) => {
            if found {
                axum::http::StatusCode::OK
            } else {
                axum::http::StatusCode::NOT_FOUND
            }
        }
        Err(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Run the web status server.
pub async fn run_web_server(listen_addr: String, pool: BackendPool) -> anyhow::Result<()> {
    let app = create_router(pool);
    if listen_addr.starts_with("unix://") {
        let mut path = listen_addr.strip_prefix("unix://").unwrap().to_string();
        if !path.starts_with('/') {
            path = format!("/{}", path);
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = tokio::fs::remove_file(&path).await;
        let listener = tokio::net::UnixListener::bind(&path)?;
        tracing::info!(listen = %path, "web status REST API started (UDS)");
        axum::serve(listener, app).await?;
    } else if listen_addr.starts_with("unix:") {
        let mut path = listen_addr.strip_prefix("unix:").unwrap().to_string();
        if !path.starts_with('/') {
            path = format!("/{}", path);
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = tokio::fs::remove_file(&path).await;
        let listener = tokio::net::UnixListener::bind(&path)?;
        tracing::info!(listen = %path, "web status REST API started (UDS)");
        axum::serve(listener, app).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
        tracing::info!(listen = %listen_addr, "web status REST API started");
        axum::serve(listener, app).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendPool;
    use crate::config::AdBlockConfig;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_run_web_server_uds() {
        let (_tx, rx) = watch::channel(0u64);
        let pool = BackendPool::new(
            &[],
            &[],
            None,
            None,
            rx,
            &AdBlockConfig::default(),
            tokio::runtime::Handle::current(),
            std::collections::HashSet::new(),
        )
        .unwrap();

        let socket_path = "/tmp/test_api_web.sock";
        let listen_addr = format!("unix://{}", socket_path);

        // Spawn the server in the background
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let _ = run_web_server(listen_addr, pool_clone).await;
        });

        // Wait a bit for the server to start
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Verify socket file exists
        assert!(std::path::Path::new(socket_path).exists());

        // Cleanup
        handle.abort();
        let _ = tokio::fs::remove_file(socket_path).await;
    }

    #[tokio::test]
    async fn test_run_web_server_uds_relative() {
        let (_tx, rx) = watch::channel(0u64);
        let pool = BackendPool::new(
            &[],
            &[],
            None,
            None,
            rx,
            &AdBlockConfig::default(),
            tokio::runtime::Handle::current(),
            std::collections::HashSet::new(),
        )
        .unwrap();

        let listen_addr = "unix://tmp/proxylb_api.sock".to_string();

        // Spawn the server in the background
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let _ = run_web_server(listen_addr, pool_clone).await;
        });

        // Wait a bit for the server to start
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Verify socket file exists
        assert!(std::path::Path::new("/tmp/proxylb_api.sock").exists());

        // Cleanup
        handle.abort();
        let _ = tokio::fs::remove_file("/tmp/proxylb_api.sock").await;
    }
}

/// JSON API endpoint: GET /api/status
async fn api_status(State(pool): State<BackendPool>) -> Json<ApiResponse> {
    let backends = pool.status_views().await;
    let tree = pool.status_tree().await;
    let memory = get_memory_usage();
    let inbounds = pool.get_inbound_stats();

    let engine = pool.adblock_manager.engine.load();
    let adblock = AdBlockStatusView {
        enabled: **pool.adblock_manager.enabled.load(),
        block_rules_count: engine.block_rules_count,
        allow_rules_count: engine.allow_rules_count,
        blocked_requests: pool
            .adblock_manager
            .blocked_requests
            .load(std::sync::atomic::Ordering::Relaxed),
    };

    Json(ApiResponse {
        backends,
        tree,
        memory,
        inbounds,
        adblock,
    })
}
