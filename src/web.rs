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
        .route("/api/filter/rules", axum::routing::get(api_get_rules).post(api_add_rule).delete(api_delete_rule))
        .route("/api/filter/urls", axum::routing::get(api_get_urls).post(api_add_url).delete(api_delete_url))
        .route("/api/filter/settings", post(api_set_filter_settings))
        .route("/api/filter/check", axum::routing::get(api_check_rule))
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
    use crate::config::FilterConfig;
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
            &FilterConfig::default(),
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
            &FilterConfig::default(),
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

    let engine = pool.filter_manager.engine.load();
    let adblock = AdBlockStatusView {
        enabled: **pool.filter_manager.enabled.load(),
        block_rules_count: engine.block_rules_count,
        allow_rules_count: 0,
        blocked_requests: pool
            .filter_manager
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

#[derive(serde::Deserialize)]
pub struct RuleRequest {
    pub rule: String,
}

#[derive(serde::Deserialize)]
pub struct UrlRequest {
    pub url: String,
    #[serde(default)]
    pub tag: String,
}

#[derive(serde::Deserialize)]
pub struct FilterSettingsRequest {
    pub enabled: bool,
    pub block_private_addresses: bool,
}

async fn api_get_rules(State(pool): State<BackendPool>) -> impl IntoResponse {
    let rules = pool.filter_manager.get_rules();
    Json(rules)
}

async fn api_add_rule(State(pool): State<BackendPool>, Json(req): Json<RuleRequest>) -> impl IntoResponse {
    if pool.filter_manager.add_rule(&req.rule).await.is_ok() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn api_delete_rule(State(pool): State<BackendPool>, Json(req): Json<RuleRequest>) -> impl IntoResponse {
    if pool.filter_manager.delete_rule(&req.rule).await.is_ok() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn api_get_urls(State(pool): State<BackendPool>) -> impl IntoResponse {
    let mut urls = pool.filter_manager.get_urls();
    let cache = pool.filter_manager.cached_remote_contents.read().await;
    for u in &mut urls {
        if let Some(content) = cache.get(&u.url) {
            u.rule_count = content.lines().filter_map(crate::filter::parse_rule_line).count();
        }
    }
    Json(urls)
}

async fn api_add_url(State(pool): State<BackendPool>, Json(req): Json<UrlRequest>) -> impl IntoResponse {
    match crate::filter::download_url(&pool, pool.filter_manager.backend.as_deref(), &req.url).await {
        Ok(content) => {
            if pool.filter_manager.add_url(&req.url, &req.tag, content).await.is_ok() {
                axum::http::StatusCode::OK
            } else {
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            }
        }
        Err(e) => {
            tracing::error!(url = %req.url, error = %e, "failed to download filter list from web UI");
            axum::http::StatusCode::BAD_REQUEST
        }
    }
}

async fn api_delete_url(State(pool): State<BackendPool>, Json(req): Json<UrlRequest>) -> impl IntoResponse {
    if pool.filter_manager.delete_url(&req.url).await.is_ok() {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}

async fn api_set_filter_settings(State(pool): State<BackendPool>, Json(req): Json<FilterSettingsRequest>) -> impl IntoResponse {
    pool.filter_manager.set_enabled(req.enabled);
    pool.filter_manager.set_block_private(req.block_private_addresses);
    axum::http::StatusCode::OK
}

#[derive(serde::Deserialize)]
pub struct CheckRequest {
    pub target: String,
}

#[derive(serde::Serialize)]
pub struct CheckResponse {
    pub blocked: bool,
}

async fn api_check_rule(State(pool): State<BackendPool>, axum::extract::Query(req): axum::extract::Query<CheckRequest>) -> impl IntoResponse {
    let target_addr = if let Ok(ip) = req.target.parse::<std::net::IpAddr>() {
        crate::outbound::TargetAddr::Ip(std::net::SocketAddr::new(ip, 0))
    } else {
        crate::outbound::TargetAddr::Domain(req.target.clone(), 0)
    };
    let blocked = pool.filter_manager.is_blocked(&target_addr);
    Json(CheckResponse { blocked })
}
