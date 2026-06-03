//! Web status RESTful API for backend health monitoring.
//!
//! Provides JSON API endpoints for real-time status query and enabling/disabling backends.

use axum::{
    extract::State,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Serialize;
use memory_stats::memory_stats;
use tower_http::cors::{CorsLayer, Any};

use crate::backend::BackendPool;

/// Memory statistics.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct MemStats {
    pub rss: usize,
    pub vmsize: usize,
}

pub fn get_memory_usage() -> MemStats {
    if let Some(usage) = memory_stats() {
        MemStats { rss: usage.physical_mem, vmsize: usage.virtual_mem }
    } else {
        MemStats { rss: 0, vmsize: 0 }
    }
}

/// JSON API response.
#[derive(Serialize)]
struct ApiResponse {
    backends: Vec<crate::backend::BackendStatusView>,
    tree: Vec<crate::backend::TreeItem>,
    memory: MemStats,
    inbounds: Vec<crate::backend::InboundStatsView>,
}

/// Create the axum router.
pub fn create_router(pool: BackendPool) -> Router {
    use axum::routing::post;
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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
        "version": "1.2.0"
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
    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!(listen = %listen_addr, "web status REST API started");
    axum::serve(listener, app).await?;
    Ok(())
}

/// JSON API endpoint: GET /api/status
async fn api_status(State(pool): State<BackendPool>) -> Json<ApiResponse> {
    let backends = pool.status_views().await;
    let tree = pool.status_tree().await;
    let memory = get_memory_usage();
    let inbounds = pool.get_inbound_stats();
    Json(ApiResponse {
        backends,
        tree,
        memory,
        inbounds,
    })
}
