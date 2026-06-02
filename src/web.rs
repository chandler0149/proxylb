//! Web status dashboard for backend health monitoring.
//!
//! Provides both a JSON API endpoint and a self-contained HTML dashboard
//! that auto-refreshes to show real-time backend status and health check history.

use axum::{
    extract::State,
    http::header,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Serialize;

use crate::backend::BackendPool;

/// Memory statistics.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct MemoryStats {
    pub rss: u64,
    pub vmsize: u64,
}

#[cfg(target_os = "linux")]
pub fn get_memory_usage() -> MemoryStats {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let mut rss = 0;
    let mut vmsize = 0;

    if let Ok(file) = File::open("/proc/self/status") {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        rss = kb * 1024;
                    }
                }
            } else if line.starts_with("VmSize:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        vmsize = kb * 1024;
                    }
                }
            }
        }
    }

    MemoryStats { rss, vmsize }
}

#[cfg(not(target_os = "linux"))]
pub fn get_memory_usage() -> MemoryStats {
    MemoryStats { rss: 0, vmsize: 0 }
}

/// JSON API response.
#[derive(Serialize)]
struct ApiResponse {
    backends: Vec<crate::backend::BackendStatusView>,
    tree: Vec<crate::backend::TreeItem>,
    memory: MemoryStats,
    inbounds: Vec<crate::backend::InboundStatsView>,
}

/// Create the axum router.
pub fn create_router(pool: BackendPool) -> Router {
    use axum::routing::post;
    Router::new()
        .route("/", get(dashboard_html))
        .route("/api/status", get(api_status))
        .route("/api/backends/:name/enable", post(api_enable_backend))
        .route("/api/backends/:name/disable", post(api_disable_backend))
        .with_state(pool)
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
    tracing::info!(listen = %listen_addr, "web status dashboard started");
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

/// HTML dashboard: GET /
async fn dashboard_html(State(pool): State<BackendPool>) -> impl IntoResponse {
    let backends = pool.status_views().await;
    let tree = pool.status_tree().await;
    let memory = get_memory_usage();
    let inbounds = pool.get_inbound_stats();
    let backends_json = serde_json::to_string(&backends).unwrap_or_else(|_| "[]".to_string());
    let tree_json = serde_json::to_string(&tree).unwrap_or_else(|_| "[]".to_string());
    let memory_json = serde_json::to_string(&memory).unwrap_or_else(|_| "{}".to_string());
    let inbounds_json = serde_json::to_string(&inbounds).unwrap_or_else(|_| "[]".to_string());

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProxyLB — Web Dashboard</title>
    <style>
        :root {{
            --bg-primary: #060613;
            --bg-secondary: #0c0c24;
            --bg-card: rgba(22, 22, 59, 0.45);
            --bg-card-hover: rgba(33, 33, 85, 0.6);
            --text-primary: #f0f0f8;
            --text-secondary: #9da4cf;
            --accent-green: #00e676;
            --accent-red: #ff3d71;
            --accent-yellow: #ffc107;
            --accent-blue: #00b0ff;
            --border-subtle: rgba(255, 255, 255, 0.08);
            --shadow-glow: 0 12px 40px 0 rgba(0, 0, 0, 0.5);
            --font-main: 'Outfit', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        .inbounds-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 1.5rem;
        }}

        .inbound-card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-glow);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}

        .inbound-card:hover {{
            transform: translateY(-4px);
            border-color: rgba(0, 176, 255, 0.3);
            box-shadow: 0 16px 48px 0 rgba(0, 176, 255, 0.15);
        }}

        .inbound-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .inbound-badge {{
            font-size: 0.75rem;
            font-family: var(--font-mono);
            text-transform: uppercase;
            padding: 3px 10px;
            border-radius: 12px;
            font-weight: 700;
        }}

        .inbound-badge.socks5 {{
            background: rgba(0, 176, 255, 0.1);
            color: var(--accent-blue);
            border: 1px solid rgba(0, 176, 255, 0.2);
        }}

        .inbound-badge.socks5-uds {{
            background: rgba(233, 30, 99, 0.1);
            color: #e91e63;
            border: 1px solid rgba(233, 30, 99, 0.2);
        }}

        .inbound-badge.shadowsocks {{
            background: rgba(163, 112, 247, 0.1);
            color: #a370f7;
            border: 1px solid rgba(163, 112, 247, 0.2);
        }}

        .inbound-badge.http {{
            background: rgba(0, 230, 118, 0.1);
            color: var(--accent-green);
            border: 1px solid rgba(0, 230, 118, 0.2);
        }}

        .inbound-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .inbound-address {{
            font-family: var(--font-mono);
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        .inbound-stats-list {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            border-top: 1px solid var(--border-subtle);
            padding-top: 12px;
        }}

        .inbound-stat-item {{
            display: flex;
            flex-direction: column;
            gap: 2px;
        }}

        .inbound-stat-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .inbound-stat-value {{
            font-size: 0.95rem;
            font-weight: 600;
            font-family: var(--font-mono);
            color: var(--text-primary);
        }}

        body {{
            font-family: var(--font-main);
            background: radial-gradient(circle at 50% 0%, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2.5rem 2rem;
            overflow-x: hidden;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }}

        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 1.5rem;
        }}

        .header-title-area h1 {{
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a370f7 0%, var(--accent-blue) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .header-title-area .subtitle {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 4px;
            font-weight: 400;
        }}

        .header-meta {{
            text-align: right;
        }}

        .refresh-badge {{
            background: rgba(0, 176, 255, 0.1);
            color: var(--accent-blue);
            border: 1px solid rgba(0, 176, 255, 0.25);
            padding: 6px 16px;
            border-radius: 30px;
            font-size: 0.8rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}

        .refresh-dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--accent-blue);
            animation: pulse 1.5s infinite;
        }}

        /* Global Summary Panel */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
        }}

        .summary-card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-glow);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            overflow: hidden;
        }}

        .summary-card:hover {{
            transform: translateY(-4px);
            border-color: rgba(163, 112, 247, 0.3);
            box-shadow: 0 16px 48px 0 rgba(163, 112, 247, 0.15);
        }}

        .summary-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, transparent, rgba(163, 112, 247, 0.5), transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }}

        .summary-card:hover::before {{
            opacity: 1;
        }}

        .summary-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}

        .summary-card-title {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 600;
        }}

        .summary-card-icon {{
            font-size: 1.25rem;
            opacity: 0.8;
        }}

        .summary-card-value {{
            font-size: 1.8rem;
            font-weight: 700;
            font-family: var(--font-mono);
            line-height: 1.2;
            margin-bottom: 0.5rem;
        }}

        .summary-card-subtext {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        /* Specific Summary Card Customizations */
        .summary-card.health .beacon-container {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .summary-card.health .beacon {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            position: relative;
        }}

        .summary-card.health .beacon-pulse {{
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            animation: pulse-ring 1.8s cubic-bezier(0.215, 0.610, 0.355, 1) infinite;
        }}

        .beacon-green {{ background: var(--accent-green); }}
        .beacon-green .beacon-pulse {{ background: rgba(0, 230, 118, 0.4); }}
        .beacon-yellow {{ background: var(--accent-yellow); }}
        .beacon-yellow .beacon-pulse {{ background: rgba(255, 193, 7, 0.4); }}
        .beacon-red {{ background: var(--accent-red); }}
        .beacon-red .beacon-pulse {{ background: rgba(255, 61, 113, 0.4); }}

        /* Traffic Distribution Panel */
        .distribution-card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: var(--shadow-glow);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        .distribution-card:hover {{
            border-color: rgba(0, 176, 255, 0.2);
            box-shadow: 0 16px 48px 0 rgba(0, 176, 255, 0.08);
        }}

        .distribution-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }}

        .distribution-header h2 {{
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: -0.2px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .total-processed {{
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .total-processed strong {{
            color: var(--text-primary);
            font-family: var(--font-mono);
        }}

        /* Stacked segment bar */
        .stacked-bar-container {{
            height: 24px;
            width: 100%;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            display: flex;
            overflow: hidden;
            margin-bottom: 1.8rem;
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 2px;
        }}

        .stacked-segment {{
            height: 100%;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            cursor: pointer;
        }}

        .stacked-segment:hover {{
            filter: brightness(1.2);
            transform: scaleY(1.05);
            z-index: 10;
        }}

        .stacked-segment:first-child {{
            border-top-left-radius: 10px;
            border-bottom-left-radius: 10px;
        }}

        .stacked-segment:last-child {{
            border-top-right-radius: 10px;
            border-bottom-right-radius: 10px;
        }}

        .stacked-segment-tooltip {{
            position: absolute;
            bottom: 35px;
            left: 50%;
            transform: translateX(-50%) translateY(10px);
            background: #11112a;
            color: #fff;
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.75rem;
            white-space: nowrap;
            opacity: 0;
            pointer-events: none;
            transition: all 0.2s ease;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
            border: 1px solid var(--border-subtle);
            z-index: 100;
        }}

        .stacked-segment:hover .stacked-segment-tooltip {{
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }}

        /* Distribution breakdown items */
        .distribution-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1.5rem;
        }}

        .dist-item {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.04);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: 8px;
            transition: all 0.2s;
        }}

        .dist-item:hover {{
            background: rgba(255, 255, 255, 0.04);
            border-color: rgba(255, 255, 255, 0.08);
        }}

        .dist-item-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .dist-item-label {{
            font-size: 0.85rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .dist-color-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }}

        .dist-item-percentage {{
            font-family: var(--font-mono);
            font-weight: 700;
            font-size: 0.95rem;
        }}

        .dist-bar-bg {{
            height: 6px;
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 3px;
            overflow: hidden;
        }}

        .dist-bar-fill {{
            height: 100%;
            border-radius: 3px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        .dist-item-bytes {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            font-family: var(--font-mono);
            display: flex;
            justify-content: space-between;
        }}

        /* Backends Grid Section */
        .backends-title {{
            font-size: 1.25rem;
            font-weight: 700;
            margin-top: 1rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
            gap: 1.5rem;
        }}

        .card {{
            background: var(--bg-card);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-glow);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            flex-direction: column;
            gap: 1.2rem;
        }}

        .card:hover {{
            transform: translateY(-4px);
            border-color: rgba(0, 176, 255, 0.3);
            box-shadow: 0 16px 48px 0 rgba(0, 176, 255, 0.15);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}

        .card-name {{
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .card-address {{
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-family: var(--font-mono);
            margin-top: 2px;
        }}

        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 30px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .status-healthy {{
            background: rgba(0, 230, 118, 0.12);
            color: var(--accent-green);
            border: 1px solid rgba(0, 230, 118, 0.25);
        }}

        .status-unhealthy {{
            background: rgba(255, 61, 113, 0.12);
            color: var(--accent-red);
            border: 1px solid rgba(255, 61, 113, 0.25);
        }}

        .status-disabled {{
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-secondary);
            border: 1px solid rgba(255, 255, 255, 0.15);
        }}

        .card .status-dot {{
            width: 7px;
            height: 7px;
            border-radius: 50%;
        }}

        .status-healthy .status-dot {{
            background: var(--accent-green);
            box-shadow: 0 0 6px var(--accent-green);
        }}

        .status-unhealthy .status-dot {{
            background: var(--accent-red);
            box-shadow: 0 0 6px var(--accent-red);
        }}

        .status-disabled .status-dot {{
            background: var(--text-secondary);
            box-shadow: none;
        }}

        .metrics {{
            display: flex;
            gap: 1.5rem;
            padding: 0.8rem 1rem;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.04);
        }}

        .metric {{
            display: flex;
            flex-direction: column;
            flex: 1;
        }}

        .metric-label {{
            color: var(--text-secondary);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
            font-weight: 600;
        }}

        .metric-value {{
            font-size: 1.15rem;
            font-weight: 700;
            font-family: var(--font-mono);
        }}

        .traffic-row {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 0.8rem;
        }}

        .traffic-item {{
            display: flex;
            flex-direction: column;
            background: rgba(255, 255, 255, 0.015);
            border: 1px solid rgba(255, 255, 255, 0.03);
            border-radius: 10px;
            padding: 0.6rem 0.8rem;
        }}

        .traffic-label {{
            color: var(--text-secondary);
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
            font-weight: 600;
        }}

        .traffic-value {{
            font-size: 0.9rem;
            font-weight: 700;
            font-family: var(--font-mono);
            color: var(--text-primary);
        }}

        .traffic-value.upload {{ color: #ffa726; }}
        .traffic-value.download {{ color: var(--accent-green); }}
        .traffic-value.active {{ color: var(--accent-yellow); }}

        .pool-row {{
            display: flex;
            gap: 0.8rem;
            padding: 0.8rem;
            background: rgba(163, 112, 247, 0.05);
            border-radius: 12px;
            border: 1px solid rgba(163, 112, 247, 0.15);
        }}

        .pool-item {{
            display: flex;
            flex-direction: column;
            flex: 1;
        }}

        .pool-label {{
            color: var(--text-secondary);
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 2px;
            font-weight: 600;
        }}

        .pool-value {{
            font-size: 0.95rem;
            font-weight: 700;
            font-family: var(--font-mono);
        }}

        .pool-value.hit  {{ color: var(--accent-green); }}
        .pool-value.miss {{ color: var(--accent-blue); }}
        .pool-value.stale {{ color: var(--accent-red); }}

        .pool-hit-rate {{
            font-size: 0.68rem;
            color: var(--text-secondary);
            margin-top: 2px;
        }}

        .history-title {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }}

        .history-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
        }}

        .history-table th {{
            text-align: left;
            color: var(--text-secondary);
            font-weight: 600;
            padding: 6px 8px;
            border-bottom: 1px solid var(--border-subtle);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}

        .history-table td {{
            padding: 6px 8px;
            border-bottom: 1px solid var(--border-subtle);
            font-family: var(--font-mono);
            font-size: 0.75rem;
        }}

        .history-table tr:last-child td {{
            border-bottom: none;
        }}

        .history-success {{
            color: var(--accent-green);
            font-weight: 600;
        }}

        .history-fail {{
            color: var(--accent-red);
            font-weight: 600;
        }}

        .error-text {{
            color: var(--accent-red);
            font-size: 0.7rem;
            max-width: 160px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .empty-state {{
            text-align: center;
            color: var(--text-secondary);
            padding: 4rem;
            font-style: italic;
            background: var(--bg-card);
            border-radius: 16px;
            border: 1px solid var(--border-subtle);
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.4; }}
        }}

        @keyframes pulse-ring {{
            0% {{ transform: scale(0.33); opacity: 1; }}
            80%, 100% {{ transform: scale(2.2); opacity: 0; }}
        }}

        @media (max-width: 1000px) {{
            .header {{ flex-direction: column; align-items: flex-start; gap: 1rem; }}
            .header-meta {{ text-align: left; }}
        }}

        @media (max-width: 600px) {{
            body {{ padding: 1.5rem 1rem; }}
            .grid {{ grid-template-columns: 1fr; }}
            .traffic-row {{ grid-template-columns: repeat(2, 1fr); }}
        }}

        /* Tree layout styling */
        .tree-root {{
            display: flex;
            flex-direction: column;
            gap: 2.5rem;
            position: relative;
            padding-left: 1.8rem;
            margin-bottom: 3rem;
        }}

        .tree-root::before {{
            content: '';
            position: absolute;
            left: 0.2rem;
            top: 24px;
            bottom: 24px;
            width: 2px;
            background: linear-gradient(to bottom, var(--accent-blue), rgba(255, 255, 255, 0.05));
            border-radius: 1px;
        }}

        .tree-node-wrapper {{
            position: relative;
        }}

        .tree-node-wrapper::before {{
            content: '';
            position: absolute;
            left: -1.6rem;
            top: 24px;
            width: 1.6rem;
            height: 2px;
            background: var(--border-subtle);
        }}

        .tree-root > .tree-node-wrapper:first-child::before {{
            background: var(--accent-blue);
        }}

        .tree-group-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-glow);
            backdrop-filter: blur(12px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}

        .tree-group-card:hover {{
            border-color: rgba(0, 176, 255, 0.4);
            box-shadow: 0 0 30px rgba(0, 176, 255, 0.1);
        }}

        .tree-group-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-subtle);
            padding-bottom: 0.8rem;
        }}

        .tree-group-title {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }}

        .tree-group-strategy {{
            font-size: 0.8rem;
            font-family: var(--font-mono);
            text-transform: uppercase;
            background: rgba(0, 176, 255, 0.1);
            color: var(--accent-blue);
            border: 1px solid rgba(0, 176, 255, 0.2);
            padding: 3px 10px;
            border-radius: 12px;
        }}

        .tree-group-children {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
            gap: 1.5rem;
        }}

        @media (max-width: 900px) {{
            .tree-group-children {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-title-area">
                <h1>⚡ ProxyLB Dashboard</h1>
                <div class="subtitle">High-Performance SOCKS5 Proxy Load Balancer & Failover Status</div>
            </div>
            <div class="header-meta">
                <div class="refresh-badge">
                    <span class="refresh-dot"></span>
                    Auto-refreshing (5s)
                </div>
            </div>
        </div>

        <!-- Global Traffic Summary Panel -->
        <div class="summary-grid" id="summary-grid">
            <!-- Dynamic Global Stats will be injected here -->
        </div>

        <!-- Traffic Allocation Share -->
        <div class="distribution-card" id="distribution-card" style="display: none;">
            <div class="distribution-header">
                <h2>📊 Global Traffic Share</h2>
                <div class="total-processed">Total Processed: <span id="total-processed-val">0 B</span></div>
            </div>
            <div class="stacked-bar-container" id="stacked-bar">
                <!-- Stacked segmented bar -->
            </div>
            <div class="distribution-grid" id="distribution-grid">
                <!-- Distribution breakdown list -->
            </div>
        </div>

        <!-- Active Inbounds Statistics -->
        <div>
            <h2 class="backends-title">🔌 Active Inbound Listeners</h2>
            <div class="inbounds-grid" id="inbounds-grid" style="margin-top: 1.5rem;">
                <!-- Dynamic inbound listener cards will be injected here -->
            </div>
        </div>

        <!-- Hierarchical Routing Tree -->
        <div>
            <h2 class="backends-title">🌳 Routing Hierarchy (Global Failover Tree)</h2>
            <div class="tree-root" id="tree-root-container" style="margin-top: 1.5rem;"></div>
        </div>
    </div>

    <script>
        let backendsData = {backends_json};
        let treeData = {tree_json};
        let memoryData = {memory_json};
        let inboundsData = {inbounds_json};

        // Harmonious UI HSL colors for backends
        const palette = [
            'hsl(262, 85%, 68%)',  // Indigo/Purple
            'hsl(190, 90%, 50%)',  // Teal/Cyan
            'hsl(145, 80%, 45%)',  // Green
            'hsl(35, 95%, 55%)',   // Orange
            'hsl(330, 85%, 60%)',  // Pink/Rose
            'hsl(210, 95%, 55%)',  // Azure Blue
            'hsl(285, 80%, 58%)'   // Magenta
        ];

        function getBackendColor(index) {{
            return palette[index % palette.length];
        }}

        function formatTime(ts) {{
            const d = new Date(ts);
            return d.toLocaleTimeString();
        }}

        function formatBytes(n) {{
            if (n === 0) return '0 B';
            const units = ['B','KB','MB','GB','TB'];
            const i = Math.min(Math.floor(Math.log2(n) / 10), units.length - 1);
            const val = n / Math.pow(1024, i);
            return (i === 0 ? val : val.toFixed(2)) + ' ' + units[i];
        }}

        function poolStats(b) {{
            const total = b.pool_hits + b.pool_misses + b.pool_stale;
            const hitRate = total > 0 ? ((b.pool_hits / total) * 100).toFixed(1) + '% hit rate' : 'no requests yet';
            return `
                <div class="pool-item">
                    <span class="pool-label">Pool Hits</span>
                    <span class="pool-value hit">${{b.pool_hits}}</span>
                    <span class="pool-hit-rate">${{hitRate}}</span>
                </div>
                <div class="pool-item">
                    <span class="pool-label">Pool Misses</span>
                    <span class="pool-value miss">${{b.pool_misses}}</span>
                    <span class="pool-hit-rate">pool empty \u2192 fresh</span>
                </div>
                <div class="pool-item">
                    <span class="pool-label">Stale Evicted</span>
                    <span class="pool-value stale">${{b.pool_stale}}</span>
                    <span class="pool-hit-rate">dead \u2192 replaced</span>
                </div>`;
        }}

        function renderSummary(backends, memory) {{
            const summaryGrid = document.getElementById('summary-grid');
            if (!backends || backends.length === 0) {{
                summaryGrid.innerHTML = '';
                return;
            }}

            let totalBytesUp = 0;
            let totalBytesDown = 0;
            let totalActiveConns = 0;
            let totalConns = 0;
            let totalPoolHits = 0;
            let totalPoolMisses = 0;
            let totalPoolStale = 0;
            let healthyCount = 0;

            backends.forEach(b => {{
                totalBytesUp += b.bytes_up;
                totalBytesDown += b.bytes_down;
                totalActiveConns += Math.max(0, b.active_connections);
                totalConns += b.total_connections;
                totalPoolHits += b.pool_hits;
                totalPoolMisses += b.pool_misses;
                totalPoolStale += b.pool_stale;
                if (b.healthy) healthyCount++;
            }});

            const totalBytes = totalBytesUp + totalBytesDown;
            const totalPoolRequests = totalPoolHits + totalPoolMisses + totalPoolStale;
            const globalHitRate = totalPoolRequests > 0 ? ((totalPoolHits / totalPoolRequests) * 100) : 0;

            // Health status class and beacon color
            let healthStatusClass = 'beacon-red';
            let healthText = 'All Unhealthy';
            if (healthyCount === backends.length) {{
                healthStatusClass = 'beacon-green';
                healthText = 'All Backends Healthy';
            }} else if (healthyCount > 0) {{
                healthStatusClass = 'beacon-yellow';
                healthText = `${{healthyCount}} / ${{backends.length}} Healthy`;
            }}

            summaryGrid.innerHTML = `
                <!-- Health Card -->
                <div class="summary-card health">
                    <div class="summary-card-header">
                        <span class="summary-card-title">System Status</span>
                        <div class="beacon-container">
                            <span class="summary-card-subtext">${{healthText}}</span>
                            <div class="beacon ${{healthStatusClass}}">
                                <span class="beacon-pulse"></span>
                            </div>
                        </div>
                    </div>
                    <div class="summary-card-value">${{healthyCount}} / ${{backends.length}}</div>
                    <div class="summary-card-subtext">Active load balancer nodes</div>
                </div>

                <!-- Traffic Card -->
                <div class="summary-card">
                    <div class="summary-card-header">
                        <span class="summary-card-title">Total Bandwidth</span>
                        <span class="summary-card-icon">⚡</span>
                    </div>
                    <div class="summary-card-value" style="font-size: 1.6rem; margin-bottom: 0.7rem;">${{formatBytes(totalBytes)}}</div>
                    <div class="summary-card-subtext" style="gap: 12px;">
                        <span style="color: #ffa726;">▲ ${{formatBytes(totalBytesUp)}}</span>
                        <span style="color: var(--accent-green);">▼ ${{formatBytes(totalBytesDown)}}</span>
                    </div>
                </div>

                <!-- Connections Card -->
                <div class="summary-card">
                    <div class="summary-card-header">
                        <span class="summary-card-title">Active Connections</span>
                        <span class="summary-card-icon">🔌</span>
                    </div>
                    <div class="summary-card-value">${{totalActiveConns}}</div>
                    <div class="summary-card-subtext">Historical total: ${{totalConns}}</div>
                </div>

                <!-- Pool Performance Card -->
                <div class="summary-card">
                    <div class="summary-card-header">
                        <span class="summary-card-title">Global Pool Hit Rate</span>
                        <span class="summary-card-icon">💾</span>
                    </div>
                    <div class="summary-card-value">${{globalHitRate.toFixed(1)}}%</div>
                    <div class="summary-card-subtext">
                        Hits: ${{totalPoolHits}} / Misses: ${{totalPoolMisses}}
                    </div>
                </div>
            `;

            const memoryHtml = (memory && memory.rss > 0) ? `
                <!-- Memory Footprint Card -->
                <div class="summary-card">
                    <div class="summary-card-header">
                        <span class="summary-card-title">Memory Footprint</span>
                        <span class="summary-card-icon">🧠</span>
                    </div>
                    <div class="summary-card-value">${{formatBytes(memory.rss)}}</div>
                    <div class="summary-card-subtext">
                        Virtual Size: ${{formatBytes(memory.vmsize)}}
                    </div>
                </div>` : `
                <!-- Memory Footprint Card -->
                <div class="summary-card">
                    <div class="summary-card-header">
                        <span class="summary-card-title">Memory Footprint</span>
                        <span class="summary-card-icon">🧠</span>
                    </div>
                    <div class="summary-card-value">N/A</div>
                    <div class="summary-card-subtext">
                        Only available on Linux
                    </div>
                </div>`;

            summaryGrid.innerHTML += memoryHtml;

            // Render Traffic Allocation Share
            const distCard = document.getElementById('distribution-card');
            if (backends.length > 0) {{
                distCard.style.display = 'block';
                document.getElementById('total-processed-val').innerText = formatBytes(totalBytes);

                const stackedBar = document.getElementById('stacked-bar');
                const distGrid = document.getElementById('distribution-grid');

                // Clear
                stackedBar.innerHTML = '';
                distGrid.innerHTML = '';

                backends.forEach((b, i) => {{
                    const backendBytes = b.bytes_up + b.bytes_down;
                    const pct = totalBytes > 0 ? ((backendBytes / totalBytes) * 100) : 0;
                    const color = getBackendColor(i);

                    // Add to stacked bar if pct > 0 (or default state)
                    if (totalBytes > 0 && pct > 0) {{
                        const segment = document.createElement('div');
                        segment.className = 'stacked-segment';
                        segment.style.width = `${{pct}}%`;
                        segment.style.backgroundColor = color;
                        const tooltip = document.createElement('span');
                        tooltip.className = 'stacked-segment-tooltip';
                        tooltip.innerHTML = `<strong>${{b.name}}${{b.group ? ' (' + b.group + ')' : ''}}</strong>: ${{pct.toFixed(1)}}% (${{formatBytes(backendBytes)}})`;
                        segment.appendChild(tooltip);

                        stackedBar.appendChild(segment);
                    }}

                    // Add to breakdown grid
                    const distItem = document.createElement('div');
                    distItem.className = 'dist-item';
                    distItem.innerHTML = `
                        <div class="dist-item-header">
                            <span class="dist-item-label">
                                <span class="dist-color-dot" style="background-color: ${{color}}"></span>
                                ${{b.name}}${{b.group ? ' (' + b.group + ')' : ''}}
                            </span>
                            <span class="dist-item-percentage">${{pct.toFixed(1)}}%</span>
                        </div>
                        <div class="dist-bar-bg">
                            <div class="dist-bar-fill" style="width: ${{pct}}%; background-color: ${{color}}"></div>
                        </div>
                        <div class="dist-item-bytes">
                            <span>Upload: ${{formatBytes(b.bytes_up)}}</span>
                            <span>Download: ${{formatBytes(b.bytes_down)}}</span>
                        </div>
                    `;
                    distGrid.appendChild(distItem);
                }});

                // If total processed is 0, add empty placeholder segment in stacked bar
                if (totalBytes === 0) {{
                    stackedBar.innerHTML = `
                        <div class="stacked-segment" style="width: 100%; background-color: rgba(255,255,255,0.05); cursor: default;">
                            <span class="stacked-segment-tooltip">No traffic processed yet</span>
                        </div>
                    `;
                }}
            }} else {{
                distCard.style.display = 'none';
            }}
        }}

        function renderBackendCard(b) {{
            const hitRate = (b.pool_hits + b.pool_misses + b.pool_stale) > 0 
                ? ((b.pool_hits / (b.pool_hits + b.pool_misses + b.pool_stale)) * 100).toFixed(1) + '% hit rate' 
                : 'no requests yet';

            const poolStatsHtml = `
                <div class="pool-item">
                    <span class="pool-label">Pool Hits</span>
                    <span class="pool-value hit">${{b.pool_hits}}</span>
                    <span class="pool-hit-rate">${{hitRate}}</span>
                </div>
                <div class="pool-item">
                    <span class="pool-label">Pool Misses</span>
                    <span class="pool-value miss">${{b.pool_misses}}</span>
                    <span class="pool-hit-rate">pool empty \u2192 fresh</span>
                </div>
                <div class="pool-item">
                    <span class="pool-label">Stale Evicted</span>
                    <span class="pool-value stale">${{b.pool_stale}}</span>
                    <span class="pool-hit-rate">dead \u2192 replaced</span>
                </div>`;

            return `
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-name">
                                ${{b.name}}
                                ${{b.group ? '<span style="font-size: 0.8rem; font-weight: normal; opacity: 0.65; margin-left: 8px; padding: 2px 8px; background: rgba(255,255,255,0.06); border-radius: 8px; border: 1px solid var(--border-subtle)">' + b.group + '</span>' : ''}}
                            </div>
                            <div class="card-address">${{b.address}}</div>
                        </div>
                        <span class="status-badge ${{!b.enabled ? 'status-disabled' : (b.healthy ? 'status-healthy' : 'status-unhealthy')}}">
                            <span class="status-dot"></span>
                            ${{!b.enabled ? 'Disabled' : (b.healthy ? 'Healthy' : 'Unhealthy')}}
                        </span>
                    </div>
                    <div class="metrics">
                        <div class="metric">
                            <span class="metric-label">Latency</span>
                            <span class="metric-value">${{b.last_latency_ms != null ? b.last_latency_ms + ' ms' : '\u2014'}}</span>
                        </div>
                        <div class="metric">
                            <span class="metric-label">Failures</span>
                            <span class="metric-value" style="color: ${{b.consecutive_failures > 0 ? 'var(--accent-red)' : 'var(--accent-green)'}}">${{b.consecutive_failures}}</span>
                        </div>
                    </div>
                    <div class="traffic-row">
                        <div class="traffic-item">
                            <span class="traffic-label">Upload</span>
                            <span class="traffic-value upload">${{formatBytes(b.bytes_up)}}</span>
                        </div>
                        <div class="traffic-item">
                            <span class="traffic-label">Download</span>
                            <span class="traffic-value download">${{formatBytes(b.bytes_down)}}</span>
                        </div>
                        <div class="traffic-item">
                            <span class="traffic-label">Active</span>
                            <span class="traffic-value active">${{Math.max(0, b.active_connections)}}</span>
                        </div>
                        <div class="traffic-item">
                            <span class="traffic-label">History Conn</span>
                            <span class="traffic-value">${{b.total_connections}}</span>
                        </div>
                    </div>
                    <div class="pool-row">
                        ${{poolStatsHtml}}
                    </div>
                    <div>
                        <div class="history-title" style="margin-bottom: 0.5rem;">Recent Health Checks</div>
                        <table class="history-table">
                            <thead>
                                <tr><th>Time</th><th>Status</th><th>Latency</th><th>Error</th></tr>
                            </thead>
                            <tbody>
                                ${{b.history.slice().reverse().map(h => `
                                    <tr>
                                        <td>${{formatTime(h.timestamp)}}</td>
                                        <td class="${{h.success ? 'history-success' : 'history-fail'}}">${{h.success ? '\u2713 OK' : '\u2717 FAIL'}}</td>
                                        <td>${{h.latency_ms != null ? h.latency_ms + ' ms' : '\u2014'}}</td>
                                        <td class="error-text" title="${{h.error || ''}}">${{h.error || '\u2014'}}</td>
                                    </tr>
                                `).join('')}}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }}

        function renderInbounds(inbounds) {{
            const grid = document.getElementById('inbounds-grid');
            if (!inbounds || inbounds.length === 0) {{
                grid.innerHTML = '<div class="empty-state">No inbound listeners configured</div>';
                return;
            }}
            grid.innerHTML = inbounds.map(i => {{
                const badgeClass = i.inbound_type.toLowerCase();
                return `
                    <div class="inbound-card">
                        <div class="inbound-header">
                            <div class="inbound-title">\uD83D\uDD0C ${{i.name}}</div>
                            <span class="inbound-badge ${{badgeClass}}">${{i.inbound_type}}</span>
                        </div>
                        <div class="inbound-address">Listen: ${{i.listen}}</div>
                        <div class="inbound-stats-list">
                            <div class="inbound-stat-item">
                                <span class="inbound-stat-label">Active Conn</span>
                                <span class="inbound-stat-value" style="color: var(--accent-blue);">${{i.active_connections}}</span>
                            </div>
                            <div class="inbound-stat-item">
                                <span class="inbound-stat-label">Total Conn</span>
                                <span class="inbound-stat-value">${{i.total_connections}}</span>
                            </div>
                            <div class="inbound-stat-item" style="border-top: 1px solid rgba(255,255,255,0.03); padding-top: 8px;">
                                <span class="inbound-stat-label">Uploaded</span>
                                <span class="inbound-stat-value" style="color: #ffa726;">${{formatBytes(i.tx_bytes)}}</span>
                            </div>
                            <div class="inbound-stat-item" style="border-top: 1px solid rgba(255,255,255,0.03); padding-top: 8px;">
                                <span class="inbound-stat-label">Downloaded</span>
                                <span class="inbound-stat-value" style="color: var(--accent-green);">${{formatBytes(i.rx_bytes)}}</span>
                            </div>
                        </div>
                    </div>
                `;
            }}).join('');
        }}

        function render(backends, tree, memory, inbounds) {{
            renderSummary(backends, memory);
            renderInbounds(inbounds);

            const container = document.getElementById('tree-root-container');
            if (!tree || tree.length === 0) {{
                container.innerHTML = '<div class="empty-state">No routing hierarchy configured</div>';
                return;
            }}

            container.innerHTML = tree.map((item, index) => {{
                if (item.type === 'backend') {{
                    const b = item.status;
                    return `
                        <div class="tree-node-wrapper">
                            ${{renderBackendCard(b)}}
                        </div>
                    `;
                }} else if (item.type === 'group') {{
                    return `
                        <div class="tree-node-wrapper">
                            <div class="tree-group-card">
                                <div class="tree-group-header">
                                    <div class="tree-group-title">
                                        <span>📂 Group: ${{item.name}}</span>
                                    </div>
                                    <span class="tree-group-strategy">${{item.strategy}}</span>
                                </div>
                                <div class="tree-group-children">
                                    ${{item.backends.map(b => renderBackendCard(b)).join('')}}
                                </div>
                            </div>
                        </div>
                    `;
                }}
                return '';
            }}).join('');
        }}

        // Initial render
        render(backendsData, treeData, memoryData, inboundsData);

        // Auto-refresh every 5 seconds.
        setInterval(async () => {{
            try {{
                const resp = await fetch('/api/status');
                const data = await resp.json();
                backendsData = data.backends;
                treeData = data.tree;
                memoryData = data.memory;
                inboundsData = data.inbounds;
                render(backendsData, treeData, memoryData, inboundsData);
            }} catch(e) {{
                console.error('Refresh failed:', e);
            }}
        }}, 5000);
    </script>
</body>
</html>"##
    );

    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}
