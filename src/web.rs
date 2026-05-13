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

/// JSON API response.
#[derive(Serialize)]
struct ApiResponse {
    backends: Vec<crate::backend::BackendStatusView>,
}

/// Create the axum router.
pub fn create_router(pool: BackendPool) -> Router {
    Router::new()
        .route("/", get(dashboard_html))
        .route("/api/status", get(api_status))
        .with_state(pool)
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
    Json(ApiResponse { backends })
}

/// HTML dashboard: GET /
async fn dashboard_html(State(pool): State<BackendPool>) -> impl IntoResponse {
    let backends = pool.status_views().await;
    let backends_json = serde_json::to_string(&backends).unwrap_or_else(|_| "[]".to_string());

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ProxyLB — Backend Status</title>
    <style>
        :root {{
            --bg-primary: #0f0f23;
            --bg-secondary: #1a1a3e;
            --bg-card: #1e1e4a;
            --text-primary: #e0e0ff;
            --text-secondary: #a0a0cc;
            --accent-green: #00e676;
            --accent-red: #ff1744;
            --accent-yellow: #ffea00;
            --accent-blue: #448aff;
            --border-subtle: rgba(255, 255, 255, 0.06);
            --shadow-glow: 0 0 20px rgba(68, 138, 255, 0.15);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem;
        }}

        .header {{
            text-align: center;
            margin-bottom: 2.5rem;
        }}

        .header h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-blue), #7c4dff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.3rem;
        }}

        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}

        .refresh-info {{
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.75rem;
            margin-bottom: 1.5rem;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
            gap: 1.5rem;
            max-width: 1400px;
            margin: 0 auto;
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: var(--shadow-glow);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}

        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 0 30px rgba(68, 138, 255, 0.25);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}

        .card-name {{
            font-size: 1.1rem;
            font-weight: 600;
        }}

        .card-address {{
            color: var(--text-secondary);
            font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }}

        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .status-healthy {{
            background: rgba(0, 230, 118, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(0, 230, 118, 0.3);
        }}

        .status-unhealthy {{
            background: rgba(255, 23, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(255, 23, 68, 0.3);
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: pulse 2s ease-in-out infinite;
        }}

        .status-healthy .status-dot {{
            background: var(--accent-green);
            box-shadow: 0 0 6px var(--accent-green);
        }}

        .status-unhealthy .status-dot {{
            background: var(--accent-red);
            box-shadow: 0 0 6px var(--accent-red);
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}

        .metrics {{
            display: flex;
            gap: 1.5rem;
            margin-bottom: 1rem;
        }}

        .metric {{
            display: flex;
            flex-direction: column;
        }}

        .metric-label {{
            color: var(--text-secondary);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 2px;
        }}

        .metric-value {{
            font-size: 1.1rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }}

        .history-title {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.5rem;
        }}

        .history-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.78rem;
        }}

        .history-table th {{
            text-align: left;
            color: var(--text-secondary);
            font-weight: 500;
            padding: 4px 8px;
            border-bottom: 1px solid var(--border-subtle);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}

        .history-table td {{
            padding: 4px 8px;
            border-bottom: 1px solid var(--border-subtle);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
        }}

        .history-table tr:last-child td {{
            border-bottom: none;
        }}

        .history-success {{
            color: var(--accent-green);
        }}

        .history-fail {{
            color: var(--accent-red);
        }}

        .error-text {{
            color: var(--accent-red);
            font-size: 0.7rem;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .empty-state {{
            text-align: center;
            color: var(--text-secondary);
            padding: 3rem;
            font-style: italic;
        }}

        .traffic-row {{
            display: flex;
            gap: 1.5rem;
            margin-bottom: 1rem;
            padding: 0.75rem;
            background: rgba(255,255,255,0.04);
            border-radius: 8px;
            border: 1px solid var(--border-subtle);
        }}

        .traffic-item {{
            display: flex;
            flex-direction: column;
            flex: 1;
        }}

        .traffic-label {{
            color: var(--text-secondary);
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 2px;
        }}

        .traffic-value {{
            font-size: 0.95rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-blue);
        }}

        .traffic-value.upload {{ color: #ff9800; }}
        .traffic-value.download {{ color: var(--accent-green); }}
        .traffic-value.active {{ color: var(--accent-yellow); }}

        @media (max-width: 600px) {{
            body {{ padding: 1rem; }}
            .grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
</head>
<body>
    <div class="header">
        <h1>⚡ ProxyLB Status</h1>
        <div class="subtitle">SOCKS5 Proxy Load Balancer</div>
    </div>
    <div class="refresh-info">Auto-refreshes every 5 seconds</div>
    <div class="grid" id="grid"></div>

    <script>
        let backendsData = {backends_json};

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

        function render(backends) {{
            const grid = document.getElementById('grid');
            if (!backends || backends.length === 0) {{
                grid.innerHTML = '<div class="empty-state">No backends configured</div>';
                return;
            }}

            grid.innerHTML = backends.map(b => `
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-name">${{b.name}}</div>
                            <div class="card-address">${{b.address}}</div>
                        </div>
                        <span class="status-badge ${{b.healthy ? 'status-healthy' : 'status-unhealthy'}}">
                            <span class="status-dot"></span>
                            ${{b.healthy ? 'Healthy' : 'Unhealthy'}}
                        </span>
                    </div>
                    <div class="metrics">
                        <div class="metric">
                            <span class="metric-label">Latency</span>
                            <span class="metric-value">${{b.last_latency_ms != null ? b.last_latency_ms + ' ms' : '—'}}</span>
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
                    <div class="history-title">Recent Health Checks</div>
                    <table class="history-table">
                        <thead>
                            <tr><th>Time</th><th>Status</th><th>Latency</th><th>Error</th></tr>
                        </thead>
                        <tbody>
                            ${{b.history.slice().reverse().map(h => `
                                <tr>
                                    <td>${{formatTime(h.timestamp)}}</td>
                                    <td class="${{h.success ? 'history-success' : 'history-fail'}}">${{h.success ? '✓ OK' : '✗ FAIL'}}</td>
                                    <td>${{h.latency_ms != null ? h.latency_ms + ' ms' : '—'}}</td>
                                    <td class="error-text" title="${{h.error || ''}}">${{h.error || '—'}}</td>
                                </tr>
                            `).join('')}}
                        </tbody>
                    </table>
                </div>
            `).join('');
        }}

        render(backendsData);

        // Auto-refresh every 5 seconds.
        setInterval(async () => {{
            try {{
                const resp = await fetch('/api/status');
                const data = await resp.json();
                backendsData = data.backends;
                render(backendsData);
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
