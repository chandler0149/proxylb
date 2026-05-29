//! ProxyLB — A high-performance SOCKS5 proxy load balancer.
//!
//! Accepts SOCKS5 and Shadowsocks inbound connections, forwards them through
//! an ordered list of SOCKS5h backends with health checking and failover.

mod backend;
mod config;
mod health;
mod inbound;
mod outbound;
mod relay;
mod web;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// ProxyLB — SOCKS5 Proxy Load Balancer with Shadowsocks support.
#[derive(Parser, Debug)]
#[command(name = "proxylb", version, about)]
struct Args {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Log level (e.g. "info", "debug", "trace", "proxylb=debug").
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::time())
        .init();

    tracing::info!("ProxyLB starting...");

    // Load config.
    let config = config::Config::load(&args.config)?;
    tracing::info!(
        backends = config.backends.len(),
        "configuration loaded"
    );

    // Initialize backend pool.
    let pool = backend::BackendPool::new(&config.backends, &config.groups, config.failover_order.as_ref())?;

    // Spawn health checker and candidate selector background tasks with a shared cancellation token.
    let mut health_cancel = CancellationToken::new();
    {
        let health_pool = pool.clone();
        let health_config = config.health_check.clone();
        let token = health_cancel.clone();
        tokio::spawn(async move {
            health::run_health_checker(health_pool, health_config, token).await;
        });

        let selector_pool = pool.clone();
        let token = health_cancel.clone();
        tokio::spawn(async move {
            backend::run_candidate_selector(selector_pool, token).await;
        });
    }

    // Spawn web dashboard.
    if config.web.enabled {
        let web_pool = pool.clone();
        let web_listen = config.web.listen.clone();
        tokio::spawn(async move {
            if let Err(e) = web::run_web_server(web_listen, web_pool).await {
                tracing::error!(error = %e, "web server failed");
            }
        });
    }

    // Spawn inbound listeners.
    let mut handles = Vec::new();

    for inbound_item in config.all_inbounds() {
        let inbound_pool = pool.clone();
        match inbound_item {
            config::InboundItemConfig::Socks5 { listen, filter } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("SOCKS5 ({})", listen),
                    listen.clone(),
                    "socks5".to_string(),
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = inbound::socks5::run_socks5_inbound(listen, inbound_pool, stats, filter_enabled).await {
                        tracing::error!(error = %e, "SOCKS5 inbound failed");
                    }
                }));
            }
            config::InboundItemConfig::Shadowsocks { listen, password, method, filter } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("Shadowsocks ({})", listen),
                    listen.clone(),
                    "shadowsocks".to_string(),
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) =
                        inbound::shadowsocks::run_shadowsocks_inbound(listen, password, method, inbound_pool, stats, filter_enabled)
                            .await
                    {
                        tracing::error!(error = %e, "Shadowsocks inbound failed");
                    }
                }));
            }
            config::InboundItemConfig::Http { listen, filter } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("HTTP ({})", listen),
                    listen.clone(),
                    "http".to_string(),
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = inbound::http::run_http_inbound(listen, inbound_pool, stats, filter_enabled).await {
                        tracing::error!(error = %e, "HTTP inbound failed");
                    }
                }));
            }
        }
    }

    // Keep a snapshot of the initial inbound config to detect unsupported
    // listener-address changes on reload (those require a restart).
    let initial_inbounds = config.all_inbounds();

    tracing::info!("ProxyLB is running. Send SIGHUP to reload config, Ctrl+C to stop.");

    // Set up SIGHUP listener (Unix-only).
    let mut sighup =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    // Main event loop: wait for SIGHUP (reload) or SIGINT/Ctrl+C (shutdown).
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down...");
                break;
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP received — hot reload triggered");
                perform_hot_reload(
                    &args.config,
                    &pool,
                    &mut health_cancel,
                    &initial_inbounds,
                )
                .await;
            }
        }
    }

    // Abort all listener tasks.
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

/// Reload the config file and apply live changes to the running pool.
async fn perform_hot_reload(
    config_path: &PathBuf,
    pool: &backend::BackendPool,
    health_cancel: &mut CancellationToken,
    initial_inbounds: &[config::InboundItemConfig],
) {
    let new_config = match config::Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "hot reload failed: could not parse config file");
            return;
        }
    };

    // Warn about inbound listener changes that require a restart.
    warn_if_inbounds_changed(initial_inbounds, &new_config.all_inbounds());

    // Stop the health checker BEFORE swapping the pool so it cannot race
    // mark_healthy / mark_unhealthy against indices that are mid-rewrite.
    health_cancel.cancel();

    // Swap the backend pool.
    match pool.reload(&new_config.backends, &new_config.groups, new_config.failover_order.as_ref()).await {
        Ok((added, removed, kept)) => {
            tracing::info!(
                added,
                removed,
                kept,
                total = added + kept,
                "hot reload complete"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "hot reload failed: could not apply new backend config");
            // Even on failure the old checker is already gone — restart both tasks
            // the old pool state so health checking and candidate selection continue.
            *health_cancel = CancellationToken::new();
            let health_pool = pool.clone();
            let health_config = new_config.health_check.clone();
            let token = health_cancel.clone();
            tokio::spawn(async move {
                health::run_health_checker(health_pool, health_config, token).await;
            });
            let selector_pool = pool.clone();
            let token = health_cancel.clone();
            tokio::spawn(async move {
                backend::run_candidate_selector(selector_pool, token).await;
            });
            return;
        }
    }

    // Start a fresh health checker and candidate selector against the now-consistent pool.
    *health_cancel = CancellationToken::new();
    {
        let health_pool = pool.clone();
        let health_config = new_config.health_check.clone();
        let token = health_cancel.clone();
        tokio::spawn(async move {
            health::run_health_checker(health_pool, health_config, token).await;
        });

        let selector_pool = pool.clone();
        let token = health_cancel.clone();
        tokio::spawn(async move {
            backend::run_candidate_selector(selector_pool, token).await;
        });
    }
}

/// Emit warnings for inbound config changes that can't be applied without a restart.
fn warn_if_inbounds_changed(old: &[config::InboundItemConfig], new: &[config::InboundItemConfig]) {
    if old != new {
        tracing::warn!(
            "hot reload: inbound listener configuration changed \
             — restart required for this change to take effect"
        );
    }
}


