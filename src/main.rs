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
mod route_watcher;
mod adblock;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_appender::non_blocking::WorkerGuard;

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

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize async (non-blocking) tracing.
    // The worker guard MUST be kept alive for the entire lifetime of main();
    // dropping it early will shut down the background I/O thread and lose
    // buffered log lines.
    let _log_guard: WorkerGuard = init_tracing(&args.log_level);

    tracing::info!("ProxyLB starting...");

    // Load config.
    let config = config::Config::load(&args.config)?;
    tracing::info!(
        backends = config.backends.len(),
        "configuration loaded"
    );

    // Extract CPU affinity configuration.
    let mut worker_cores = None;
    let mut ancillary_cores = None;
    if let Some(ref affinity) = config.cpu_affinity {
        worker_cores = affinity.worker_cores.clone();
        ancillary_cores = affinity.ancillary_cores.clone();
    }

    // Builder for worker runtime.
    let mut worker_builder = tokio::runtime::Builder::new_multi_thread();
    worker_builder.enable_all();
    if let Some(ref cores) = worker_cores {
        if !cores.is_empty() {
            let next_core_idx = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let cores = cores.clone();
            worker_builder.on_thread_start(move || {
                let idx = next_core_idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(&core_num) = cores.get(idx % cores.len()) {
                    if let Some(core_ids) = core_affinity::get_core_ids() {
                        if let Some(core_id) = core_ids.into_iter().find(|c| c.id == core_num) {
                            if core_affinity::set_for_current(core_id) {
                                tracing::info!("Bound tokio worker thread to CPU core {}", core_num);
                            } else {
                                tracing::warn!("Failed to bind tokio worker thread to CPU core {}", core_num);
                            }
                        }
                    }
                }
            });
        }
    }
    let worker_runtime = worker_builder.build()?;
    let worker_handle = worker_runtime.handle().clone();

    // Builder for ancillary runtime.
    let mut ancillary_builder = tokio::runtime::Builder::new_multi_thread();
    ancillary_builder.enable_all();
    if let Some(ref cores) = ancillary_cores {
        if !cores.is_empty() {
            let next_core_idx = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let cores = cores.clone();
            ancillary_builder.on_thread_start(move || {
                let idx = next_core_idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(&core_num) = cores.get(idx % cores.len()) {
                    if let Some(core_ids) = core_affinity::get_core_ids() {
                        if let Some(core_id) = core_ids.into_iter().find(|c| c.id == core_num) {
                            if core_affinity::set_for_current(core_id) {
                                tracing::info!("Bound tokio ancillary thread to CPU core {}", core_num);
                            } else {
                                tracing::warn!("Failed to bind tokio ancillary thread to CPU core {}", core_num);
                            }
                        }
                    }
                }
            });
        }
    }
    let ancillary_runtime = ancillary_builder.build()?;
    let ancillary_handle = ancillary_runtime.handle().clone();

    worker_runtime.block_on(main_async(config, args, worker_handle, ancillary_handle))
}

async fn main_async(
    config: config::Config,
    args: Args,
    worker_handle: tokio::runtime::Handle,
    ancillary_handle: tokio::runtime::Handle,
) -> anyhow::Result<()> {
    // Initialize route change monitoring.
    let (route_tx, route_rx) = tokio::sync::watch::channel(0u64);
    route_watcher::start_route_watcher(&ancillary_handle, route_tx);

    // Initialize backend pool.
    let pool = backend::BackendPool::new(
        &config.backends,
        &config.groups,
        config.failover_order.as_ref(),
        config.bind_interface.as_deref(),
        route_rx.clone(),
        &config.adblock,
    )?;

    // Spawn adblock background manager task if enabled
    let mut adblock_cancel = CancellationToken::new();
    if config.adblock.enabled {
        adblock::start_adblock_manager(
            pool.adblock_manager.clone(),
            pool.clone(),
            config.adblock.clone(),
            adblock_cancel.clone(),
        ).await;
    }

    // Spawn health checker and candidate selector background tasks with a shared cancellation token.
    let mut health_cancel = CancellationToken::new();
    {
        let health_pool = pool.clone();
        let health_config = config.health_check.clone();
        let token = health_cancel.clone();
        let route_rx_clone = route_rx.clone();
        ancillary_handle.spawn(async move {
            health::run_health_checker(health_pool, health_config, token, route_rx_clone).await;
        });

        let selector_pool = pool.clone();
        let token = health_cancel.clone();
        ancillary_handle.spawn(async move {
            backend::run_candidate_selector(selector_pool, token).await;
        });
    }

    // Spawn web dashboard.
    if config.web.enabled {
        let web_pool = pool.clone();
        let web_listen = config.web.listen.clone();
        ancillary_handle.spawn(async move {
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
                handles.push(worker_handle.spawn(async move {
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
                handles.push(worker_handle.spawn(async move {
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
                handles.push(worker_handle.spawn(async move {
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
                    &mut adblock_cancel,
                    &initial_inbounds,
                    &ancillary_handle,
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
    adblock_cancel: &mut CancellationToken,
    initial_inbounds: &[config::InboundItemConfig],
    ancillary_handle: &tokio::runtime::Handle,
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

    // Update adblock enabled state.
    pool.adblock_manager.enabled.store(std::sync::Arc::new(new_config.adblock.enabled));

    // Cancel old adblock task and spawn a new one if enabled.
    adblock_cancel.cancel();
    *adblock_cancel = CancellationToken::new();
    if new_config.adblock.enabled {
        adblock::start_adblock_manager(
            pool.adblock_manager.clone(),
            pool.clone(),
            new_config.adblock.clone(),
            adblock_cancel.clone(),
        ).await;
    }

    // Stop the health checker BEFORE swapping the pool so it cannot race
    // mark_healthy / mark_unhealthy against indices that are mid-rewrite.
    health_cancel.cancel();

    // Swap the backend pool.
    match pool.reload(
        &new_config.backends,
        &new_config.groups,
        new_config.failover_order.as_ref(),
        new_config.bind_interface.as_deref(),
    ).await {
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
            let route_rx = pool.rt_chg_signal.clone();
            ancillary_handle.spawn(async move {
                health::run_health_checker(health_pool, health_config, token, route_rx).await;
            });
            let selector_pool = pool.clone();
            let token = health_cancel.clone();
            ancillary_handle.spawn(async move {
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
        let route_rx = pool.rt_chg_signal.clone();
        ancillary_handle.spawn(async move {
            health::run_health_checker(health_pool, health_config, token, route_rx).await;
        });

        let selector_pool = pool.clone();
        let token = health_cancel.clone();
        ancillary_handle.spawn(async move {
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

/// Initialise a non-blocking tracing subscriber that writes to stderr.
///
/// A dedicated background thread performs all I/O so that log calls on the
/// hot proxy path are reduced to a single lock-free channel send.
///
/// The returned [`WorkerGuard`] **must** be stored in a binding that lives for
/// the entire duration of `main`; dropping it earlier shuts down the I/O
/// thread and may lose buffered log lines.
fn init_tracing(log_level: &str) -> tracing_appender::non_blocking::WorkerGuard {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stderr());

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::time())
        .init();

    guard
}
