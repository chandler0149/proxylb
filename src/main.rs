//! ProxyLB — A high-performance SOCKS5 proxy load balancer.
//!
//! Accepts SOCKS5 and Shadowsocks inbound connections, forwards them through
//! an ordered list of SOCKS5h backends with health checking and failover.

mod adblock;
mod backend;
mod config;
mod health;
mod inbound;
mod outbound;
mod relay;
mod route_watcher;
pub mod tls;
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
#[command(name = "proxylb", version = concat!(env!("CARGO_PKG_VERSION"), "-", env!("GIT_HASH")), about)]
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

    // Load config first to read CPU affinity settings.
    let config = config::Config::load(&args.config)?;

    // Store zero-copy flag.
    #[cfg(target_os = "linux")]
    crate::relay::ZERO_COPY_ENABLED.store(
        config.advanced.zero_copy,
        std::sync::atomic::Ordering::Relaxed,
    );

    // Extract CPU affinity configuration.
    let mut worker_cores = None;
    let mut ancillary_cores = None;
    if let Some(ref affinity) = config.cpu_affinity {
        worker_cores = affinity.worker_cores.clone();
        ancillary_cores = affinity.ancillary_cores.clone();
    }

    // Initialize async (non-blocking) tracing with background thread pinned to ancillary core.
    let _log_guard = if args.log_level.eq_ignore_ascii_case("off") {
        None
    } else {
        Some(init_tracing(&args.log_level, &ancillary_cores))
    };

    tracing::info!("ProxyLB starting...");
    tracing::info!(backends = config.backends.len(), "configuration loaded");

    // Launch the fd-closer thread before the worker runtime so it is ready
    // as soon as the first connection closes.  Pin it to the first ancillary
    // core when one is configured so it stays off the forwarding cores.
    let closer_core = ancillary_cores.as_ref().and_then(|v| v.first().copied());
    crate::relay::init_deferred_dropper(closer_core);

    // Builder for worker runtime.
    let mut worker_builder = tokio::runtime::Builder::new_multi_thread();
    worker_builder.enable_all();
    worker_builder.thread_name("proxylb-worker");
    if let Some(ref cores) = worker_cores {
        if !cores.is_empty() {
            let next_core_idx = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let cores = cores.clone();
            worker_builder.on_thread_start(move || {
                let thread = std::thread::current();
                let name = thread.name().unwrap_or("");
                if name.starts_with("proxylb-worker") {
                    let idx = next_core_idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Some(&core_num) = cores.get(idx % cores.len()) {
                        if let Some(core_ids) = core_affinity::get_core_ids() {
                            if let Some(core_id) = core_ids.into_iter().find(|c| c.id == core_num) {
                                if core_affinity::set_for_current(core_id) {
                                    tracing::info!(
                                        "Bound tokio worker thread ({}) to CPU core {}",
                                        name,
                                        core_num
                                    );
                                } else {
                                    tracing::warn!(
                                        "Failed to bind tokio worker thread ({}) to CPU core {}",
                                        name,
                                        core_num
                                    );
                                }
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
    ancillary_builder.thread_name("proxylb-ancillary");
    if let Some(ref cores) = ancillary_cores {
        if !cores.is_empty() {
            let next_core_idx = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let cores = cores.clone();
            ancillary_builder.on_thread_start(move || {
                let thread = std::thread::current();
                let name = thread.name().unwrap_or("");
                if name.starts_with("proxylb-ancillary") {
                    let idx = next_core_idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Some(&core_num) = cores.get(idx % cores.len()) {
                        if let Some(core_ids) = core_affinity::get_core_ids() {
                            if let Some(core_id) = core_ids.into_iter().find(|c| c.id == core_num) {
                                if core_affinity::set_for_current(core_id) {
                                    tracing::info!(
                                        "Bound tokio ancillary thread ({}) to CPU core {}",
                                        name,
                                        core_num
                                    );
                                } else {
                                    tracing::warn!(
                                        "Failed to bind tokio ancillary thread ({}) to CPU core {}",
                                        name,
                                        core_num
                                    );
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    let ancillary_runtime = ancillary_builder.build()?;
    let ancillary_handle = ancillary_runtime.handle().clone();

    worker_runtime
        .block_on(main_async(config, args, worker_handle, ancillary_handle))
        .ok();

    tracing::info!("waiting for worker tasks to finish...");
    worker_runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    tracing::info!("waiting for ancillary tasks to finish...");
    ancillary_runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    Ok(())
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

    // Compute all active routes used by inbounds
    let mut active_routes = std::collections::HashSet::new();
    for item in config.all_inbounds() {
        let route = match item {
            config::InboundItemConfig::Socks5 { route, .. } => route,
            config::InboundItemConfig::Shadowsocks { route, .. } => route,
            config::InboundItemConfig::Http { route, .. } => route,
            config::InboundItemConfig::Mtproto { route, .. } => route,
        };
        if let Some(r) = route {
            active_routes.insert(r.clone());
        }
    }

    // Initialize backend pool.
    let pool = backend::BackendPool::new(
        &config.backends,
        &config.groups,
        config.failover_order.as_ref(),
        config.bind_interface.as_deref(),
        route_rx.clone(),
        &config.adblock,
        ancillary_handle.clone(),
        active_routes,
    )?;

    let mut ancillary_handles = Vec::new();
    // Spawn adblock background manager task if enabled
    let mut adblock_cancel = CancellationToken::new();
    if config.adblock.enabled {
        let adblock_pool = pool.clone();
        let adblock_config = config.adblock.clone();
        let token = adblock_cancel.clone();
        let adblock_manager = pool.adblock_manager.clone();
        ancillary_handles.push(ancillary_handle.spawn(async move {
            adblock::start_adblock_manager(adblock_manager, adblock_pool, adblock_config, token)
                .await;
        }));
    }

    // Spawn health checker and candidate selector background tasks with a shared cancellation token.
    let mut health_cancel = CancellationToken::new();
    {
        let health_pool = pool.clone();
        let health_config = config.health_check.clone();
        let token = health_cancel.clone();
        let route_rx_clone = route_rx.clone();
        ancillary_handles.push(ancillary_handle.spawn(async move {
            health::run_health_checker(health_pool, health_config, token, route_rx_clone).await;
        }));

        let selector_pool = pool.clone();
        let token = health_cancel.clone();
        ancillary_handles.push(ancillary_handle.spawn(async move {
            backend::run_candidate_selector(selector_pool, token).await;
        }));
    }

    // Spawn web dashboard.
    if config.web.enabled {
        let web_pool = pool.clone();
        let web_listen = config.web.listen.clone();
        ancillary_handles.push(ancillary_handle.spawn(async move {
            if let Err(e) = web::run_web_server(web_listen, web_pool).await {
                tracing::error!(error = %e, "web server failed");
            }
        }));
    }

    // Spawn inbound listeners.
    let inbound_cancel = CancellationToken::new();
    let mut handles = Vec::new();

    for inbound_item in config.all_inbounds() {
        let inbound_pool = pool.clone();
        let cancel = inbound_cancel.clone();
        match inbound_item {
            config::InboundItemConfig::Socks5 {
                listen,
                filter,
                tls: tls_cfg,
                username,
                password,
                route,
            } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("SOCKS5 ({})", listen),
                    listen.clone(),
                    "socks5".to_string(),
                );
                let route_idx = route.as_ref().and_then(|r| pool.get_route_index(r));
                handles.push(worker_handle.spawn(async move {
                    if let Err(e) = inbound::socks5::run_socks5_inbound(
                        listen,
                        inbound_pool,
                        stats,
                        filter_enabled,
                        tls_cfg,
                        username,
                        password,
                        route_idx,
                        cancel,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "SOCKS5 inbound failed");
                    }
                }));
            }
            config::InboundItemConfig::Shadowsocks {
                listen,
                password,
                method,
                filter,
                tls: tls_cfg,
                route,
            } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("Shadowsocks ({})", listen),
                    listen.clone(),
                    "shadowsocks".to_string(),
                );
                let route_idx = route.as_ref().and_then(|r| pool.get_route_index(r));
                handles.push(worker_handle.spawn(async move {
                    if let Err(e) = inbound::shadowsocks::run_shadowsocks_inbound(
                        listen,
                        password,
                        method,
                        inbound_pool,
                        stats,
                        filter_enabled,
                        tls_cfg,
                        route_idx,
                        cancel,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "Shadowsocks inbound failed");
                    }
                }));
            }
            config::InboundItemConfig::Http {
                listen,
                filter,
                tls: tls_cfg,
                username,
                password,
                route,
            } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("HTTP ({})", listen),
                    listen.clone(),
                    "http".to_string(),
                );
                let route_idx = route.as_ref().and_then(|r| pool.get_route_index(r));
                handles.push(worker_handle.spawn(async move {
                    if let Err(e) = inbound::http::run_http_inbound(
                        listen,
                        inbound_pool,
                        stats,
                        filter_enabled,
                        tls_cfg,
                        username,
                        password,
                        route_idx,
                        cancel,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "HTTP inbound failed");
                    }
                }));
            }
            config::InboundItemConfig::Mtproto {
                listen,
                password: secret,
                tls: tls_cfg,
                filter,
                route,
            } => {
                let filter_enabled = filter.map(|f| f.enabled).unwrap_or(true);
                let stats = pool.register_inbound(
                    format!("MTProto ({})", listen),
                    listen.clone(),
                    "mtproto".to_string(),
                );
                let route_idx = route.as_ref().and_then(|r| pool.get_route_index(r));
                handles.push(worker_handle.spawn(async move {
                    if let Err(e) = inbound::mtproto::run_mtproto_inbound(
                        listen,
                        inbound_pool,
                        stats,
                        filter_enabled,
                        secret,
                        tls_cfg,
                        route_idx,
                        cancel,
                    )
                    .await
                    {
                        tracing::error!(error = %e, "MTProto inbound failed");
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
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

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

    // Cancel all inbound accept loops and wait for them to exit.
    inbound_cancel.cancel();
    for handle in handles {
        let _ = handle.await;
    }

    adblock_cancel.cancel();
    health_cancel.cancel();

    for handle in ancillary_handles {
        handle.abort();
    }

    tracing::info!("ProxyLB stopped.");
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
    pool.adblock_manager
        .enabled
        .store(std::sync::Arc::new(new_config.adblock.enabled));

    // Cancel old adblock task and spawn a new one if enabled.
    adblock_cancel.cancel();
    *adblock_cancel = CancellationToken::new();
    if new_config.adblock.enabled {
        let adblock_pool = pool.clone();
        let adblock_config = new_config.adblock.clone();
        let token = adblock_cancel.clone();
        let adblock_manager = pool.adblock_manager.clone();
        ancillary_handle.spawn(async move {
            adblock::start_adblock_manager(adblock_manager, adblock_pool, adblock_config, token)
                .await;
        });
    }

    // Stop the health checker BEFORE swapping the pool so it cannot race
    // mark_healthy / mark_unhealthy against indices that are mid-rewrite.
    health_cancel.cancel();

    // Swap the backend pool.
    match pool
        .reload(
            &new_config.backends,
            &new_config.groups,
            new_config.failover_order.as_ref(),
            new_config.bind_interface.as_deref(),
        )
        .await
    {
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

struct AffinityWriter<W: std::io::Write> {
    inner: W,
    cores: Option<Vec<usize>>,
    pinned: std::sync::atomic::AtomicBool,
}

impl<W: std::io::Write> std::io::Write for AffinityWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.pinned.load(std::sync::atomic::Ordering::Relaxed) {
            if let Some(ref cores) = self.cores {
                if !cores.is_empty() {
                    if let Some(core_num) = cores.first() {
                        if let Some(core_ids) = core_affinity::get_core_ids() {
                            if let Some(core_id) = core_ids.into_iter().find(|c| c.id == *core_num)
                            {
                                let _ = core_affinity::set_for_current(core_id);
                            }
                        }
                    }
                }
            }
            self.pinned
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
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
fn init_tracing(
    log_level: &str,
    ancillary_cores: &Option<Vec<usize>>,
) -> tracing_appender::non_blocking::WorkerGuard {
    let writer = AffinityWriter {
        inner: std::io::stderr(),
        cores: ancillary_cores.clone(),
        pinned: std::sync::atomic::AtomicBool::new(false),
    };
    let (non_blocking, guard) = tracing_appender::non_blocking(writer);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::time())
        .init();

    guard
}
