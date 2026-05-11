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

use std::path::PathBuf;

use clap::Parser;
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
    let pool = backend::BackendPool::new(&config.backends)?;

    // Spawn health checker.
    let health_pool = pool.clone();
    let health_config = config.health_check.clone();
    tokio::spawn(async move {
        health::run_health_checker(health_pool, health_config).await;
    });

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

    if let Some(ref socks5_config) = config.inbound.socks5 {
        let listen = socks5_config.listen.clone();
        let socks5_pool = pool.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = inbound::socks5::run_socks5_inbound(listen, socks5_pool).await {
                tracing::error!(error = %e, "SOCKS5 inbound failed");
            }
        }));
    }

    if let Some(ref ss_config) = config.inbound.shadowsocks {
        let listen = ss_config.listen.clone();
        let password = ss_config.password.clone();
        let method = ss_config.method.clone();
        let ss_pool = pool.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                inbound::shadowsocks::run_shadowsocks_inbound(listen, password, method, ss_pool)
                    .await
            {
                tracing::error!(error = %e, "Shadowsocks inbound failed");
            }
        }));
    }

    tracing::info!("ProxyLB is running. Press Ctrl+C to stop.");

    // Wait for Ctrl+C.
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down...");

    // Abort all listener tasks.
    for handle in handles {
        handle.abort();
    }

    Ok(())
}
