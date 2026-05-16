//! Configuration types for proxylb.
//!
//! Parsed from a YAML config file. Supports SOCKS5 and Shadowsocks inbound
//! listeners, an ordered list of SOCKS5h backends, health check parameters,
//! and an optional web status dashboard.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Root configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub inbound: InboundConfig,
    pub backends: Vec<BackendConfig>,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    #[serde(default)]
    pub web: WebConfig,
}

/// Inbound listener configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct InboundConfig {
    pub socks5: Option<Socks5InboundConfig>,
    pub shadowsocks: Option<ShadowsocksInboundConfig>,
}

/// SOCKS5 inbound listener.
#[derive(Debug, Deserialize, Clone)]
pub struct Socks5InboundConfig {
    pub listen: String,
}

/// Shadowsocks inbound listener.
#[derive(Debug, Deserialize, Clone)]
pub struct ShadowsocksInboundConfig {
    pub listen: String,
    pub password: String,
    /// Cipher method, e.g. "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"
    pub method: String,
}

/// A SOCKS5h backend entry.
#[derive(Debug, Deserialize, Clone)]
pub struct BackendConfig {
    /// Address in the form "host:port"
    pub address: String,
    /// Optional SOCKS5 username for backend authentication.
    pub username: Option<String>,
    /// Optional SOCKS5 password for backend authentication.
    pub password: Option<String>,
    /// Human-readable name for the backend (auto-generated if not set).
    pub name: Option<String>,
    /// Number of pre-authenticated connections to maintain (default: 5).
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

fn default_pool_size() -> usize {
    10
}

/// Health check configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheckConfig {
    /// Interval between health checks in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Timeout for a single health check in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Target host:port to probe through each backend.
    #[serde(default = "default_check_target")]
    pub check_target: String,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            timeout_secs: default_timeout(),
            check_target: default_check_target(),
        }
    }
}

fn default_interval() -> u64 {
    10
}
fn default_timeout() -> u64 {
    5
}
fn default_check_target() -> String {
    "www.google.com:80".to_string()
}

/// Web status dashboard configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct WebConfig {
    /// Listen address for the status web server.
    #[serde(default = "default_web_listen")]
    pub listen: String,
    /// Enable or disable the web dashboard.
    #[serde(default = "default_web_enabled")]
    pub enabled: bool,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: default_web_listen(),
            enabled: default_web_enabled(),
        }
    }
}

fn default_web_listen() -> String {
    "0.0.0.0:9090".to_string()
}
fn default_web_enabled() -> bool {
    true
}

impl Config {
    /// Load config from a YAML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading config: {}", path.display()))?;
        let config: Config =
            serde_yaml::from_str(&content).with_context(|| "parsing YAML config")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            anyhow::bail!("at least one backend must be configured");
        }
        if self.inbound.socks5.is_none() && self.inbound.shadowsocks.is_none() {
            anyhow::bail!("at least one inbound (socks5 or shadowsocks) must be configured");
        }
        if let Some(ref ss) = self.inbound.shadowsocks {
            // Validate cipher method is parseable
            ss.method
                .parse::<shadowsocks::crypto::CipherKind>()
                .map_err(|_| anyhow::anyhow!("unsupported shadowsocks cipher: {}", ss.method))?;
        }
        Ok(())
    }
}
