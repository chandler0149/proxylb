//! Configuration types for proxylb.
//!
//! Parsed from a YAML config file. Supports SOCKS5 and Shadowsocks inbound
//! listeners, an ordered list of SOCKS5h backends (TCP or Unix domain socket),
//! health check parameters, and an optional web status dashboard.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Root configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub inbound: InboundConfig,
    #[serde(default)]
    pub inbounds: Vec<InboundItemConfig>,
    pub backends: Vec<BackendConfig>,
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
    #[serde(default)]
    pub failover_order: Option<Vec<String>>,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    #[serde(default)]
    pub web: WebConfig,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GroupStrategy {
    UrlTest,
    Failover,
    LoadBalance,
}

impl Default for GroupStrategy {
    fn default() -> Self {
        Self::Failover
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GroupConfig {
    pub name: String,
    #[serde(default)]
    pub strategy: GroupStrategy,
    pub backends: Vec<String>,
}

/// Inbound listener configuration.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct InboundConfig {
    pub socks5: Option<Socks5InboundConfig>,
    pub shadowsocks: Option<ShadowsocksInboundConfig>,
    pub http: Option<HttpInboundConfig>,
    #[serde(default)]
    pub filter: FilterConfig,
}

/// A specific inbound configuration item when running multiple inbounds.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundItemConfig {
    Socks5 {
        listen: String,
        #[serde(default)]
        filter: Option<FilterConfig>,
    },
    Shadowsocks {
        listen: String,
        password: String,
        method: String,
        #[serde(default)]
        filter: Option<FilterConfig>,
    },
    Http {
        listen: String,
        #[serde(default)]
        filter: Option<FilterConfig>,
    },
}

/// SOCKS5 inbound listener.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct Socks5InboundConfig {
    pub listen: String,
}

/// Shadowsocks inbound listener.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ShadowsocksInboundConfig {
    pub listen: String,
    pub password: String,
    /// Cipher method, e.g. "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"
    pub method: String,
}

/// HTTP inbound listener.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct HttpInboundConfig {
    pub listen: String,
}

fn default_filter_enabled() -> bool {
    true
}

/// Private address target filter configuration.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct FilterConfig {
    #[serde(default = "default_filter_enabled")]
    pub enabled: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}




/// A SOCKS5h backend entry.
///
/// Exactly one of `address` (TCP) or `unix_socket` (Unix domain socket path)
/// must be set. Setting both or neither is a configuration error.
#[derive(Debug, Deserialize, Clone)]
pub struct BackendConfig {
    /// TCP backend address in the form "host:port".
    /// Mutually exclusive with `unix_socket`.
    pub address: Option<String>,
    /// Path to a Unix domain socket for the backend.
    /// Mutually exclusive with `address`.
    pub unix_socket: Option<String>,
    /// Optional SOCKS5 username for backend authentication.
    pub username: Option<String>,
    /// Optional SOCKS5 password for backend authentication.
    pub password: Option<String>,
    /// Human-readable name for the backend (auto-generated if not set).
    pub name: Option<String>,
    /// Number of pre-authenticated connections to maintain (default: 10).
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
    "http://www.gstatic.com/generate_204".to_string()
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

    /// Return all active inbounds, combining the legacy single `inbound` section and the new `inbounds` list.
    pub fn all_inbounds(&self) -> Vec<InboundItemConfig> {
        let mut res = Vec::new();
        if let Some(ref s5) = self.inbound.socks5 {
            res.push(InboundItemConfig::Socks5 {
                listen: s5.listen.clone(),
                filter: Some(self.inbound.filter.clone()),
            });
        }
        if let Some(ref ss) = self.inbound.shadowsocks {
            res.push(InboundItemConfig::Shadowsocks {
                listen: ss.listen.clone(),
                password: ss.password.clone(),
                method: ss.method.clone(),
                filter: Some(self.inbound.filter.clone()),
            });
        }
        if let Some(ref http) = self.inbound.http {
            res.push(InboundItemConfig::Http {
                listen: http.listen.clone(),
                filter: Some(self.inbound.filter.clone()),
            });
        }
        for item in &self.inbounds {
            let mut resolved_item = item.clone();
            match &mut resolved_item {
                InboundItemConfig::Socks5 { filter, .. } => {
                    if filter.is_none() {
                        *filter = Some(self.inbound.filter.clone());
                    }
                }
                InboundItemConfig::Shadowsocks { filter, .. } => {
                    if filter.is_none() {
                        *filter = Some(self.inbound.filter.clone());
                    }
                }
                InboundItemConfig::Http { filter, .. } => {
                    if filter.is_none() {
                        *filter = Some(self.inbound.filter.clone());
                    }
                }
            }
            res.push(resolved_item);
        }
        res
    }

    fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            anyhow::bail!("at least one backend must be configured");
        }

        // Collect all backend names to check existence.
        let mut backend_names = std::collections::HashSet::new();
        for (i, backend) in self.backends.iter().enumerate() {
            let name = backend
                .name
                .clone()
                .unwrap_or_else(|| format!("backend-{}", i));
            backend_names.insert(name);

            let label = backend
                .name
                .as_deref()
                .map(|n| format!("backend '{}'", n))
                .unwrap_or_else(|| format!("backend[{}]", i));
            match (&backend.address, &backend.unix_socket) {
                (Some(_), None) | (None, Some(_)) => {} // exactly one set — OK
                (Some(_), Some(_)) => {
                    anyhow::bail!(
                        "{}: 'address' and 'unix_socket' are mutually exclusive",
                        label
                    );
                }
                (None, None) => {
                    anyhow::bail!(
                        "{}: one of 'address' or 'unix_socket' must be set",
                        label
                    );
                }
            }
        }

        // Validate groups
        let mut group_names = std::collections::HashSet::new();
        let mut grouped_backends = std::collections::HashSet::new();
        for group in &self.groups {
            if group_names.contains(&group.name) {
                anyhow::bail!("duplicate group name: {}", group.name);
            }
            if backend_names.contains(&group.name) {
                anyhow::bail!("group name '{}' conflicts with backend name", group.name);
            }
            group_names.insert(group.name.clone());

            if group.backends.is_empty() {
                anyhow::bail!("group '{}' has no backends", group.name);
            }

            for member in &group.backends {
                if !backend_names.contains(member) {
                    anyhow::bail!(
                        "group '{}' refers to non-existent backend '{}'",
                        group.name,
                        member
                    );
                }
                // Enforce: the same backend cannot be used in multiple groups
                if !grouped_backends.insert(member.clone()) {
                    anyhow::bail!(
                        "backend '{}' cannot be used in multiple groups",
                        member
                    );
                }
            }
        }

        // Validate failover_order if present
        if let Some(ref order) = self.failover_order {
            for target in order {
                if !group_names.contains(target) && !backend_names.contains(target) {
                    anyhow::bail!(
                        "failover_order refers to unknown target '{}' (must be a group or backend name)",
                        target
                    );
                }
                // Enforce: a backend cannot be used as a standalone target in failover_order if it belongs to a group
                if backend_names.contains(target) && grouped_backends.contains(target) {
                    anyhow::bail!(
                        "backend '{}' cannot be used as a standalone target in failover_order because it belongs to a group",
                        target
                    );
                }
            }
        }

        // Validate all shadowsocks cipher methods are parseable
        for item in &self.all_inbounds() {
            if let InboundItemConfig::Shadowsocks { method, .. } = item {
                method
                    .parse::<shadowsocks::crypto::CipherKind>()
                    .map_err(|_| anyhow::anyhow!("unsupported shadowsocks cipher: {}", method))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config_with_groups() {
        let cfg = Config {
            inbound: InboundConfig::default(),
            inbounds: vec![],
            backends: vec![
                BackendConfig { address: Some("127.0.0.1:8081".to_string()), unix_socket: None, name: Some("b1".to_string()), username: None, password: None, pool_size: 1 },
                BackendConfig { address: Some("127.0.0.1:8082".to_string()), unix_socket: None, name: Some("b2".to_string()), username: None, password: None, pool_size: 1 },
            ],
            groups: vec![
                GroupConfig { name: "g1".to_string(), strategy: GroupStrategy::UrlTest, backends: vec!["b1".to_string()] },
            ],
            failover_order: Some(vec!["g1".to_string(), "b2".to_string()]),
            health_check: HealthCheckConfig::default(),
            web: WebConfig::default(),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_invalid_duplicate_backend_in_multiple_groups() {
        let cfg = Config {
            inbound: InboundConfig::default(),
            inbounds: vec![],
            backends: vec![
                BackendConfig { address: Some("127.0.0.1:8081".to_string()), unix_socket: None, name: Some("b1".to_string()), username: None, password: None, pool_size: 1 },
            ],
            groups: vec![
                GroupConfig { name: "g1".to_string(), strategy: GroupStrategy::UrlTest, backends: vec!["b1".to_string()] },
                GroupConfig { name: "g2".to_string(), strategy: GroupStrategy::Failover, backends: vec!["b1".to_string()] },
            ],
            failover_order: None,
            health_check: HealthCheckConfig::default(),
            web: WebConfig::default(),
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("cannot be used in multiple groups"));
    }

    #[test]
    fn test_invalid_grouped_backend_as_standalone_in_failover_order() {
        let cfg = Config {
            inbound: InboundConfig::default(),
            inbounds: vec![],
            backends: vec![
                BackendConfig { address: Some("127.0.0.1:8081".to_string()), unix_socket: None, name: Some("b1".to_string()), username: None, password: None, pool_size: 1 },
            ],
            groups: vec![
                GroupConfig { name: "g1".to_string(), strategy: GroupStrategy::UrlTest, backends: vec!["b1".to_string()] },
            ],
            failover_order: Some(vec!["g1".to_string(), "b1".to_string()]),
            health_check: HealthCheckConfig::default(),
            web: WebConfig::default(),
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("cannot be used as a standalone target"));
    }

    #[test]
    fn test_multiple_inbounds_parsing_and_resolution() {
        let yaml = r#"
inbound:
  filter:
    enabled: false
inbounds:
  - type: socks5
    listen: "127.0.0.1:1080"
  - type: shadowsocks
    listen: "127.0.0.1:8388"
    password: "password123"
    method: "aes-256-gcm"
  - type: http
    listen: "127.0.0.1:8080"
backends:
  - address: "127.0.0.1:8081"
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.validate().is_ok());
        let resolved = cfg.all_inbounds();
        assert_eq!(resolved.len(), 3);

        match &resolved[0] {
            InboundItemConfig::Socks5 { listen, filter } => {
                assert_eq!(listen, "127.0.0.1:1080");
                assert_eq!(filter.as_ref().unwrap().enabled, false);
            }
            _ => panic!("Expected Socks5 inbound"),
        }

        match &resolved[1] {
            InboundItemConfig::Shadowsocks { listen, password, method, filter } => {
                assert_eq!(listen, "127.0.0.1:8388");
                assert_eq!(password, "password123");
                assert_eq!(method, "aes-256-gcm");
                assert_eq!(filter.as_ref().unwrap().enabled, false);
            }
            _ => panic!("Expected Shadowsocks inbound"),
        }

        match &resolved[2] {
            InboundItemConfig::Http { listen, filter } => {
                assert_eq!(listen, "127.0.0.1:8080");
                assert_eq!(filter.as_ref().unwrap().enabled, false);
            }
            _ => panic!("Expected HTTP inbound"),
        }
    }
}
