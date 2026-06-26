//! Filter domain filtering module.
//!
//! Implements a high-performance, custom suffix-matching Trie to block domains
//! and subdomains using AdGuard Home / ABP formatted filter lists. Whitelisting
//! rules (exceptions) override blocklist rules.

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct FilterUrl {
    pub url: String,
    pub tag: String,
    #[serde(default)]
    pub rule_count: usize,
}

#[cfg(feature = "filter")]
mod imp {
use super::FilterUrl;


use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use rusqlite::Connection;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::backend::BackendPool;
use crate::outbound::{BackendStream, TargetAddr};

#[cfg(feature = "ahash")]
pub type FilterSet = ahash::AHashSet<Box<str>>;

#[cfg(all(feature = "fast-hash", not(feature = "ahash")))]
pub type FilterSet = rustc_hash::FxHashSet<Box<str>>;

#[cfg(all(not(feature = "fast-hash"), not(feature = "ahash")))]
pub type FilterSet = std::collections::HashSet<Box<str>>;

/// Branch prediction hint: indicates that `b` is highly likely to be true.
#[inline(always)]
fn likely(b: bool) -> bool {
    #[cold]
    #[inline(never)]
    fn cold() {}
    if !b {
        cold();
    }
    b
}

/// Compilation of blocklist and whitelist domain rules.
pub struct FilterEngine {
    pub rules: FilterSet,
    pub block_rules_count: usize,
}

impl FilterEngine {
    pub fn new() -> Self {
        Self {
            rules: FilterSet::default(),
            block_rules_count: 0,
        }
    }

    /// Insert a domain pattern into the engine.
    pub fn insert(&mut self, domain: &str) {
        let is_lower = domain.bytes().all(|b| !b.is_ascii_uppercase());
        if likely(is_lower) {
            if !self.is_blocked(domain) {
                if self.rules.insert(domain.into()) {
                    self.block_rules_count += 1;
                }
            }
        } else {
            let domain_lower = domain.to_lowercase();
            if !self.is_blocked(domain_lower.as_str()) {
                if self.rules.insert(domain_lower.into_boxed_str()) {
                    self.block_rules_count += 1;
                }
            }
        }
    }

    /// Match a domain against the engine. Returns `true` if matched by a blocklist rule.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_trimmed = domain.trim_end_matches('.');
        if domain_trimmed.is_empty() {
            return false;
        }

        let is_lower = domain_trimmed.bytes().all(|b| !b.is_ascii_uppercase());
        let domain_lower = if likely(is_lower) {
            std::borrow::Cow::Borrowed(domain_trimmed)
        } else {
            std::borrow::Cow::Owned(domain_trimmed.to_ascii_lowercase())
        };

        let mut current = domain_lower.as_ref();
        loop {
            if self.rules.contains(current) {
                return true;
            }
            if let Some(idx) = current.find('.') {
                current = &current[idx + 1..];
            } else {
                break;
            }
        }

        false
    }
}

/// Thread-safe manager that holds the active engine and tracks blocked connections.
pub struct FilterManager {
    pub engine: ArcSwap<FilterEngine>,
    pub enabled: ArcSwap<bool>,
    pub block_private: ArcSwap<bool>,
    pub blocked_requests: AtomicU64,
    pub db: Mutex<Option<Connection>>,
    pub cached_remote_contents: tokio::sync::RwLock<std::collections::HashMap<String, String>>,
    pub config_files: Vec<String>,
    pub config_urls: Vec<FilterUrl>,
    pub backend: Option<String>,
    pub rebuild_lock: tokio::sync::Mutex<()>,
}


impl FilterManager {
    pub fn new(config: &crate::config::FilterConfig, db_path: Option<&str>) -> Self {
        let db = db_path.and_then(|p| Connection::open(p).ok());
        let mut enabled = config.enabled;
        let mut block_private = config.block_private_addresses;

        if let Some(ref conn) = db {
            let _ = conn.execute(
                "CREATE TABLE IF NOT EXISTS filter_rules (domain TEXT PRIMARY KEY)",
                [],
            );
            let _ = conn.execute(
                "CREATE TABLE IF NOT EXISTS filter_urls (url TEXT PRIMARY KEY)",
                [],
            );
            // Migration: add tag column if it doesn't exist
            let _ = conn.execute(
                "ALTER TABLE filter_urls ADD COLUMN tag TEXT",
                [],
            );
            let _ = conn.execute(
                "CREATE TABLE IF NOT EXISTS filter_state (key TEXT PRIMARY KEY, value TEXT)",
                [],
            );

            // Load initial state overrides
            if let Ok(mut stmt) = conn.prepare("SELECT value FROM filter_state WHERE key = 'enabled'") {
                if let Ok(mut rows) = stmt.query([]) {
                    if let Ok(Some(row)) = rows.next() {
                        let val: String = row.get(0).unwrap();
                        enabled = val == "true";
                    }
                }
            }
            if let Ok(mut stmt) = conn.prepare("SELECT value FROM filter_state WHERE key = 'block_private'") {
                if let Ok(mut rows) = stmt.query([]) {
                    if let Ok(Some(row)) = rows.next() {
                        let val: String = row.get(0).unwrap();
                        block_private = val == "true";
                    }
                }
            }
        }

        Self {
            engine: ArcSwap::from_pointee(FilterEngine::new()),
            enabled: ArcSwap::from_pointee(enabled),
            block_private: ArcSwap::from_pointee(block_private),
            blocked_requests: AtomicU64::new(0),
            db: Mutex::new(db),
            cached_remote_contents: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            config_files: config.files.clone(),
            config_urls: config.urls.clone().into_iter().map(|u| u.into_filter_url()).collect(),
            backend: config.backend.clone(),
            rebuild_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Check if target address should be blocked.
    pub fn is_blocked(&self, target: &TargetAddr) -> bool {
        if !**self.enabled.load() {
            return false;
        }

        if **self.block_private.load() && crate::inbound::is_private_target_sync(target) {
            self.blocked_requests.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let blocked = match target {
            TargetAddr::Domain(host, _) => self.engine.load().is_blocked(host),
            TargetAddr::Ip(addr) => self.engine.load().is_blocked(&addr.ip().to_string()),
        };

        if blocked {
            self.blocked_requests.fetch_add(1, Ordering::Relaxed);
        }

        blocked
    }

    pub async fn rebuild_engine(&self) {
        let _guard = self.rebuild_lock.lock().await;

        let mut local_contents = Vec::new();
        for file_path in &self.config_files {
            if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                local_contents.push(content);
            }
        }

        let mut db_rules = String::new();
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                if let Ok(mut stmt) = conn.prepare("SELECT domain FROM filter_rules") {
                    if let Ok(rules_iter) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                        for r in rules_iter.flatten() {
                            db_rules.push_str(&r);
                            db_rules.push('\n');
                        }
                    }
                }
            }
        }
        if !db_rules.is_empty() {
            local_contents.push(db_rules);
        }

        let remote = self.cached_remote_contents.read().await;
        let remote_contents: Vec<&str> = remote.values().map(|s| s.as_str()).collect();
        let local_contents_str: Vec<&str> = local_contents.iter().map(|s| s.as_str()).collect();
        let engine = build_engine_from_contents(&local_contents_str, &remote_contents);
        self.engine.store(Arc::new(engine));
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(Arc::new(enabled));
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO filter_state (key, value) VALUES ('enabled', ?)",
                    [if enabled { "true" } else { "false" }],
                );
            }
        }
    }

    pub fn set_block_private(&self, block_private: bool) {
        self.block_private.store(Arc::new(block_private));
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO filter_state (key, value) VALUES ('block_private', ?)",
                    [if block_private { "true" } else { "false" }],
                );
            }
        }
    }

    pub async fn add_rule(&self, rule: &str) -> anyhow::Result<()> {
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                conn.execute(
                    "INSERT OR REPLACE INTO filter_rules (domain) VALUES (?)",
                    [rule],
                )?;
            }
        }
        self.rebuild_engine().await;
        Ok(())
    }

    pub async fn delete_rule(&self, rule: &str) -> anyhow::Result<()> {
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                conn.execute("DELETE FROM filter_rules WHERE domain = ?", [rule])?;
            }
        }
        self.rebuild_engine().await;
        Ok(())
    }

    pub fn get_rules(&self) -> Vec<String> {
        let mut rules = Vec::new();
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                if let Ok(mut stmt) = conn.prepare("SELECT domain FROM filter_rules") {
                    if let Ok(rules_iter) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                        for r in rules_iter.flatten() {
                            rules.push(r);
                        }
                    }
                }
            }
        }
        rules
    }

    pub async fn add_url(&self, url: &str, tag: &str, content: String) -> anyhow::Result<()> {
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                conn.execute(
                    "INSERT OR REPLACE INTO filter_urls (url, tag) VALUES (?, ?)",
                    (url, tag),
                )?;
            }
        }
        self.cached_remote_contents.write().await.insert(url.to_string(), content);
        self.rebuild_engine().await;
        Ok(())
    }

    pub async fn delete_url(&self, url: &str) -> anyhow::Result<()> {
        if self.config_urls.iter().any(|u| u.url == url) {
            anyhow::bail!("Cannot delete URL specified in configuration file");
        }
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                conn.execute("DELETE FROM filter_urls WHERE url = ?", [url])?;
            }
        }
        self.cached_remote_contents.write().await.remove(url);
        self.rebuild_engine().await;
        Ok(())
    }

    pub fn get_urls(&self) -> Vec<FilterUrl> {
        let mut urls = Vec::new();
        for u in &self.config_urls {
            urls.push(u.clone());
        }
        if let Ok(guard) = self.db.lock() {
            if let Some(conn) = guard.as_ref() {
                if let Ok(mut stmt) = conn.prepare("SELECT url, tag FROM filter_urls") {
                    if let Ok(urls_iter) = stmt.query_map([], |row| {
                        Ok(FilterUrl {
                            url: row.get(0)?,
                            tag: row.get(1).unwrap_or_default(),
                            rule_count: 0,
                        })
                    }) {
                        for u in urls_iter.flatten() {
                            urls.push(u);
                        }
                    }
                }
            }
        }
        urls
    }
}

/// Parse a rule line into a domain string and allowed flag.
/// Supports hosts files (`127.0.0.1 domain`), AdGuard/ABP rules (`||domain^`, `@@||domain^`),
/// and plain domain rules. Skips comments and cosmetic rules.
pub fn parse_rule_line(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return None;
    }

    // Skip cosmetic filters
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") {
        return None;
    }

    if line.starts_with("@@") {
        return None; // Ignore allow rules
    }

    let mut rule = line;

    if rule.starts_with("||") {
        rule = &rule[2..];
    }

    rule = rule.trim_start_matches('|').trim_end_matches('|');

    let end_idx = rule.find(|c| c == '^' || c == '/' || c == '$' || c == ':' || c == '*');
    let mut domain = if let Some(idx) = end_idx {
        &rule[..idx]
    } else {
        rule
    };

    domain = domain.trim();

    // Hosts file format: IP domain
    let parts: Vec<&str> = domain.split_whitespace().collect();
    if parts.len() >= 2 {
        if parts[0].parse::<std::net::IpAddr>().is_ok() {
            domain = parts[1];
        }
    }

    if domain.is_empty() || domain.contains('/') || domain.contains('*') || domain.contains('?') {
        return None;
    }

    Some(domain)
}

/// Connect to target via a specific backend in the pool.
async fn connect_via_backend(
    pool: &BackendPool,
    backend_name: Option<&str>,
    target: &TargetAddr,
    timeout: Duration,
) -> Result<BackendStream, anyhow::Error> {
    let name = match backend_name {
        None | Some("direct") => {
            return Ok(crate::outbound::direct_connect(target, timeout, None).await?);
        }
        Some(n) => n,
    };

    let backends = pool.get_backends_in_order().await;
    let found = backends
        .into_iter()
        .find(|(_, info, _, _)| info.name == name);

    if let Some((index, info, _healthy, _enabled)) = found {
        if info.is_direct() {
            return Ok(crate::outbound::direct_connect(
                target,
                timeout,
                info.bind_interface.as_deref(),
            )
            .await?);
        } else if info.is_shadowsocks() {
            let ss_cfg = info.ss_config.as_ref().unwrap();
            let ss_ctx = info.ss_context.as_ref().unwrap().clone();
            let pc = pool.get_pooled_connection(index);
            match pc {
                Some(crate::backend::PooledConn {
                    stream: Some(pooled),
                    ..
                }) => {
                    return Ok(crate::outbound::ss_connect_pooled(
                        pooled, ss_cfg, ss_ctx, target,
                    ));
                }
                _ => {
                    return Ok(crate::outbound::ss_connect_fresh(
                        &info, ss_cfg, ss_ctx, target, timeout,
                    )
                    .await?);
                }
            }
        } else {
            let pc = pool.get_pooled_connection(index);
            match pc {
                Some(crate::backend::PooledConn {
                    stream: Some(pooled),
                    ..
                }) => match crate::outbound::socks5h_connect_target(pooled, target).await {
                    Ok(s) => return Ok(s),
                    Err(_) => {
                        return Ok(crate::outbound::socks5h_connect(&info, target, timeout).await?);
                    }
                },
                _ => {
                    return Ok(crate::outbound::socks5h_connect(&info, target, timeout).await?);
                }
            }
        }
    }

    tracing::warn!(backend = %name, "specified backend not found in pool, falling back to direct connection");
    Ok(crate::outbound::direct_connect(target, timeout, None).await?)
}

/// Download filter rules from a URL via a specific backend.
pub async fn download_url(
    pool: &BackendPool,
    backend_name: Option<&str>,
    initial_url_str: &str,
) -> Result<String, anyhow::Error> {
    let mut url = Url::parse(initial_url_str)?;
    let mut redirects_followed = 0;
    const MAX_REDIRECTS: usize = 5;

    loop {
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("missing host in URL"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let target = TargetAddr::Domain(host.clone(), port);
        let timeout = Duration::from_secs(15);

        let stream = connect_via_backend(pool, backend_name, &target, timeout).await?;

        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let path_with_query = if let Some(query) = url.query() {
            format!("{}?{}", path, query)
        } else {
            path.to_string()
        };

        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: proxylb/1.2.0\r\n\
             Connection: close\r\n\r\n",
            path_with_query, host
        );

        let mut body_buf = Vec::new();
        if url.scheme() == "https" {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let domain = ServerName::try_from(host).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid DNS name")
            })?;
            let mut tls_stream = connector.connect(domain, stream).await?;

            tls_stream.write_all(request.as_bytes()).await?;
            tls_stream.flush().await?;
            tls_stream.read_to_end(&mut body_buf).await?;
        } else {
            let mut stream = stream;
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            stream.read_to_end(&mut body_buf).await?;
        }

        if let Some(next_url) = parse_http_redirect(&body_buf, &url)? {
            if redirects_followed >= MAX_REDIRECTS {
                anyhow::bail!("too many redirects");
            }
            redirects_followed += 1;
            url = next_url;
            tracing::debug!(url = %url, "following redirect");
            continue;
        }

        return parse_http_response(&body_buf);
    }
}

fn parse_http_redirect(
    response_buf: &[u8],
    current_url: &Url,
) -> Result<Option<Url>, anyhow::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(response_buf)?;
    if let httparse::Status::Complete(_) = status {
        let code = resp.code.unwrap_or(200);
        if (300..400).contains(&code) {
            for header in resp.headers.iter() {
                if header.name.eq_ignore_ascii_case("location") {
                    let loc_str = std::str::from_utf8(header.value)?;
                    let next_url = current_url.join(loc_str)?;
                    return Ok(Some(next_url));
                }
            }
        }
    }
    Ok(None)
}

fn parse_http_response(response_buf: &[u8]) -> Result<String, anyhow::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(response_buf)?;
    if let httparse::Status::Complete(body_start_offset) = status {
        if resp.code == Some(200) {
            let body = &response_buf[body_start_offset..];
            Ok(String::from_utf8_lossy(body).into_owned())
        } else {
            anyhow::bail!("HTTP download returned status: {:?}", resp.code);
        }
    } else {
        anyhow::bail!("incomplete HTTP response");
    }
}

/// Compile lists into an `FilterEngine`.
pub fn build_engine_from_contents(
    local_contents: &[&str],
    remote_contents: &[&str],
) -> FilterEngine {
    let mut engine = FilterEngine::new();
    let mut parsed_rules = 0;

    let mut all_domains = Vec::new();
    for content in local_contents.iter().chain(remote_contents.iter()) {
        for line in content.lines() {
            if let Some(domain) = parse_rule_line(line) {
                all_domains.push(domain);
                parsed_rules += 1;
            }
        }
    }

    all_domains.sort_unstable_by_key(|d| d.len());

    for domain in all_domains {
        engine.insert(domain);
    }

    engine.rules.shrink_to_fit();

    tracing::info!(
        block_rules = engine.block_rules_count,
        total_parsed = parsed_rules,
        "filter engine built successfully"
    );
    engine
}

/// Start background manager task to fetch lists periodically.
pub async fn start_filter_manager(
    manager: Arc<FilterManager>,
    pool: BackendPool,
    config: crate::config::FilterConfig,
    cancel: CancellationToken,
) {
    if !config.enabled {
        return;
    }

    // Initial rebuild
    manager.rebuild_engine().await;

    let manager_clone = manager.clone();
    let pool_clone = pool.clone();
    let config_clone = config.clone();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        let interval = Duration::from_secs(config_clone.update_interval_hours * 3600);
        let mut ticker = tokio::time::interval(interval);
        // Consume the first immediate tick so we wait for the actual interval in the loop.
        ticker.tick().await;

        loop {
            let mut new_cache = std::collections::HashMap::new();
            let combined_urls: std::collections::HashSet<String> = manager_clone.get_urls().into_iter().map(|u| u.url).collect();

            for url in &combined_urls {
                tracing::info!(url = %url, "downloading filter list");
                match download_url(&pool_clone, config_clone.backend.as_deref(), url).await {
                    Ok(content) => {
                        new_cache.insert(url.clone(), content);
                        tracing::info!(url = %url, "downloaded filter list successfully");
                    }
                    Err(e) => {
                        tracing::error!(url = %url, error = %e, "failed to download filter list");
                    }
                }
            }

            *manager_clone.cached_remote_contents.write().await = new_cache;
            manager_clone.rebuild_engine().await;

            tokio::select! {
                _ = cancel_clone.cancelled() => {
                    tracing::debug!("filter updater cancelled");
                    return;
                }
                _ = ticker.tick() => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_rule_parser() {
        assert_eq!(parse_rule_line("! comment"), None);
        assert_eq!(parse_rule_line("# comment"), None);
        assert_eq!(
            parse_rule_line("||example.org^"),
            Some("example.org")
        );
        assert_eq!(
            parse_rule_line("@@||example.org^"),
            None
        );
        assert_eq!(
            parse_rule_line("127.0.0.1 badsite.com"),
            Some("badsite.com")
        );
        assert_eq!(
            parse_rule_line("0.0.0.0   badsite.com"),
            Some("badsite.com")
        );
        assert_eq!(
            parse_rule_line("badsite.com"),
            Some("badsite.com")
        );
        assert_eq!(
            parse_rule_line("||example.org^$third-party"),
            Some("example.org")
        );
    }

    #[test]
    fn test_trie_matching() {
        let mut engine = FilterEngine::new();
        engine.insert("example.com");
        engine.insert("doubleclick.net");
        // engine.insert("sub.example.com", true); // exception removed

        assert!(engine.is_blocked("example.com"));
        assert!(engine.is_blocked("a.example.com"));
        assert!(engine.is_blocked("sub.example.com"));
        assert!(engine.is_blocked("a.sub.example.com"));
        assert!(!engine.is_blocked("google.com"));
    }

    #[test]
    fn test_filter_performance_benchmark() {
        let mut engine = FilterEngine::new();

        // Add 10,000 dummy rules
        for i in 0..10000 {
            engine.insert(&format!("bad-domain-{}.com", i));
        }
        engine.insert("example.com");
        engine.insert("sub.example.com");

        let iterations = 1_000_000;
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(engine.is_blocked("example.com"));
            std::hint::black_box(engine.is_blocked("google.com"));
            std::hint::black_box(engine.is_blocked("sub.example.com"));
        }
        let duration = start.elapsed();
        let total_queries = iterations * 3;
        let ns_per_query = duration.as_nanos() as f64 / total_queries as f64;
        let qps = total_queries as f64 / duration.as_secs_f64();

        println!(
            "\nFilter Matcher Benchmark:\n\
             -------------------------\n\
             Rules count: {}\n\
             Total queries: {}\n\
             Total duration: {:?}\n\
             Avg query time: {:.2} ns\n\
             Queries/second: {:.0}\n",
            engine.block_rules_count,
            total_queries,
            duration,
            ns_per_query,
            qps
        );
    }



    #[test]
    #[ignore]
    fn bench_filter_engine() {
        println!("Downloading filter rules from github...");
        let url = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt";
        
        let output = std::process::Command::new("curl")
            .arg("-sSL")
            .arg(url)
            .output()
            .expect("failed to execute curl");
            
        if !output.status.success() {
            panic!("Failed to download filter rules");
        }

        let content = String::from_utf8(output.stdout).expect("invalid utf8");
        println!("Downloaded {} bytes.", content.len());

        let mut engine = FilterEngine::new();
        let start_build = Instant::now();
        let mut _parsed = 0;
        for line in content.lines() {
            if let Some(domain) = parse_rule_line(line) {
                engine.insert(&domain);
                _parsed += 1;
            }
        }
        
        println!("Engine built with {} unique domains in {:?}", engine.rules.len(), start_build.elapsed());
        
        let test_domains = vec![
            "google-analytics.com",
            "ads.google.com",
            "sub.ads.google.com",
            "example.com",
            "not-blocked.com",
            "www.baidu.com",
            "api.bilibili.com",
            "some.very.long.subdomain.of.a.blocked.domain.google-analytics.com",
        ];
        
        let iterations = 10_000_000;
        let total_lookups = iterations * test_domains.len();
        
        println!("Benchmarking {} iterations of lookups ({} total lookups)...", iterations, total_lookups);
        
        let start_bench = Instant::now();
        let mut blocked_count = 0;
        for _ in 0..iterations {
            for domain in &test_domains {
                if engine.is_blocked(domain) {
                    blocked_count += 1;
                }
            }
        }
        let elapsed = start_bench.elapsed();
        
        println!("Total lookups: {}", total_lookups);
        println!("Blocked count: {}", blocked_count);
        println!("Total time: {:?}", elapsed);
        println!("Time per lookup: {:?}", elapsed / total_lookups as u32);
    }
}
}

#[cfg(feature = "filter")]
pub use imp::*;


#[cfg(not(feature = "filter"))]
mod stub {
    #![allow(dead_code)]
    use super::FilterUrl;
    use std::sync::atomic::AtomicU64;
    use arc_swap::ArcSwap;
    use crate::outbound::TargetAddr;

    pub struct FilterEngine {
        pub block_rules_count: usize,
    }
    impl FilterEngine {
        pub fn new() -> Self { Self { block_rules_count: 0 } }
        pub fn is_blocked(&self, _domain: &str) -> bool { false }
    }

    pub struct FilterManager {
        pub engine: ArcSwap<FilterEngine>,
        pub enabled: ArcSwap<bool>,
        pub block_private: ArcSwap<bool>,
        pub blocked_requests: AtomicU64,
        pub backend: Option<String>,
        pub cached_remote_contents: tokio::sync::RwLock<std::collections::HashMap<String, String>>,
    }

    impl FilterManager {
        pub fn new(config: &crate::config::FilterConfig, _db_path: Option<&str>) -> Self {
            Self {
                engine: ArcSwap::from_pointee(FilterEngine::new()),
                enabled: ArcSwap::from_pointee(false),
                block_private: ArcSwap::from_pointee(false),
                blocked_requests: AtomicU64::new(0),
                backend: config.backend.clone(),
                cached_remote_contents: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            }
        }

        pub fn is_blocked(&self, _target: &TargetAddr) -> bool { false }
        pub async fn rebuild_engine(&self) {}
        pub fn set_enabled(&self, _enabled: bool) {}
        pub fn set_block_private(&self, _block_private: bool) {}
        pub async fn add_rule(&self, _rule: &str) -> anyhow::Result<()> { Ok(()) }
        pub async fn delete_rule(&self, _rule: &str) -> anyhow::Result<()> { Ok(()) }
        pub fn get_rules(&self) -> Vec<String> { Vec::new() }
        pub async fn add_url(&self, _url: &str, _tag: &str, _content: String) -> anyhow::Result<()> { Ok(()) }
        pub async fn delete_url(&self, _url: &str) -> anyhow::Result<()> { Ok(()) }
        pub fn get_urls(&self) -> Vec<FilterUrl> { Vec::new() }
    }

    pub async fn start_filter_manager(
        _manager: std::sync::Arc<FilterManager>,
        _pool: crate::backend::BackendPool,
        _config: crate::config::FilterConfig,
        _cancel: tokio_util::sync::CancellationToken,
    ) {}

    pub async fn download_url(
        _pool: &crate::backend::BackendPool,
        _backend_name: Option<&str>,
        _url: &str,
    ) -> anyhow::Result<String> {
        anyhow::bail!("Filter engine is disabled at compile time");
    }

    pub fn parse_rule_line(_line: &str) -> Option<&str> { None }

    pub fn build_engine_from_contents(
        _local_contents: &[&str],
        _remote_contents: &[&str],
    ) -> FilterEngine {
        FilterEngine::new()
    }
}

#[cfg(not(feature = "filter"))]
pub use stub::*;
