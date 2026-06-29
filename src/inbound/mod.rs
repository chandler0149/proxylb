pub mod http;
pub mod mtproto;
pub mod shadowsocks;
pub mod socks5;

use crate::outbound::TargetAddr;
use std::future::Future;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio_util::sync::CancellationToken;

pub(crate) static WRR_COUNTER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// ─── Unified listener abstraction ────────────────────────────────────────────

/// A bound listener that accepts either TCP or Unix-domain-socket connections.
pub enum BoundListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl BoundListener {
    /// Bind to `addr`. A `unix://…` prefix selects a UDS listener; anything
    /// else is treated as a TCP `host:port`.
    pub async fn bind(
        addr: &str,
        prebound_uds: Option<std::os::unix::net::UnixListener>,
    ) -> anyhow::Result<Self> {
        if let Some(uds) = prebound_uds {
            uds.set_nonblocking(true)?;
            return Ok(Self::Unix(UnixListener::from_std(uds)?));
        }

        if let Some(path) = addr.strip_prefix("unix://") {
            if let Some(parent) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::metadata(path).is_ok() {
                let _ = std::fs::remove_file(path);
            }
            Ok(Self::Unix(UnixListener::bind(path)?))
        } else {
            let addr_parsed: std::net::SocketAddr = addr.parse()?;
            let socket = if addr_parsed.is_ipv6() {
                socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?
            } else {
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?
            };

            socket.set_reuse_address(true)?;
            #[cfg(not(windows))]
            socket.set_reuse_port(true)?;

            socket.set_nonblocking(true)?;
            socket.bind(&addr_parsed.into())?;
            socket.listen(1024)?;

            let std_listener: std::net::TcpListener = socket.into();
            Ok(Self::Tcp(TcpListener::from_std(std_listener)?))
        }
    }

    /// Accept one connection and return the stream together with a display
    /// string for the remote address.
    pub async fn accept(&self) -> std::io::Result<(InboundStream, crate::stats::ClientId)> {
        match self {
            BoundListener::Tcp(l) => {
                let (s, addr) = l.accept().await?;
                let _ = s.set_nodelay(true);
                Ok((InboundStream::Tcp(s), crate::stats::ClientId::Ip(addr.ip())))
            }
            BoundListener::Unix(l) => {
                let (s, _addr) = l.accept().await?;
                Ok((InboundStream::Unix(s), crate::stats::ClientId::Unix))
            }
        }
    }
}

// ─── Unified inbound stream ───────────────────────────────────────────────────

/// A raw (pre-TLS) stream accepted from a `BoundListener`.
pub enum InboundStream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

impl tokio::io::AsyncRead for InboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            InboundStream::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            InboundStream::Unix(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for InboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            InboundStream::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            InboundStream::Unix(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            InboundStream::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            InboundStream::Unix(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            InboundStream::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            InboundStream::Unix(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for InboundStream {}

#[cfg(target_os = "linux")]
impl crate::relay::AsRawStreamRef for InboundStream {
    fn as_raw_stream_ref(&self) -> Option<crate::relay::RawStreamRef<'_>> {
        match self {
            InboundStream::Tcp(s) => Some(crate::relay::RawStreamRef::Tcp(s)),
            InboundStream::Unix(s) => Some(crate::relay::RawStreamRef::Unix(s)),
        }
    }
}

// ─── Generic accept loop ──────────────────────────────────────────────────────

/// Drive `listener` until `cancel` fires, spawning `on_accept(stream, addr)`
/// for every incoming connection. The closure is called with a cloned context
/// each iteration (all captured `Arc`s are cheap to clone).
pub async fn run_accept_loop<F, Fut>(
    listener: BoundListener,
    cancel: CancellationToken,
    protocol: &'static str,
    on_accept: F,
) -> anyhow::Result<()>
where
    F: Fn(InboundStream, crate::stats::ClientId) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            res = listener.accept() => match res {
                Ok((stream, client_id)) => { tokio::spawn(on_accept(stream, client_id)); }
                Err(e) => { tracing::warn!(error = %e, "{protocol} accept error"); }
            }
        }
    }
    Ok(())
}

/// Consolidates high-performance routing and load-balanced/failover backend connection establishment.
///
/// When `route` is `Some`, uses route-specific candidates (bound to a group or backend).
/// When `route` is `None`, uses the global failover order.

/// Extract the parent domain (e.g. "example.com" from "sub.example.com") without allocation.
/// Returns a `&str` slice into the input — zero heap allocation.
pub fn extract_parent_domain_str(host: &str) -> &str {
    let bytes = host.as_bytes();
    let mut dot_count = 0u8;
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'.' {
            dot_count += 1;
            if dot_count == 2 {
                return &host[i + 1..];
            }
        }
    }
    host // single-label or two-label domain — return as-is
}

/// Hash the routing key for consistent-hashing without heap allocation.
fn hash_target_for_ch(target: &TargetAddr) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match target {
        TargetAddr::Ip(addr) => addr.ip().hash(&mut hasher),
        TargetAddr::Domain(host, _) => extract_parent_domain_str(host).hash(&mut hasher),
    }
    hasher.finish()
}

/// Extract parent domain as an owned String (used by stats path, not the routing hot path).
pub fn extract_parent_domain(target: &TargetAddr) -> String {
    match target {
        TargetAddr::Ip(addr) => addr.ip().to_string(),
        TargetAddr::Domain(host, _) => extract_parent_domain_str(host).to_string(),
    }
}

/// Compute the rotation start position for a subgroup (0 = no rotation).
fn compute_start(sg: &crate::scheduler::SubGroupCache, target: &TargetAddr) -> usize {
    use std::sync::atomic::Ordering;
    let len = sg.healthy.len();
    if len == 0 {
        return 0;
    }

    match sg.strategy {
        crate::config::GroupStrategy::ConsistentHashing if !sg.hash_ring.is_empty() => {
            let h = hash_target_for_ch(target);
            let idx = match sg.hash_ring.binary_search_by_key(&h, |(k, _)| *k) {
                Ok(i) => i,
                Err(i) => {
                    if i == sg.hash_ring.len() {
                        0
                    } else {
                        i
                    }
                }
            };
            sg.hash_ring[idx].1 % len
        }
        crate::config::GroupStrategy::WeightedRoundRobin if !sg.wrr_choices.is_empty() => {
            let count = WRR_COUNTER.fetch_add(1, Ordering::Relaxed);
            sg.wrr_choices[count % sg.wrr_choices.len()]
        }
        _ => 0,
    }
}

const MAX_INLINE_SUBGROUPS: usize = 16;

/// Zero-allocation iterator over candidates. Borrows from `CachedCandidates`
/// and yields `&(backend_idx, weight, Arc<BackendInfo>)` references — no
/// `Arc::clone()` per connection.
pub struct CandidateIter<'a> {
    subgroups: &'a [crate::scheduler::SubGroupCache],
    starts: [usize; MAX_INLINE_SUBGROUPS],
    sg_idx: usize,
    offset: usize,
}

impl<'a> CandidateIter<'a> {
    pub fn new(candidates: &'a crate::scheduler::CachedCandidates, target: &TargetAddr) -> Self {
        let count = candidates.subgroups.len().min(MAX_INLINE_SUBGROUPS);
        let mut starts = [0usize; MAX_INLINE_SUBGROUPS];
        for i in 0..count {
            starts[i] = compute_start(&candidates.subgroups[i], target);
        }
        CandidateIter {
            subgroups: &candidates.subgroups[..count],
            starts,
            sg_idx: 0,
            offset: 0,
        }
    }
}

impl<'a> Iterator for CandidateIter<'a> {
    type Item = &'a (usize, u32, Arc<crate::backend::BackendInfo>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.sg_idx >= self.subgroups.len() {
                return None;
            }
            let sg = &self.subgroups[self.sg_idx];
            let len = sg.healthy.len();
            if len == 0 || self.offset >= len {
                self.sg_idx += 1;
                self.offset = 0;
                continue;
            }
            let pos = (self.starts[self.sg_idx] + self.offset) % len;
            self.offset += 1;
            return Some(&sg.healthy[pos]);
        }
    }
}

pub async fn route_and_connect(
    pool: &crate::backend::BackendPool,
    target: &TargetAddr,
    route_idx: Option<usize>,
) -> Result<
    (
        crate::outbound::BackendStream,
        Arc<crate::backend::TrafficCounters>,
    ),
    anyhow::Error,
> {
    use crate::outbound::{
        BackendStream, direct_connect, socks5h_connect, socks5h_connect_target, ss_connect_fresh,
        ss_connect_pooled,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let backend_timeout = Duration::from_secs(10);

    // Use route-specific candidates if a route is bound, otherwise global.
    let candidates = pool.get_route_candidates(route_idx);
    let unhealthy = &candidates.unhealthy;

    let mut backend_stream: Option<crate::outbound::BackendStream> = None;
    let mut chosen_traffic: Option<Arc<crate::backend::TrafficCounters>> = None;

    let iter = CandidateIter::new(&candidates, target);

    // First pass: try healthy backends.
    for (index, _, info) in iter {
        // Lock-free cache lookup: yields both the pooled stream (if any) and the traffic Arc.
        let pc = pool.get_pooled_connection(*index);
        let (pool_stream, traffic) = match pc {
            Some(pc) => (pc.stream, Some(pc.traffic)),
            None => (None, None), // OOB — never happens
        };

        let conn_res: std::io::Result<BackendStream> = if info.is_direct() {
            // ── Direct backend ─────────────────────────────────────────────
            if let Some(ref tc) = traffic {
                tc.pool_misses.fetch_add(1, Ordering::Relaxed);
            }
            direct_connect(target, backend_timeout, info.bind_interface.as_deref()).await
        } else if info.is_shadowsocks() {
            // ── Shadowsocks backend ────────────────────────────────────────
            let ss_cfg = info.ss_config.as_ref().unwrap();
            let ss_ctx = info.ss_context.as_ref().unwrap().clone();

            match pool_stream {
                Some(stream) => {
                    // Pool hit: wrap the pre-established stream.
                    tracing::debug!(backend = %info.name, "SS: using pooled connection");
                    if let Some(ref tc) = traffic {
                        tc.pool_hits.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(ss_connect_pooled(stream, ss_cfg, ss_ctx, target))
                }
                None => {
                    // Pool miss: open a fresh connection.
                    if let Some(ref tc) = traffic {
                        tc.pool_misses.fetch_add(1, Ordering::Relaxed);
                    }
                    ss_connect_fresh(info, ss_cfg, ss_ctx, target, backend_timeout).await
                }
            }
        } else {
            // ── SOCKS5 backend ─────────────────────────────────────────
            match pool_stream {
                Some(stream) => {
                    tracing::debug!(backend = %info.name, "using pooled connection");
                    match socks5h_connect_target(stream, target).await {
                        Ok(s) => {
                            if let Some(ref tc) = traffic {
                                tc.pool_hits.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(s)
                        }
                        Err(e) => {
                            if let Some(ref tc) = traffic {
                                tc.pool_stale.fetch_add(1, Ordering::Relaxed);
                            }
                            tracing::debug!(
                                backend = %info.name,
                                error = %e,
                                "pooled connection was stale, retrying with fresh connection"
                            );
                            socks5h_connect(info, target, backend_timeout).await
                        }
                    }
                }
                None => {
                    if let Some(ref tc) = traffic {
                        tc.pool_misses.fetch_add(1, Ordering::Relaxed);
                    }
                    socks5h_connect(info, target, backend_timeout).await
                }
            }
        };

        match conn_res {
            Ok(stream) => {
                tracing::debug!(backend = %info.name, target = %target, "connected through backend");
                backend_stream = Some(stream);
                chosen_traffic = traffic;
                break;
            }
            Err(e) => {
                tracing::debug!(backend = %info.name, error = %e, "backend connect failed, trying next");
                pool.mark_unhealthy(*index, &format!("connect failed: {}", e));
            }
        }
    }

    // Second pass: try unhealthy backends as last resort.
    if backend_stream.is_none() {
        for (index, _, info) in unhealthy {
            let result: std::io::Result<BackendStream> = if info.is_direct() {
                direct_connect(target, backend_timeout, info.bind_interface.as_deref()).await
            } else if info.is_shadowsocks() {
                let ss_cfg = info.ss_config.as_ref().unwrap();
                let ss_ctx = info.ss_context.as_ref().unwrap().clone();
                ss_connect_fresh(info, ss_cfg, ss_ctx, target, backend_timeout).await
            } else {
                socks5h_connect(info, target, backend_timeout).await
            };

            if let Ok(stream) = result {
                tracing::debug!(backend = %info.name, target = %target, "connected through unhealthy backend (fallback)");
                backend_stream = Some(stream);
                chosen_traffic = pool.get_traffic_counters(*index);
                break;
            }
        }
    }

    if let (Some(stream), Some(traffic)) = (backend_stream, chosen_traffic) {
        Ok((stream, traffic))
    } else {
        anyhow::bail!("all backends failed for {}", target)
    }
}

pub async fn route_and_connect_udp(
    pool: &crate::backend::BackendPool,
    target: &TargetAddr,
    route_idx: Option<usize>,
) -> Result<
    (
        crate::udp::UdpBackendSession,
        std::sync::Arc<crate::backend::TrafficCounters>,
    ),
    anyhow::Error,
> {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let backend_timeout = Duration::from_secs(10);
    let candidates = pool.get_route_candidates(route_idx);
    let iter = CandidateIter::new(&candidates, target);

    for (index, _, info) in iter {
        if !info.udp_enabled {
            continue;
        }

        let traffic = pool.get_traffic_counters(*index).unwrap_or_default();

        if info.is_direct() {
            if let Some(ref tc) = pool.get_traffic_counters(*index) {
                tc.pool_misses.fetch_add(1, Ordering::Relaxed);
            }
            if let Ok(socket) = crate::udp::create_tuned_udp_socket() {
                return Ok((crate::udp::UdpBackendSession::Direct { socket }, traffic));
            }
        } else if info.is_shadowsocks() {
            let ss_cfg = info.ss_config.as_ref().unwrap();
            let ss_ctx = info.ss_context.as_ref().unwrap().clone();
            if let Ok(socket) =
                ::shadowsocks::relay::udprelay::ProxySocket::connect(ss_ctx, ss_cfg.as_ref()).await
            {
                let server_addr = match ss_cfg.addr() {
                    ::shadowsocks::config::ServerAddr::SocketAddr(sa) => *sa,
                    ::shadowsocks::config::ServerAddr::DomainName(domain, port) => {
                        if let Ok(mut addrs) =
                            tokio::net::lookup_host((domain.as_str(), *port)).await
                        {
                            if let Some(addr) = addrs.next() {
                                addr
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                };
                return Ok((
                    crate::udp::UdpBackendSession::Shadowsocks {
                        socket,
                        server_addr,
                    },
                    traffic,
                ));
            }
        } else {
            // SOCKS5
            if let Ok(tcp_stream) = crate::outbound::connect_endpoint(info, backend_timeout).await {
                if let Ok(tcp_stream) =
                    crate::outbound::socks5::socks5h_authenticate(tcp_stream, info).await
                {
                    if let Ok((tcp_stream, backend_relay_addr)) =
                        crate::outbound::socks5::socks5h_udp_associate(tcp_stream).await
                    {
                        if let Ok(socket) = crate::udp::create_tuned_udp_socket() {
                            return Ok((
                                crate::udp::UdpBackendSession::Socks5 {
                                    socket,
                                    backend_relay_addr,
                                    _tcp: tokio::sync::Mutex::new(
                                        crate::outbound::BackendStream::boxed(Box::pin(tcp_stream)),
                                    ),
                                },
                                traffic,
                            ));
                        }
                    }
                }
            }
        }
    }

    anyhow::bail!("all UDP backends failed for {}", target)
}

/// High-performance bidirectional relay with unified traffic counter tracking and clean stream shutdown.
///
/// After the relay completes, both streams are handed off to the fd-closer thread
/// (via [`crate::relay::defer_drop`]) so that `close(2)` / TCP teardown for both
/// the inbound client socket and the backend socket never runs on a tokio worker thread.
pub async fn relay_and_track<I>(
    mut inbound_stream: I,
    mut backend_stream: crate::outbound::BackendStream,
    traffic: Arc<crate::backend::TrafficCounters>,
    inbound_stats: Option<Arc<crate::backend::InboundStats>>,
    client_id: crate::stats::ClientId,
    target: &TargetAddr,
    protocol_name: &str,
    pool: &crate::backend::BackendPool,
) -> Result<(), anyhow::Error>
where
    I: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + Unpin
        + crate::relay::AsRawStreamRef
        + Send
        + 'static,
{
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncWriteExt;

    traffic.total_connections.fetch_add(1, Ordering::Relaxed);
    traffic.active_connections.fetch_add(1, Ordering::Relaxed);
    if let Some(ref stats) = inbound_stats {
        stats.total_connections.fetch_add(1, Ordering::Relaxed);
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    let domain = extract_parent_domain(target);
    let domain_stats = pool.domain_manager.get_or_create(&domain);
    let client_stats = pool.client_manager.get_or_create(&client_id);

    domain_stats
        .total_connections
        .fetch_add(1, Ordering::Relaxed);
    client_stats
        .total_connections
        .fetch_add(1, Ordering::Relaxed);

    let mut up_counters = vec![
        &traffic.bytes_up,
        &domain_stats.tx_bytes,
        &client_stats.tx_bytes,
    ];
    let mut down_counters = vec![
        &traffic.bytes_down,
        &domain_stats.rx_bytes,
        &client_stats.rx_bytes,
    ];
    if let Some(ref stats) = inbound_stats {
        up_counters.push(&stats.tx_bytes);
        down_counters.push(&stats.rx_bytes);
    }

    match crate::relay::relay(
        &mut inbound_stream,
        &mut backend_stream,
        up_counters,
        down_counters,
    )
    .await
    {
        Ok((up, down)) => {
            tracing::debug!(
                target = %target,
                up_bytes = up,
                down_bytes = down,
                "{} relay complete",
                protocol_name
            );
            // Counters were already incrementally updated in real-time by the relay.
        }
        Err(e) => {
            tracing::debug!(
                target = %target,
                error = %e,
                "{} relay error",
                protocol_name
            );
        }
    }

    traffic.active_connections.fetch_sub(1, Ordering::Relaxed);
    if let Some(ref stats) = inbound_stats {
        stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    // Flush the write-halves so peers see a clean EOF before we release the FDs.
    let _ = inbound_stream.shutdown().await;
    let _ = backend_stream.shutdown().await;

    // Defer both close(2) calls to the fd-closer thread — off the worker runtime.
    crate::relay::defer_drop(inbound_stream);
    crate::relay::defer_drop(backend_stream);

    Ok(())
}

/// Helper function to check if a target address points to a private/loopback address.
#[allow(dead_code)]
pub fn is_private_target_sync(target: &crate::outbound::TargetAddr) -> bool {
    match target {
        crate::outbound::TargetAddr::Ip(addr) => is_private_ip(addr.ip()),
        crate::outbound::TargetAddr::Domain(host, _port) => {
            let host_lower = host.to_lowercase();
            host_lower == "localhost" || host_lower.ends_with(".local")
        }
    }
}

/// Helper function to check if an IpAddr is private or loopback/local.
#[allow(dead_code)]
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_unspecified()
                || ipv4.is_broadcast()
        }
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || is_ipv6_unique_local(&ipv6)
                || is_ipv6_link_local(&ipv6)
        }
    }
}

#[allow(dead_code)]
fn is_ipv6_unique_local(ipv6: &std::net::Ipv6Addr) -> bool {
    (ipv6.octets()[0] & 0xfe) == 0xfc
}

#[allow(dead_code)]
fn is_ipv6_link_local(ipv6: &std::net::Ipv6Addr) -> bool {
    (ipv6.octets()[0] == 0xfe) && ((ipv6.octets()[1] & 0xc0) == 0x80)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1
        )))); // ::1
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        )))); // fc00::1

        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_private_target() {
        let t1 = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80));
        assert!(is_private_target_sync(&t1));

        let t2 = TargetAddr::Domain("localhost".to_string(), 80);
        assert!(is_private_target_sync(&t2));

        let t3 = TargetAddr::Domain("some-service.local".to_string(), 80);
        assert!(is_private_target_sync(&t3));

        let t4 = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80));
        assert!(!is_private_target_sync(&t4));
    }
}
