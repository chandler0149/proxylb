# ProxyLB

[English](README.md) | [简体中文](README_zh.md)

ProxyLB is an ultra-high-performance, feature-rich proxy load balancer and traffic router written in Rust. It acts as an intermediary gateway supporting SOCKS5, Shadowsocks, and HTTP inbound protocols, routing client traffic through a pool of configurable outbound backends with advanced load balancing strategies, real-time health checks, zero-downtime hot reloading, and built-in domain filtering.

![web](./web/web.jpg)

---

## ⚡ Performance Architecture

ProxyLB is engineered from the ground up for high throughput, minimal overhead, and predictable low latency:

*   **Lockless Hot-Path Forwarding**: Data relaying between clients and backends operates entirely lock-free. Once a route is established, data packets bypass all control-plane locks (such as RwLocks or Mutexes), utilizing high-speed tokio-assisted asynchronous pipelines.
*   **Dedicated CPU Affinity Pinning**: 
    *   **Worker Cores**: Heavy-lifting I/O relay tasks are pinned to dedicated CPU cores (`worker_cores`). Thread names are prefixed with `proxylb-worker` to guarantee strict isolation.
    *   **Ancillary Cores**: Background management tasks (health checking, connection pool refilling, AdBlock updates, REST API server, and netlink watchers) are isolated to separate CPU cores (`ancillary_cores`) via a dedicated tokio runtime. This ensures that control plane overhead never interrupts or adds latency to the hot forwarding path.
*   **Pre-Authenticated Connection Pooling**: To eliminate SOCKS5/Shadowsocks handshake latency, ProxyLB maintains a background connection pool for each backend. When a client connects, a pre-handshaked connection is popped from the pool instantly, converting outbound connection latency to near-zero.
*   **High-Speed AdBlock Trie Matcher**: Utilizes a highly optimized domain suffix-matching Trie to evaluate blocker rules and exceptions (whitelist overrides). The engine is benchmarked to handle millions of queries per second with sub-nanosecond lookups.

---

## 🛠️ Core Functionality

### Inbound Protocols
*   **SOCKS5 Inbound**: Supports standard SOCKS5 authentication and TCP forwarding. Can listen on TCP ports or Unix Domain Sockets (e.g. `unix:///tmp/socks.sock`).
*   **Shadowsocks Inbound**: Standard Shadowsocks server supporting multiple modern encryption ciphers (e.g., `aes-256-gcm`, `chacha20-ietf-poly1305`).
*   **HTTP Inbound**: Fully featured HTTP/1.1 proxy supporting both relative and absolute GET requests as well as CONNECT tunneling.

### Outbound Backends & Grouping
*   **Supported Outbound Protocols**: Direct connection, SOCKS5h over TCP, SOCKS5h over Unix Domain Sockets, and Shadowsocks.
*   **Hierarchical Grouping**: Group backends and apply customized routing policies. Groups can be referenced directly in the global failover sequence.
*   **Advanced Load Balancing Strategies**:
    *   `failover`: Routes to the first healthy backend in the list.
    *   `urltest`: Dynamically monitors latency and routes traffic to the backend with the lowest response time.
    *   `loadbalance`: Distributes connections based on least historical and active connections.

### Resilience & Control
*   **Zero-Downtime Hot Reload**: Triggered via `SIGHUP`. Reloads the configuration, constructs new connection pools, and updates route tables gracefully without dropping active client connections.
*   **Dynamic Network Watcher**: Monitors routing socket events (Netlink on Linux, Route Sockets on macOS). Instantly triggers a health check probe upon physical link or default gateway changes to route around failed connections immediately.
*   **Web Dashboard & REST API**: Real-time traffic metrics, active connection counts, memory stats, and per-backend latency logs. The API can listen on a TCP port or a Unix Domain Socket (e.g., `unix:///tmp/api.sock`).
*   **Security & Protection**:
    *   **Private Address Filter**: Blocks forwarding to private/internal IPs (RFC 1918) through proxy backends to protect local networks.
    *   **AdBlock Engine**: AdGuard / Hosts style lists parsed and updated periodically in the background.

---

## ⚙️ Configuration Example

Below is a robust example of `config.yaml` showing inbound listeners, backends, grouping strategies, CPU pinning, and AdBlock configurations:

```yaml
# Inbound listeners configuration
inbounds:
  - type: socks5
    listen: "127.0.0.1:1080"
  - type: http
    listen: "127.0.0.1:8080"
  - type: shadowsocks
    listen: "127.0.0.1:8388"
    password: "securepassword"
    method: "chacha20-ietf-poly1305"

# Outbound backend servers
backends:
  - name: "direct-out"
    type: "direct"
  - name: "socks-us-1"
    type: "socks5"
    address: "12.34.56.78:1080"
    username: "user"
    password: "pass"
    pool_size: 10
  - name: "ss-hk-1"
    type: "shadowsocks"
    address: "88.99.11.22:8388"
    username: "chacha20-ietf-poly1305"
    password: "backendpassword"
    pool_size: 15

# Hierarchical groups and strategies
groups:
  - name: "asia-group"
    strategy: "urltest" # Dynamically route to lowest latency
    backends:
      - "ss-hk-1"
  - name: "failover-pool"
    strategy: "failover"
    backends:
      - "socks-us-1"
      - "direct-out"

# Global priority failover order
failover_order:
  - "asia-group"
  - "failover-pool"

# Health check intervals
health_check:
  interval_secs: 10
  timeout_secs: 5
  check_target: "http://www.gstatic.com/generate_204"

# Web Status Dashboard API
web:
  enabled: true
  listen: "unix:///tmp/api.sock" # Or TCP address, e.g. "127.0.0.1:9090"

# CPU Affinity & Thread Isolation Settings
cpu_affinity:
  worker_cores: [0, 1]      # Pinned core IDs for proxy forwarding (hot path)
  ancillary_cores: [2]      # Pinned core IDs for background/health tasks

# Domain filtering (AdBlock)
adblock:
  enabled: true
  backend: "direct-out"     # Backend used to download lists
  update_interval_hours: 24
  urls:
    - "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  files:
    - "/etc/proxylb/custom_rules.txt"
```

---

## 🚀 Getting Started

### Prerequisites
*   Rust toolchain (Stable 1.75+)

### Compilation & Execution
```bash
# Build release version
cargo build --release

# Run ProxyLB with a configuration file
./target/release/proxylb -c config.yaml
```

### Hot Reload
To apply configuration changes on the fly without restarting the service or interrupting active connections:
```bash
kill -SIGHUP $(pgrep proxylb)
```
