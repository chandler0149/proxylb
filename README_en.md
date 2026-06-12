# ProxyLB

[English](README_en.md) | [简体中文](README.md)

ProxyLB is an ultra-high-performance proxy load balancer and traffic router written in Rust. It acts as an intermediary gateway supporting SOCKS5, Shadowsocks, and HTTP inbound protocols, routing client traffic through a pool of configurable outbound backends with advanced load balancing, real-time health checks, zero-downtime hot reloading, and built-in domain filtering.

![web](./web/web.jpg)

---

## ⚡ Performance

```bash
root@dev:~/code/gfw/proxylb# uname -a
Linux dev 6.12.85+deb13-arm64 #1 SMP Debian 6.12.85-1 (2026-04-30) aarch64 GNU/Linux
```

> **Measured on a single machine — 2 worker cores (pinned), pool_size = 5, 300 concurrent clients, 10 s window:**
>
> | Metric | Result |
> |---|---|
> | Connections per second (CPS) | **14,669** |
> | Failed connections | **0** |
> | Benchmark tool | Rust `benchmark_cps` (bundled) |

ProxyLB is engineered from the ground up for high throughput, minimal overhead, and predictable low latency. Every design decision in the data path is motivated by eliminating unnecessary work:

### Zero-Copy `splice(2)` relay (Linux)

On Linux, the hot relay path uses `splice(2)` to move data between the client socket and the backend socket **without ever copying bytes into user space**. The kernel transfers data directly between file descriptors through an intermediate pipe, saving two memory copies per direction and removing the associated CPU and cache pressure entirely.

Pipe file descriptors are **pre-allocated at connection-pool fill time** and attached to pooled backend streams so there is zero syscall overhead on the critical path when a client hits a pool hit.

The fallback for non-Linux targets or non-TCP streams is `tokio::io::copy_bidirectional`, which is itself highly efficient.

### Lock-free hot path

Once a route is established, the entire relay loop is lock-free. No `Mutex` or `RwLock` is held during data transfer. The connection pool lookup is a single atomic read from a pre-built snapshot that is swapped out only when health state changes — entirely off the hot path.

### Pre-authenticated connection pooling

Every SOCKS5 / Shadowsocks backend maintains a background connection pool. Workers continuously fill the pool with **pre-handshaked, ready-to-use connections**. When a client connects, a pooled connection is popped atomically — the outbound connection latency is effectively zero. Pool misses (cold connections) still work but fall back to a fresh dial.

### Dedicated CPU affinity pinning

Two separate tokio runtimes keep the control plane and data plane from interfering:

| Runtime thread | Pinned to | What runs there |
|---|---|---|
| `proxylb-worker` | `worker_cores` | inbound accept, relay, all I/O |
| `proxylb-ancillary` | `ancillary_cores` | health checks, pool refill, adblock, web API, netlink |

This prevents health-check or stats collection jitter from ever adding latency to the forwarding path.

### jemalloc allocator

ProxyLB uses **jemalloc** (`tikv-jemallocator`) as the global allocator. Compared to glibc `malloc`, jemalloc reduces memory fragmentation and lock contention under the high-allocation, high-concurrency workload of a proxy server.

### High-speed adblock trie

The domain filter uses a **compressed suffix-matching trie** evaluated at sub-nanosecond latency. At 300 CPS sustained, the trie adds immeasurable overhead even with millions of rules loaded.

---

## 🛠️ Core Features

### Inbound protocols
- **SOCKS5** — TCP or Unix domain socket (`unix:///tmp/socks.sock`), optional username/password auth, optional TLS
- **Shadowsocks** — AEAD ciphers (`aes-256-gcm`, `chacha20-ietf-poly1305`, …), TCP or UDS
- **HTTP** — HTTP/1.1 proxy: `CONNECT` tunnel + absolute/relative `GET`, optional Basic Auth, optional TLS

### Outbound backends & grouping
- **Protocols**: Direct, SOCKS5h over TCP, SOCKS5h over UDS, Shadowsocks
- **Hierarchical groups** with per-group strategies:
  - `failover` — first healthy backend wins
  - `urltest` — lowest-latency backend wins (measured continuously)
  - `loadbalance` — fewest active connections wins

### Resilience & control
- **Zero-downtime hot reload** via `SIGHUP` — rewires backends without dropping active sessions
- **Dynamic network watcher** — Netlink (Linux) / Route Sockets (macOS) trigger immediate re-probe on link or gateway changes
- **Web dashboard + REST API** — real-time traffic metrics, per-backend latency, active connections; listens on TCP or UDS
- **Private address filter** — blocks RFC 1918 targets to protect local networks
- **AdBlock engine** — AdGuard/Hosts-format lists fetched and refreshed in background

---

## ⚙️ Configuration Example

```yaml
# Inbound listeners
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
    pool_size: 10          # pre-authenticated connections kept ready
  - name: "ss-hk-1"
    type: "shadowsocks"
    address: "88.99.11.22:8388"
    password: "backendpassword"
    method: "chacha20-ietf-poly1305"
    pool_size: 15

# Hierarchical groups and strategies
groups:
  - name: "asia-group"
    strategy: "urltest"    # route to lowest-latency backend dynamically
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

# Health check
health_check:
  interval_secs: 10
  timeout_secs: 5
  check_target: "http://www.gstatic.com/generate_204"

# Web dashboard / REST API
web:
  enabled: true
  listen: "unix:///tmp/api.sock"   # or e.g. "127.0.0.1:9090"

# CPU affinity — keep data plane and control plane on separate cores
cpu_affinity:
  worker_cores: [0, 1]      # relay & accept threads
  ancillary_cores: [2]      # health check, pool refill, adblock, API

# Domain filtering (AdBlock)
adblock:
  enabled: true
  backend: "direct-out"
  update_interval_hours: 24
  urls:
    - "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  files:
    - "/etc/proxylb/custom_rules.txt"

# Performance tuning
advanced:
  zero_copy: true           # enable splice(2) on Linux (default: true)
```

---

## 🚀 Getting Started

### Prerequisites
- Rust toolchain (stable 1.75+)

### Build & run
```bash
# Build optimised release binary
cargo build --release

# Run with your config
./target/release/proxylb -c config.yaml

# Apply config changes without restarting
kill -SIGHUP $(pgrep proxylb)
```

### Run the benchmark
```bash
make bench
```

The bundled benchmark (`benchmark_cps`) spawns a Rust SOCKS5 mock backend on a dedicated core and a multi-threaded client firing 300 concurrent connections for 10 seconds, reporting total CPS and failure rate.

---

## 🐳 Docker

```bash
docker build -t proxylb .
docker run -v $(pwd)/config.yaml:/config.yaml proxylb
```

---

## 📄 License

[GPL-3.0](LICENSE)
