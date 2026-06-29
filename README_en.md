# ProxyLB

[English](README_en.md) | [简体中文](README.md)

High-performance proxy load balancer written in Rust. Supports SOCKS5, Shadowsocks, HTTP, and MTProto inbound protocols, with built-in load balancing, health checks, and zero-downtime config reloads.

![web](./web/web.jpg)

---

## 🛠️ Features

### Protocols & Transport
- **Inbound:** SOCKS5 (TCP/UDS/UDP, auth, TLS), Shadowsocks (TCP/UDP, AEAD ciphers), HTTP (`CONNECT` tunnel, `GET` proxy, Basic Auth, TLS), and MTProto (FakeTLS for Telegram).
- **Outbound:** Direct, SOCKS5h (TCP/UDS/UDP), and Shadowsocks (TCP/UDP).
- **Transport Layer:** TCP, UDP, and Unix Domain Sockets (UDS) for both inbound and outbound.

### Routing & Load Balancing
- **Hierarchical Routing:** Bind specific inbounds to nested backend groups; groups can reference each other.
- **Routing Strategies:**
  - `failover` — Uses the first healthy backend in configured order.
  - `urltest` — Routes to the backend with the lowest health-check latency.
  - `loadbalance` — Routes to the backend with the fewest active connections.
  - `consistent_hashing` — Consistent hashing for sticky domain-based routing; backend changes only remap a minimal set of keys.
  - `weighted_round_robin` — Distributes traffic proportionally by weight using the Nginx smooth weighted round-robin algorithm. Supports per-member `weight` configuration.
- **Global Fallback:** Any inbound without an explicit route uses the global `failover_order`. Internal group strategies are fully preserved (e.g., a WRR group inside `failover_order` still distributes by weight).

### Operations
- **Subcommand CLI:** Use standard CLI subcommands (e.g., `proxylb run -c config.yaml`).
- **Zero-Downtime Reload:** Send `SIGHUP` to reload configurations without dropping active sessions.
- **Network Awareness:** Automatically reprobes when link or gateway changes are detected.
- **Embedded Web Dashboard:** A zero-dependency React Web UI compiled directly into the binary, featuring real-time bandwidth time-series charts, client tracking, and backend latency metrics. See [REST API Documentation](./restapi.md).
- **Built-in AdBlock:** Periodically fetches and updates AdGuard/Hosts blocklists (disabled by default for zero-overhead routing).

---

## ⚡ Performance

ProxyLB is built for maximum throughput and low latency:

- **Zero-Copy Relay:** Uses Linux `splice(2)` to bypass userspace for unencrypted connections. Encrypted relays use optimized buffer manipulation.
- **Pre-warmed Connection Pools:** Background out-of-band handshakes keep hot-path latency minimal.
- **Lock-Free Hot-Path:** Uses atomics and `ArcSwap` to prevent thread contention. Zero policy calculation on the hot-path.
- **Dedicated CPU Runtimes:** Forwarding threads and background tasks are pinned to specific CPU cores.
- **jemalloc:** Uses the `jemalloc` memory allocator optimized for concurrency.
- **Profile-Guided Optimization (PGO):** Integrated PGO pipeline in Makefile (`make pgo`) to generate workload-specific optimized binaries.

### Benchmarks

Tested on a Debian 13 guest via Parallels Desktop on macOS 14 (M3 Macbook Air).
*Parameters: 1 worker core (CPU-pinned) · pool_size=5 · 300 concurrent clients · 10s duration*

| Inbound | Connections Per Second (CPS) |
|---------|------------------------------|
| **UDS** | **~37,485** |
| **TCP** | **~15,346** |

ProxyLB handles tens of thousands of connections per second on a single core.

---

## 🛠️ Usage Scenarios

### Scenario 1: Reliable Proxy Gateway

Deploy ProxyLB as a unified SOCKS5/Shadowsocks entry point in front of local proxy clients like `sing-box`, `hysteria`, or `mihomo`.

**Deployment Options:**
- **Distributed Deployment:** Run ProxyLB on a public cloud server, routing traffic through WireGuard to a home server running `sing-box`/`hysteria`. ProxyLB's connection pool hides the handshake latency to the home server.
- **Local Deployment (UDS):** Run ProxyLB and `sing-box` on the same router. They communicate via Unix Domain Sockets (UDS), bypassing the network stack for better performance. Use `frp` to expose ProxyLB's UDS inbound to the public internet for remote access, while local devices connect to its local SOCKS5 port.

*(Note: The official `sing-box` and `hysteria` do not natively support UDS. Use modified versions with UDS support: [sing-box](https://github.com/chandler0149/sing-box) and [hysteria](https://github.com/chandler0149/hysteria)).*

### Scenario 2: Multi-Protocol Load Balancing

Route different inbound protocols to specific backend groups.

```text
    [ Inbounds ]                                   [ ProxyLB Routing ]                          [ Backends ]

                  |                                                                             +----------+
    Shadowsocks   |                                   +------------------+                      |          |
    (route: asia) +-------------+               +---->| Group: Asia      |--------------------->| sing-box |-->
                  |             |               |     | (urltest)        |                      |          |
                  |             |               |     +------------------+                      +----------+
                  |             |               |
                  |         +---+-----+         |                                               +----------+
    SOCKS5        |         |         |         |     +------------------+                      |          |
    (no route)    +-------->|         |---------+---->| Global Fallback  |--------------------->| hysteria |-->
--------------------------->| ProxyLB |         |     | (failover)       |                      |          |
                  +-------->|         |---------+     +------------------+                      +----------+
                  |         |         |         |              ^
    HTTP          |         +---+-----+         |              |
    (no route)    |             |               |              | (nested fallback)
                  |             |               |     +--------+---------+                      +----------+
                  |             |               |     | Group: Telegram  |                      |          |
    MTProto       |             +---------------+---->| (failover)       |--------------------->| sing-box |-->
    (route: tg)   |                                   +------------------+                      |          |
                  |                                                                             +----------+
```

---

## ⚙️ Configuration

```yaml
inbounds:
  - type: socks5
    listen: "127.0.0.1:1080"
  - type: http
    listen: "127.0.0.1:8080"
  - type: mtproto
    listen: "0.0.0.0:8443"
    password: "00000000000000000000000000000000"
    route: "telegram-group"  # Bind this inbound to a specific nested group
  - type: shadowsocks
    listen: "127.0.0.1:8388"
    password: "securepassword"
    method: "chacha20-ietf-poly1305"
    route: "telegram-group"

backends:
  - name: "direct-out"
    type: "direct"
    force_healthy: true
  - name: "socks-us-1"
    type: "socks5"
    address: "12.34.56.78:1080"
    username: "user"
    password: "pass"
    pool_size: 10
  - name: "ss-hk-1"
    type: "shadowsocks"
    address: "88.99.11.22:8388"
    password: "backendpassword"
    method: "chacha20-ietf-poly1305"
    pool_size: 15

groups:
  # Sub-groups
  - name: "asia-group"
    strategy: "urltest"
    members: ["ss-hk-1"]
  - name: "us-fallback"
    strategy: "failover"
    members: ["socks-us-1", "direct-out"]
  
  # Weighted round robin group
  - name: "weighted-group"
    strategy: "weighted_round_robin"
    members:
      - name: "asia-group"
        weight: 5
      - name: "us-fallback"
        weight: 1

  # Nested group (incorporating other groups as members)
  - name: "telegram-group"
    strategy: "failover"
    members: ["asia-group", "us-fallback"]

failover_order: ["asia-group", "us-fallback"]

health_check:
  interval_secs: 10
  timeout_secs: 5
  check_target: "http://www.gstatic.com/generate_204"

web:
  enabled: true
  listen: "0.0.0.0:9090"

# Pin forwarding threads to cores 0-1, background tasks to core 2
cpu_affinity:
  worker_cores: [0, 1]
  ancillary_cores: [2]

advanced:
  zero_copy: true   # splice(2) on Linux, default on
```

---

## 🚀 Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/proxylb run -c config.yaml

# Hot reload (no dropped connections)
kill -SIGHUP $(pgrep proxylb)

# Benchmark
make bench
```

---

## 🐳 Docker

```bash
docker build -t proxylb .
docker run -v $(pwd)/config.yaml:/config.yaml proxylb
```

---

## 📄 License

[GPL-3.0](LICENSE)
