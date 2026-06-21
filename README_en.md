# ProxyLB

[English](README_en.md) | [简体中文](README.md)

A high-performance proxy load balancer written in Rust. It supports SOCKS5, Shadowsocks, HTTP, and MTProto inbound protocols. ProxyLB provides advanced load balancing, health checks, and zero-downtime config reloads.

![web](./web/web.jpg)

---

## 🛠️ Features

### Protocols & Transport
- **Inbound:** SOCKS5 (TCP/UDS, auth, TLS), Shadowsocks (AEAD ciphers), HTTP (`CONNECT` tunnel, `GET` proxy, Basic Auth, TLS), and MTProto (FakeTLS for Telegram).
- **Outbound:** Direct, SOCKS5h (TCP/UDS), and Shadowsocks.
- **Transport Layer:** Both inbound and outbound connections support TCP and Unix Domain Sockets (UDS).

### Routing & Load Balancing
- **Hierarchical Routing:** Bind specific inbounds to nested backend groups.
- **Routing Strategies:**
  - `failover` — Uses the first healthy backend.
  - `urltest` — Routes to the backend with the lowest latency.
  - `loadbalance` — Routes to the backend with the fewest active connections.
- **Global Fallback:** Any inbound without an explicit route uses the global `failover_order`.

### Operations
- **Zero-Downtime Reload:** Send `SIGHUP` to reload configurations without dropping active sessions.
- **Network Awareness:** Automatically triggers reprobes when link or gateway changes are detected.
- **Web Dashboard & API:** Real-time visibility into traffic, backend latency, and connections.
- **Built-in AdBlock:** Periodically fetches and updates AdGuard/Hosts blocklists in the background.

---

## ⚡ Performance

ProxyLB is optimized for throughput and low latency:

- **Zero-Copy Relay:** Uses Linux `splice(2)` for kernel-level data transfer, bypassing userspace entirely.
- **Pre-warmed Connection Pools:** Handshakes with outbounds are completed in the background so the hot-path latency is kept minimal.
- **Lock-free Architecture:** Relies on atomics and `ArcSwap` to prevent thread contention.
- **Dedicated CPU Runtimes:** Forwarding threads and background tasks are pinned to specific CPU cores.
- **jemalloc:** Uses the `jemalloc` memory allocator optimized for concurrency.

### Benchmarks

Tested on a Debian 13 guest via Parallels Desktop on macOS 14 (M3 Macbook Air).
*Parameters: 1 worker core (CPU-pinned) · pool_size=5 · 300 concurrent clients · 10s duration*

| Inbound | Connections Per Second (CPS) |
|---------|------------------------------|
| **UDS** | **~37,485** |
| **TCP** | **~15,346** |

ProxyLB can handle tens of thousands of connections per second on a single core.

---

## 🛠️ Usage Scenarios

### Scenario 1: Reliable Proxy Gateway

A common use case is running proxy clients like `sing-box`, `hysteria`, or `mihomo` connected to various VPS nodes, and putting ProxyLB in front of them as a unified, highly reliable SOCKS5 or Shadowsocks entry point.

**Deployment Options:**
- **Distributed Deployment:** Run ProxyLB on a stable public cloud server. It routes traffic through WireGuard to a home server running `sing-box`/`hysteria`. ProxyLB's connection pool effectively hides the handshake latency to the home server.
- **Local Deployment (UDS):** Run ProxyLB and `sing-box` on the same router. They communicate via Unix Domain Sockets (UDS), bypassing the network protocol stack entirely for better performance. You can use `frp` to expose ProxyLB's UDS inbound to the public internet for remote access, while your local devices connect to its local SOCKS5 port.

*(Note: The official `sing-box` and `hysteria` do not support UDS natively. You can use modified versions that add UDS support: [sing-box](https://github.com/chandler0149/sing-box) and [hysteria](https://github.com/chandler0149/hysteria)).*

### Scenario 2: Multi-Protocol Load Balancing

ProxyLB can route different inbound protocols to specific backend groups.

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
    backends: ["ss-hk-1"]
  - name: "us-fallback"
    strategy: "failover"
    backends: ["socks-us-1", "direct-out"]
  
  # Nested group (incorporating other groups as backends)
  - name: "telegram-group"
    strategy: "failover"
    backends: ["asia-group", "us-fallback"]

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
./target/release/proxylb -c config.yaml

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
