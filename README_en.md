# ProxyLB

[English](README_en.md) | [简体中文](README.md)

A high-performance proxy load balancer written in Rust. Supports SOCKS5, Shadowsocks, and HTTP inbound protocols with advanced load balancing, health checking, and zero-downtime hot reload.

![web](./web/web.jpg)

---

## ⚡ Performance

Test environment:

```
Linux dev 6.12.85+deb13-arm64 aarch64 GNU/Linux
2 worker cores (CPU-pinned) · pool_size=5 · 300 concurrent clients · 10 s
```

| Connections / second | Failed |
|---|---|
| **14,669** | **0** |

What makes it fast:

- **Zero-copy relay** — `splice(2)` enables kernel-level data transfer, bypassing userspace entirely
- **Pre-warmed connection pools** — outbound handshakes happen in the background, making connection latency near-zero
- **Dedicated CPU runtimes** — forwarding threads and background tasks are isolated on pinned CPU cores, preventing control-plane jitter from affecting the data path
- **jemalloc** — optimized memory allocation for high-concurrency workloads

---

## 🛠️ Features

**Inbound**
- SOCKS5 — TCP or Unix socket, optional auth, optional TLS
- Shadowsocks — AEAD ciphers (`aes-256-gcm`, `chacha20-ietf-poly1305`, …)
- HTTP — `CONNECT` tunnel and plain `GET` proxy, optional Basic Auth, optional TLS

**Outbound**
- Direct, SOCKS5h (TCP or Unix socket), Shadowsocks
- Hierarchical backend groups with per-group strategy:
  - `failover` — first healthy backend
  - `urltest` — lowest measured latency
  - `loadbalance` — fewest active connections

**Operations**
- Hot reload via `SIGHUP` — rewires backends without dropping active sessions
- Network change detection — auto-reprobes on link or gateway changes
- Web dashboard & REST API — live traffic stats, per-backend latency, active connections
- AdBlock — AdGuard/Hosts-format lists fetched and refreshed in the background

---

## ⚙️ Configuration

```yaml
inbounds:
  - type: socks5
    listen: "127.0.0.1:1080"
  - type: http
    listen: "127.0.0.1:8080"
  - type: shadowsocks
    listen: "127.0.0.1:8388"
    password: "securepassword"
    method: "chacha20-ietf-poly1305"

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
  - name: "asia"
    strategy: "urltest"
    backends: ["ss-hk-1"]
  - name: "us-fallback"
    strategy: "failover"
    backends: ["socks-us-1", "direct-out"]

failover_order: ["asia", "us-fallback"]

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
