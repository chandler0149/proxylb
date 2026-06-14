# ProxyLB

[English](README_en.md) | [简体中文](README.md)

A high-performance proxy load balancer written in Rust. Supports SOCKS5, Shadowsocks, and HTTP inbound protocols with advanced load balancing, health checking, and zero-downtime hot reload.

![web](./web/web.jpg)

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

## ⚡ Performance


What makes it fast:

- **Zero-copy relay** — `splice(2)` enables kernel-level data transfer, bypassing userspace entirely
- **Pre-warmed connection pools** — outbound handshakes happen in the background, making connection latency near-zero
- **Dedicated CPU runtimes** — forwarding threads and background tasks are isolated on pinned CPU cores, preventing control-plane jitter from affecting the data path
- **jemalloc** — optimized memory allocation for high-concurrency workloads

---

Test environment:

Parallels Desktop on macOS 14 running linux guest: M3 Macbook Air

```
Linux dev 6.12.85+deb13-arm64 aarch64 GNU/Linux
1 worker cores (CPU-pinned) · pool_size=5 · 300 concurrent clients · 10 s
```

A rough CPS benchmark, UDS inbound CPS reaches 37485, TCP inbound CPS reaches 15346.

```bash
root@dev:~/code/gfw/proxylb# make bench BENCH_UDS=1
cargo build --release
    Finished `release` profile [optimized] target(s) in 0.08s
Starting SOCKS5 CPS benchmark...
Starting Rust SOCKS5 mock backend...
Starting ProxyLB in release mode...
Running Rust SOCKS5 CPS benchmark...
Proxy:  unix:///tmp/proxylb_bench.sock
Target: 127.0.0.1:10800
Concurrency: 300, Duration: 10s
Starting SOCKS5 CPS benchmark...

=== Consolidated Results ===
Total Successful Connections: 375073
Total Failed Connections:     0
Max Elapsed Time:             10.01s
Combined Connections Per Second (CPS): 37485.10
Cleaning up processes...
Benchmark complete.
root@dev:~/code/gfw/proxylb# make bench
cargo build --release
    Finished `release` profile [optimized] target(s) in 0.09s
Starting SOCKS5 CPS benchmark...
Starting Rust SOCKS5 mock backend...
Starting ProxyLB in release mode...
Running Rust SOCKS5 CPS benchmark...
Proxy:  127.0.0.1:1080
Target: 127.0.0.1:10800
Concurrency: 300, Duration: 10s
Starting SOCKS5 CPS benchmark...

=== Consolidated Results ===
Total Successful Connections: 169099
Total Failed Connections:     0
Max Elapsed Time:             11.02s
Combined Connections Per Second (CPS): 15346.97
Cleaning up processes...
Benchmark complete.
```









---

## 🛠️ Usage Scenarios

### Scenario 1: Highly Reliable Proxy Gateway

The most common use case is utilizing tools like sing-box, Hysteria, or Mihomo as backends connected to different VPSs, while ProxyLB provides a unified SOCKS5/Shadowsocks gateway for highly reliable network services.

ProxyLB and the backends can be deployed on different machines or on the same machine depending on the situation:

- **ProxyLB and sing-box deployed on different machines, communicating over the network:**
  * Since ProxyLB supports connection pooling, it effectively reduces the handshake latency between ProxyLB and the backends.
  * My friend's deployment method: Deploy ProxyLB on a public cloud to provide a stable entry point, then connect via WireGuard to the home machine running sing-box/Hysteria/Mihomo.

- **ProxyLB and sing-box deployed on the same machine, communicating via Unix Domain Sockets (UDS):**
  * Using domain sockets bypasses the network protocol stack, yielding better performance.
  * My friend's deployment method:
    - Deploy ProxyLB on a software router.
    - Use frp to expose ProxyLB's UDS inbound to the public network, allowing mobile devices to connect via the frp server when away from home.
    - When at home, connect phones and computers directly to ProxyLB's SOCKS5 inbound.

Since sing-box and Hysteria do not natively support domain sockets, you will need to use my modified versions. For details, refer to:

- sing-box: https://github.com/chandler0149/sing-box 
- Hysteria: https://github.com/chandler0149/hysteria


### Scenario 2: SOCKS5 Load Balancer

```
                                                 +-------+                  
                                                 |       |                  
                                  +-------------->singbox+----------------> 
                                  |              |       |                  
                |                 |              +-------+                  
                |                 |                                         
                | shadowsocks     |                                         
      UDS/TCP   |                 |                                         
                |                 |                                         
                |             +---+-----+        +-------+                  
  socks5        +------------>|         |        |       |                  
----------------------------->| proxylb +-------->singbox+----------------> 
                +------------>|         |        |       |                  
                |             +---+-----+        +-------+                  
                |                 |                                         
                |                 |                                         
                |                 |                                         
                |  http           |                                         
                |                 |              +-------+                  
                |                 |              |       |                  
                |                 +-------------->hysteri+----------------->
                                                 |       |                  
                                                 +-------+                  

```

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
