# ProxyLB

[English](README_en.md) | [简体中文](README.md)

一款使用 Rust 编写的高性能代理负载均衡器。支持 SOCKS5、Shadowsocks 和 HTTP 入站协议，入站和出站均支持TCP或UDS传输层，提供高级负载均衡、健康检查以及零停机热重载功能。

![web](./web/web.jpg)

---

## ⚡ 性能

测试环境：

```
Linux dev 6.12.85+deb13-arm64 aarch64 GNU/Linux
2 个工作核心（CPU 绑定）· pool_size=5 · 300 并发客户端 · 10 秒
```

| 每秒连接数（CPS） | 失败数 |
|---|---|
| **14,669** | **0** |

性能亮点：

- **零拷贝中继** — `splice(2)` 实现内核级数据传输，完全绕过用户空间
- **预热连接池** — 后台提前完成握手，使出站握手延迟趋近于零
- **独立 CPU 运行时** — 转发线程与后台任务隔离在专用的 CPU 核心上，防止控制平面的抖动影响数据路径
- **jemalloc** — 为高并发负载优化的内存分配器

---

## 🛠️ 功能特性

传输层与协议层分离，出站和入站均支持tcp或UDS传输层，入站支持socks5、http、shadowsocks协议，出站支持直连、socks5、shadowsocks协议。还支持TLS安全层，详见配置文件

**入站协议**
- SOCKS5 — TCP 或 Unix 域套接字，可选认证，可选 TLS
- Shadowsocks — AEAD 加密（`aes-256-gcm`, `chacha20-ietf-poly1305` 等）
- HTTP — `CONNECT` 隧道及普通 `GET` 代理，可选 Basic Auth，可选 TLS

**出站后端**
- 直连 (Direct)、SOCKS5h (TCP 或 Unix 域套接字)、Shadowsocks
- 支持策略组，策略类型：
  - `failover` — 优先使用第一个健康的后端
  - `urltest` — 路由到延迟最低的后端
  - `loadbalance` — 路由到活跃连接数最少的后端

**运维控制**
- 零停机热重载 (`SIGHUP`) — 在不中断活动会话的情况下重新加载配置
- 网络状态感知 — 链路或网关变更时自动触发重新探测
- Web 仪表盘 & REST API — 实时流量统计、后端延迟、活跃连接数
- AdBlock — 后台自动获取和刷新 AdGuard/Hosts 格式的过滤规则

---

## ⚙️ 配置示例

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

# 将转发线程绑定到核心 0-1，后台任务绑定到核心 2
cpu_affinity:
  worker_cores: [0, 1]
  ancillary_cores: [2]

advanced:
  zero_copy: true   # Linux 下启用 splice(2)，默认开启
```

---

## 🚀 快速入门

```bash
# 构建
cargo build --release

# 运行
./target/release/proxylb -c config.yaml

# 热重载（不中断现有连接）
kill -SIGHUP $(pgrep proxylb)

# 运行基准测试
make bench
```

---

## 🐳 Docker

```bash
docker build -t proxylb .
docker run -v $(pwd)/config.yaml:/config.yaml proxylb
```

---

## 📄 许可证

[GPL-3.0](LICENSE)
