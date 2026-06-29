# ProxyLB

[English](README_en.md) | [简体中文](README.md)

使用 Rust 编写的高性能代理负载均衡器。支持 SOCKS5、Shadowsocks、HTTP 和 MTProto 入站协议，内置负载均衡、健康检查以及零停机热重载。

![web](./web/web.jpg)

---

## 🛠️ 功能特性

### 协议与传输层
- **入站:** SOCKS5 (TCP/UDS/UDP，可选认证与 TLS)、Shadowsocks (TCP/UDP，AEAD 加密)、HTTP (`CONNECT` 隧道与 `GET` 代理，可选 Basic Auth 和 TLS)、MTProto (FakeTLS，可用作 Telegram 代理)。
- **出站:** 直连 (Direct)、SOCKS5h (TCP/UDS/UDP)、Shadowsocks (TCP/UDP)。
- **传输层:** 入站和出站均支持 TCP、UDP 和 Unix 域套接字 (UDS)。

### 路由与负载均衡
- **层级路由:** 将特定的入站监听器绑定到嵌套策略组，策略组可相互引用。
- **路由策略:**
  - `failover` — 按配置顺序，优先使用第一个健康的后端。
  - `urltest` — 路由到健康检查延迟最低的后端。
  - `loadbalance` — 路由到活跃连接数最少的后端。
  - `consistent_hashing` — 一致性哈希，确保相同域名固定路由到同一后端；后端上下线时仅影响最小范围的重映射。
  - `weighted_round_robin` — 按权重比例分配流量（Nginx 平滑加权轮询算法），支持为每个成员单独指定 `weight`。
- **全局兜底:** 未明确指定路由的入站会默认使用全局的 `failover_order` 进行流量转发。内部策略组的调度策略会被完整保留（例如 `failover_order` 中引用的 WRR 组仍会按权重分配）。

### 运维控制
- **Subcommand CLI:** 提供标准的子命令接口（如 `proxylb run -c config.yaml`）。
- **零停机热重载:** 发送 `SIGHUP` 信号在不中断活动会话的情况下重载配置。
- **网络状态感知:** 检测到链路或网关变更时自动触发重新探测。
- **内置 Web 仪表盘:** 零依赖的 React Web UI，直接编译打包进二进制文件中。支持 10 秒实时流量波形图、客户端追踪和后端延迟可视化。查阅 [RESTful API 接口文档](./restapi.md)。
- **内置 AdBlock:** 在后台定期获取并刷新 AdGuard/Hosts 格式的过滤规则（默认关闭，以保证零开销纯代理转发）。

---

## ⚡ 性能

ProxyLB 为最大吞吐量和极低延迟而生：

- **零拷贝中继:** 在 Linux 上对未加密的中继使用 `splice(2)` 绕过用户空间。加密中继使用优化的缓冲区操作。
- **预热连接池:** 提前在后台完成出站握手，极大地降低热路径延迟。
- **无锁热路径:** 使用原子操作和 `ArcSwap` 避免线程竞争。热路径上零策略计算，确保最高速度。
- **独立 CPU 运行时:** 将转发线程与后台任务绑定到专属的 CPU 核心。
- **jemalloc:** 采用适合高并发场景的 `jemalloc` 内存分配器。
- **PGO (配置引导优化):** 内置 `make pgo` 优化流水线，根据实际工作负载生成极致性能的二进制文件。

### 基准测试

测试环境：macOS 14 上的 Parallels Desktop 虚拟机 (Debian 13)，运行于 M3 Macbook Air。
*参数设置: 1 个工作核心 (CPU 绑定) · pool_size=5 · 300 并发客户端 · 10 秒时长*

| 入站协议 | Connections Per Second (CPS) |
|----------|------------------------------|
| **UDS**  | **~37,485** |
| **TCP**  | **~15,346** |

单核轻松处理每秒数万次连接。

---

## 🛠️ 使用场景

### 场景 1: 代理网关

将 ProxyLB 作为统一的 SOCKS5/Shadowsocks 入口，前置于 `sing-box`、`hysteria` 或 `mihomo` 等本地代理客户端。

**部署方式:**
- **分布式部署:** 将 ProxyLB 部署在公有云，通过 WireGuard 将流量路由到家里运行着 `sing-box` / `hysteria` 的机器。连接池能够掩盖到家宽的握手延迟。
- **本地部署 (UDS):** 在同一台路由器上运行 ProxyLB 和 `sing-box`。它们之间通过 Unix 域套接字 (UDS) 通信，绕过网络协议栈以提升性能。可通过 `frp` 将 ProxyLB 的 UDS 入站暴露到公网，内网设备则直接连接其 SOCKS5 端口。

*(注：原版 `sing-box` 和 `hysteria` 暂不支持 UDS，可使用添加了 UDS 支持的分支: [sing-box](https://github.com/chandler0149/sing-box) 和 [hysteria](https://github.com/chandler0149/hysteria))。*

### 场景 2: 多协议负载均衡

将不同的入站协议路由到指定的后端策略组。

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

## ⚙️ 配置示例

```yaml
inbounds:
  - type: socks5
    listen: "127.0.0.1:1080"
  - type: http
    listen: "127.0.0.1:8080"
  - type: mtproto
    listen: "0.0.0.0:8443"
    password: "00000000000000000000000000000000"
    route: "telegram-group"  # 将此入站绑定到特定的嵌套组
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
  # 子策略组
  - name: "asia-group"
    strategy: "urltest"
    members: ["ss-hk-1"]
  - name: "us-fallback"
    strategy: "failover"
    members: ["socks-us-1", "direct-out"]
  
  # 带权重的轮询策略组
  - name: "weighted-group"
    strategy: "weighted_round_robin"
    members:
      - name: "asia-group"
        weight: 5
      - name: "us-fallback"
        weight: 1

  # 嵌套策略组 (支持将其它组作为 members 引入)
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
./target/release/proxylb run -c config.yaml

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
