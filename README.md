# ProxyLB

[English](README_en.md) | [简体中文](README.md)

ProxyLB 是一款使用 Rust 编写的超高性能代理负载均衡器和流量路由器。它作为中间网关，支持 SOCKS5、Shadowsocks 和 HTTP 入站协议，通过具有高级负载均衡策略、实时健康检查、零停机热重载和内置域名过滤的可配置外发后端池来路由客户端流量。

![web](./web/web.jpg)

---

## ⚡ 性能

```bash
root@dev:~/code/gfw/proxylb# uname -a
Linux dev 6.12.85+deb13-arm64 #1 SMP Debian 6.12.85-1 (2026-04-30) aarch64 GNU/Linux
```

> **实测环境：单机、2 个工作核心（CPU 绑定）、pool_size = 5、300 并发客户端、10 秒测试窗口：**
>
> | 指标 | 结果 |
> |---|---|
> | 每秒连接数（CPS） | **14,669** |
> | 连接失败数 | **0** |
> | 测试工具 | Rust `benchmark_cps`（项目内置） |

ProxyLB 从底层设计即以高吞吐、极低开销和可预测低延迟为目标。数据路径上的每一个设计决策都着眼于消除不必要的工作。

### 零拷贝 `splice(2)` 中继（Linux）

在 Linux 上，热数据转发路径使用 `splice(2)` 系统调用在客户端套接字与后端套接字之间移动数据，**数据字节始终不需要拷贝到用户空间**。内核通过中间管道在文件描述符之间直接传输数据，每个方向节省两次内存拷贝，彻底消除相关的 CPU 和缓存压力。

管道文件描述符在**连接池填充阶段预先分配**，并随连接一起存储在池中，确保客户端复用池化连接时关键路径上没有额外的系统调用开销。

对于非 Linux 平台或非 TCP 流，回退使用 `tokio::io::copy_bidirectional`，其本身也具有极高效率。

### 无锁热路径

一旦路由建立，整个中继循环完全无锁运行。数据传输期间不持有任何 `Mutex` 或 `RwLock`。连接池查找是对预构建快照的单次原子读取操作，该快照仅在健康状态变更时才在热路径之外进行替换。

### 预验证连接池

每个 SOCKS5 / Shadowsocks 后端均维护一个后台连接池，工作线程持续向池中填充**已完成握手、随时可用的连接**。当客户端发起连接时，池化连接被原子弹出——外发连接延迟实际上为零。池未命中（冷连接）时仍会进行新的拨号，但这属于退化路径。

### 专用 CPU 亲和性绑定

两个独立的 tokio 运行时确保控制平面与数据平面互不干扰：

| 运行时线程 | 绑定到 | 运行内容 |
|---|---|---|
| `proxylb-worker` | `worker_cores` | 入站接受、数据中继、所有 I/O |
| `proxylb-ancillary` | `ancillary_cores` | 健康检查、连接池填充、广告拦截、Web API、Netlink |

这确保了健康检查或统计收集产生的抖动永远不会对转发路径增加延迟。

### jemalloc 内存分配器

ProxyLB 使用 **jemalloc**（`tikv-jemallocator`）作为全局内存分配器。与 glibc `malloc` 相比，jemalloc 在代理服务器高分配率、高并发的工作负载下能显著减少内存碎片和锁竞争。

### 高速广告拦截 Trie 匹配器

域名过滤采用**压缩后缀匹配 Trie**，查找延迟在亚纳秒量级。即使加载数百万条规则，在 300 CPS 的持续负载下，Trie 引入的开销也微乎其微。

---

## 🛠️ 核心功能

### 入站协议
- **SOCKS5** — TCP 或 Unix 域套接字（`unix:///tmp/socks.sock`），可选用户名/密码认证，可选 TLS
- **Shadowsocks** — AEAD 加密（`aes-256-gcm`、`chacha20-ietf-poly1305` 等），TCP 或 UDS
- **HTTP** — HTTP/1.1 代理：`CONNECT` 隧道 + 绝对/相对 `GET` 请求，可选 Basic Auth，可选 TLS

### 外发后端与分组
- **支持协议**：直接连接、基于 TCP 的 SOCKS5h、基于 UDS 的 SOCKS5h、Shadowsocks
- **层级分组**，每组独立策略：
  - `failover`（故障转移）——优先使用列表中第一个健康后端
  - `urltest`（延迟测试）——持续测量延迟，路由到响应最快的后端
  - `loadbalance`（负载均衡）——路由到当前活跃连接数最少的后端

### 弹性与控制
- **零停机热重载** via `SIGHUP`——在不中断活动会话的情况下重新接入后端
- **动态网络监听器** — Netlink（Linux）/ Route Sockets（macOS），链路或网关变更时立即触发重新探测
- **Web 仪表盘 + REST API** — 实时流量指标、每后端延迟、活跃连接数；可监听 TCP 或 UDS
- **私有地址过滤器** — 阻断 RFC 1918 目标，保护本地网络
- **广告拦截引擎** — AdGuard/Hosts 格式规则列表，后台自动获取并更新

---

## ⚙️ 配置示例

```yaml
# 入站监听器
inbounds:
  - type: socks5
    listen: "127.0.0.1:1080"
  - type: http
    listen: "127.0.0.1:8080"
  - type: shadowsocks
    listen: "127.0.0.1:8388"
    password: "securepassword"
    method: "chacha20-ietf-poly1305"

# 外发后端服务器
backends:
  - name: "direct-out"
    type: "direct"
  - name: "socks-us-1"
    type: "socks5"
    address: "12.34.56.78:1080"
    username: "user"
    password: "pass"
    pool_size: 10          # 预先握手的连接数
  - name: "ss-hk-1"
    type: "shadowsocks"
    address: "88.99.11.22:8388"
    password: "backendpassword"
    method: "chacha20-ietf-poly1305"
    pool_size: 15

# 层级分组与策略
groups:
  - name: "asia-group"
    strategy: "urltest"    # 动态路由到延迟最低的后端
    backends:
      - "ss-hk-1"
  - name: "failover-pool"
    strategy: "failover"
    backends:
      - "socks-us-1"
      - "direct-out"

# 全局优先级故障转移顺序
failover_order:
  - "asia-group"
  - "failover-pool"

# 健康检查
health_check:
  interval_secs: 10
  timeout_secs: 5
  check_target: "http://www.gstatic.com/generate_204"

# Web 仪表盘 / REST API
web:
  enabled: true
  listen: "unix:///tmp/api.sock"   # 或 TCP 地址，如 "127.0.0.1:9090"

# CPU 亲和性 — 数据平面与控制平面绑定到不同核心
cpu_affinity:
  worker_cores: [0, 1]      # 中继与接受线程
  ancillary_cores: [2]      # 健康检查、连接池填充、广告拦截、API

# 域名过滤（广告拦截）
adblock:
  enabled: true
  backend: "direct-out"
  update_interval_hours: 24
  urls:
    - "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  files:
    - "/etc/proxylb/custom_rules.txt"

# 性能调优
advanced:
  zero_copy: true           # 在 Linux 上启用 splice(2)（默认: true）
```

---

## 🚀 快速入门

### 前置条件
- Rust 工具链（Stable 1.75+）

### 编译与运行
```bash
# 构建优化的 Release 版本
cargo build --release

# 使用配置文件运行 ProxyLB
./target/release/proxylb -c config.yaml

# 在不重启服务的情况下应用配置变更
kill -SIGHUP $(pgrep proxylb)
```

### 运行基准测试
```bash
make bench
```

内置的 `benchmark_cps` 工具会在独立核心上启动 Rust SOCKS5 模拟后端，并使用多线程客户端以 300 并发连接持续发压 10 秒，输出总 CPS 和失败率。

---

## 🐳 Docker

```bash
docker build -t proxylb .
docker run -v $(pwd)/config.yaml:/config.yaml proxylb
```

---

## 📄 许可证

[GPL-3.0](LICENSE)
