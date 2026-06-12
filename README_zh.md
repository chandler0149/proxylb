# ProxyLB

[English](README.md) | [简体中文](README_zh.md)

ProxyLB 是一款使用 Rust 编写的超高性能、功能丰富的代理负载均衡器和流量路由器。它作为一个中间网关，支持 SOCKS5、Shadowsocks 和 HTTP 入站协议，通过具有高级负载均衡策略、实时健康检查、零停机热重载和内置域名过滤的配置外发后端池来路由客户端流量。

![web](./web/web.jpg)

---

## ⚡ 性能架构

ProxyLB 从底层构建，旨在实现高吞吐量、极低的开销和可预测的低延迟：

*   **无锁热路径转发**：客户端与后端之间的数据中继完全无锁运行。一旦路由建立，数据包将绕过所有控制平面锁（例如 RwLock 或 Mutex），利用 tokio 辅助的高速异步管道。
*   **专用的 CPU 亲和性绑定**：
    *   **工作内核 (Worker Cores)**：繁重的 I/O 中继任务被绑定到专用的 CPU 内核 (`worker_cores`)。线程名称带有 `proxylb-worker` 前缀以保证严格隔离。
    *   **辅助内核 (Ancillary Cores)**：后台管理任务（健康检查、连接池填充、广告拦截更新、REST API 服务和 netlink 监听器）通过专用的 tokio 运行时隔离到独立的 CPU 内核 (`ancillary_cores`)。这确保了控制平面的开销绝不会中断或为热转发路径带来延迟。
*   **预验证连接池**：为了消除 SOCKS5/Shadowsocks 握手延迟，ProxyLB 为每个后端维护一个后台连接池。当客户端连接时，能够立即从池中弹出一个已预先握手的连接，从而将外发连接延迟降至近乎为零。
*   **高速广告拦截 Trie 匹配器**：利用高度优化的域名后缀匹配 Trie 树来评估拦截规则和例外（白名单覆盖）。该引擎经基准测试，能够以亚纳秒级的查找速度每秒处理数百万次查询。

---

## 🛠️ 核心功能

### 入站协议
*   **SOCKS5 入站**：支持标准的 SOCKS5 认证和 TCP 转发。可以监听 TCP 端口或 Unix 域套接字（例如 `unix:///tmp/socks.sock`）。
*   **Shadowsocks 入站**：标准的 Shadowsocks 服务器，支持多种现代加密算法（如 `aes-256-gcm`, `chacha20-ietf-poly1305`）。
*   **HTTP 入站**：功能齐全的 HTTP/1.1 代理，支持相对和绝对 GET 请求以及 CONNECT 隧道。

### 外发后端与分组
*   **支持的外发协议**：直接连接 (Direct)、基于 TCP 的 SOCKS5h、基于 Unix 域套接字的 SOCKS5h，以及 Shadowsocks。
*   **层级分组**：对外发后端进行分组并应用自定义路由策略。组可以直接在全局故障转移顺序中被引用。
*   **高级负载均衡策略**：
    *   `failover`（故障转移）：路由到列表中第一个健康的后端。
    *   `urltest`（延迟测试）：动态监测延迟，并将流量路由到响应时间最短的后端。
    *   `loadbalance`（负载均衡）：根据历史和活动连接数最少的原则分配连接。

### 弹性与控制
*   **零停机热重载**：通过 `SIGHUP` 信号触发。优雅地重新加载配置、构建新的连接池并更新路由表，而不会中断活动的客户端连接。
*   **动态网络监听器**：监听路由套接字事件（Linux 上的 Netlink，macOS 上的 Route Sockets）。物理链路或默认网关发生变化时立即触发健康检查探测，从而立刻绕过失效的连接进行路由。
*   **Web 仪表盘与 REST API**：实时流量指标、活动连接数、内存统计信息以及每个后端的延迟日志。API 可以监听 TCP 端口或 Unix 域套接字（如 `unix:///tmp/api.sock`）。
*   **安全与防护**：
    *   **私有地址过滤器**：阻止通过代理后端转发到私有/内部 IP（RFC 1918），以保护本地网络。
    *   **广告拦截引擎**：后台定期解析和更新 AdGuard / Hosts 样式的规则列表。

---

## ⚙️ 配置示例

下面是一个功能完备的 `config.yaml` 示例，展示了入站监听器、后端、分组策略、CPU 绑定和广告拦截配置：

```yaml
# 入站监听器配置
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
    pool_size: 10
  - name: "ss-hk-1"
    type: "shadowsocks"
    address: "88.99.11.22:8388"
    username: "chacha20-ietf-poly1305"
    password: "backendpassword"
    pool_size: 15

# 层级分组与策略
groups:
  - name: "asia-group"
    strategy: "urltest" # 动态路由到延迟最低的节点
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

# 健康检查间隔
health_check:
  interval_secs: 10
  timeout_secs: 5
  check_target: "http://www.gstatic.com/generate_204"

# Web 状态仪表盘 API
web:
  enabled: true
  listen: "unix:///tmp/api.sock" # 或 TCP 地址，如 "127.0.0.1:9090"

# CPU 亲和性与线程隔离设置
cpu_affinity:
  worker_cores: [0, 1]      # 用于代理转发的绑定 CPU 核心 ID（热路径）
  ancillary_cores: [2]      # 用于后台/健康任务的绑定 CPU 核心 ID

# 域名过滤 (广告拦截)
adblock:
  enabled: true
  backend: "direct-out"     # 用于下载列表的后端
  update_interval_hours: 24
  urls:
    - "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  files:
    - "/etc/proxylb/custom_rules.txt"
```

---

## 🚀 快速入门

### 前提条件
*   Rust 工具链（Stable 1.75+）

### 编译与运行
```bash
# 构建 Release 版本
cargo build --release

# 使用配置文件运行 ProxyLB
./target/release/proxylb -c config.yaml
```

### 热重载
在不重启服务或中断活动连接的情况下，即时应用配置更改：
```bash
kill -SIGHUP $(pgrep proxylb)
```
