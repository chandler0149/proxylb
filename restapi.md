# ProxyLB RESTful API Documentation

ProxyLB provides a built-in HTTP server to monitor status in real-time, toggle backends and inbounds dynamically, and manage AdBlock filter rules.

By default, the Web API can listen on a TCP port or a Unix Domain Socket (UDS). Configure this in your `config.yaml` under the `web` section:

```yaml
web:
  enabled: true
  listen: "0.0.0.0:9090" # or "unix:///var/run/proxylb-web.sock"
```

---

## 1. Status & Metrics

### GET `/`
Returns basic API information and version.

**Response:**
```json
{
  "status": "ok",
  "name": "ProxyLB API",
  "version": "1.4.0-abcdef"
}
```

### GET `/api/status`
Returns the comprehensive real-time status of the proxy, including memory usage, backends, nested groups (tree), inbound listeners, active clients, and AdBlock metrics.

**Response:**
```json
{
  "backends": [
    {
      "name": "socks-us-1",
      "type": "socks5",
      "address": "12.34.56.78:1080",
      "healthy": true,
      "latency_ms": 145,
      "active_connections": 10,
      "tx_bytes": 1048576,
      "rx_bytes": 2097152,
      "enabled": true
    }
  ],
  "tree": [
    {
      "name": "us-fallback",
      "strategy": "failover",
      "children": ["socks-us-1", "direct-out"]
    }
  ],
  "memory": {
    "rss": 15432000,
    "vmsize": 20045000
  },
  "inbounds": [
    {
      "name": "SOCKS5 (127.0.0.1:1080)",
      "listen": "127.0.0.1:1080",
      "inbound_type": "socks5",
      "active_connections": 5,
      "total_connections": 100,
      "tx_bytes": 50000,
      "rx_bytes": 80000,
      "enabled": true
    }
  ],
  "clients": [],
  "domains": [],
  "blocked_domains": [],
  "adblock": {
    "enabled": true,
    "block_rules_count": 50432,
    "allow_rules_count": 12,
    "blocked_requests": 34
  }
}
```

---

## 2. Dynamic Control (Backends & Inbounds)

### POST `/api/backends/{name}/enable`
Enables a specific backend node by name.

**Response:** `200 OK` or `404 Not Found`

### POST `/api/backends/{name}/disable`
Disables a specific backend node by name. Disabled backends will immediately stop receiving new connections, but active connections are not forcefully dropped.

**Response:** `200 OK` or `404 Not Found`

---

## 3. Filter Engine & AdBlock

### GET `/api/filter/items`
Retrieves all configured custom rules and remote rule URLs.

**Response:**
```json
{
  "rules": ["||example.com^", "@@||whitelist.com^"],
  "urls": [
    {
      "url": "https://example.com/adblock.txt",
      "tag": "Ads",
      "rule_count": 15200
    }
  ]
}
```

### POST `/api/filter/items`
Adds a new filter item. You can either provide a direct custom rule, or a remote URL to subscribe to.

**Payload for Rule:**
```json
{
  "type": "rule",
  "rules": ["||malware.com^"]
}
```

**Payload for URL:**
```json
{
  "type": "url",
  "url": "https://example.com/ads.txt",
  "tag": "Ads"
}
```
*Note: When adding a URL, the proxy will attempt to download and parse it immediately before returning `200 OK`.*

### DELETE `/api/filter/items`
Deletes an existing filter item. The payload format is identical to the `POST` request.

### POST `/api/filter/settings`
Updates the global settings for the filter engine.

**Payload:**
```json
{
  "enabled": true,
  "block_private_addresses": false
}
```

### GET `/api/filter/check?target={domain_or_ip}`
Checks whether a specific target (domain or IP address) is currently blocked by the filter engine.

**Example Request:** `GET /api/filter/check?target=ads.example.com`

**Response:**
```json
{
  "blocked": true
}
```
