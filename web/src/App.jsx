import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [apiHost, setApiHost] = useState(() => {
    return localStorage.getItem('proxylb_api_host') || 'http://192.168.1.240:2020';
  });
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('all'); // 'all', 'groups', 'backends'

  // Sync API host to localStorage
  const handleApiHostChange = (e) => {
    const val = e.target.value;
    setApiHost(val);
    localStorage.setItem('proxylb_api_host', val);
  };

  // Fetch status helper
  const fetchStatus = async () => {
    try {
      const host = apiHost.replace(/\/$/, ''); // strip trailing slash
      const response = await fetch(`${host}/api/status`);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const json = await response.json();
      setData(json);
      setError(null);
    } catch (err) {
      console.error('Fetch failed:', err);
      setError(`Failed to connect to ProxyLB API at ${apiHost}. Make sure the server is running and CORS is enabled.`);
    } finally {
      setLoading(false);
    }
  };

  // Poll API every 5 seconds
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [apiHost]);

  // Toggle backend enabled state
  const handleToggleBackend = async (name, currentEnabled) => {
    try {
      const host = apiHost.replace(/\/$/, '');
      const action = currentEnabled ? 'disable' : 'enable';
      const response = await fetch(`${host}/api/backends/${name}/${action}`, {
        method: 'POST',
      });
      if (!response.ok) {
        throw new Error(`Failed to ${action} backend ${name}`);
      }
      // Re-fetch status immediately
      fetchStatus();
    } catch (err) {
      alert(`Error toggling backend: ${err.message}`);
    }
  };

  // Utility to format bytes
  const formatBytes = (n) => {
    if (n === 0 || !n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log2(n) / 10), units.length - 1);
    const val = n / Math.pow(1024, i);
    return (i === 0 ? val : val.toFixed(2)) + ' ' + units[i];
  };

  // Utility to format time
  const formatTime = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleTimeString();
  };

  // If loading and no data yet
  if (loading && !data) {
    return (
      <div className="container" style={{ justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <div className="refresh-badge">
          <span className="refresh-dot"></span>
          Loading ProxyLB dashboard...
        </div>
      </div>
    );
  }

  // Calculate overall stats from backends
  const backends = data?.backends || [];
  const totalBytesUp = backends.reduce((acc, b) => acc + (b.bytes_up || 0), 0);
  const totalBytesDown = backends.reduce((acc, b) => acc + (b.bytes_down || 0), 0);
  const totalActiveConns = backends.reduce((acc, b) => acc + Math.max(0, b.active_connections || 0), 0);
  const totalConns = backends.reduce((acc, b) => acc + (b.total_connections || 0), 0);
  const totalPoolHits = backends.reduce((acc, b) => acc + (b.pool_hits || 0), 0);
  const totalPoolMisses = backends.reduce((acc, b) => acc + (b.pool_misses || 0), 0);
  const totalPoolStale = backends.reduce((acc, b) => acc + (b.pool_stale || 0), 0);
  const healthyCount = backends.filter((b) => b.healthy).length;

  const totalPoolRequests = totalPoolHits + totalPoolMisses + totalPoolStale;
  const globalHitRate = totalPoolRequests > 0 ? ((totalPoolHits / totalPoolRequests) * 100) : 0;

  let healthStatusClass = 'beacon-red';
  let healthText = 'All Unhealthy';
  if (healthyCount === backends.length && backends.length > 0) {
    healthStatusClass = 'beacon-green';
    healthText = 'All Backends Healthy';
  } else if (healthyCount > 0) {
    healthStatusClass = 'beacon-yellow';
    healthText = `${healthyCount} / ${backends.length} Healthy`;
  }

  // 1. Sort inbound stats by data usage (tx_bytes + rx_bytes) descending
  const sortedInbounds = [...(data?.inbounds || [])].sort((a, b) => {
    const usageA = (a.tx_bytes || 0) + (a.rx_bytes || 0);
    const usageB = (b.tx_bytes || 0) + (b.rx_bytes || 0);
    return usageB - usageA;
  });

  // Render a backend card helper
  const renderBackendCard = (b) => {
    const totalRequests = b.pool_hits + b.pool_misses + b.pool_stale;
    const hitRate = totalRequests > 0 ? ((b.pool_hits / totalRequests) * 100).toFixed(1) + '% hit rate' : 'no requests yet';

    // 2. Health check result should limit to 5 history items
    // Since newer results are appended at the end of the history array in backend,
    // reversing gives newest first, and then we slice to 5 items.
    const recentHistory = [...(b.history || [])].reverse().slice(0, 5);

    return (
      <div key={b.name} className="card">
        <div className="card-header">
          <div>
            <div className="card-name">
              {b.name}
              {b.group && <span className="card-group-tag">{b.group}</span>}
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={b.enabled}
                  onChange={() => handleToggleBackend(b.name, b.enabled)}
                />
                <span className="slider"></span>
              </label>
            </div>
            <div className="card-address">{b.address}</div>
          </div>
          <span className={`status-badge ${!b.enabled ? 'status-disabled' : (b.healthy ? 'status-healthy' : 'status-unhealthy')}`}>
            <span className="status-dot"></span>
            {!b.enabled ? 'Disabled' : (b.healthy ? 'Healthy' : 'Unhealthy')}
          </span>
        </div>

        <div className="metrics">
          <div className="metric">
            <span className="metric-label">Latency</span>
            <span className="metric-value">{b.last_latency_ms != null ? `${b.last_latency_ms} ms` : '—'}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Failures</span>
            <span className="metric-value" style={{ color: b.consecutive_failures > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>
              {b.consecutive_failures}
            </span>
          </div>
        </div>

        <div className="traffic-row">
          <div className="traffic-item">
            <span className="traffic-label">Upload</span>
            <span className="traffic-value upload">{formatBytes(b.bytes_up)}</span>
          </div>
          <div className="traffic-item">
            <span className="traffic-label">Download</span>
            <span className="traffic-value download">{formatBytes(b.bytes_down)}</span>
          </div>
          <div className="traffic-item">
            <span className="traffic-label">Active</span>
            <span className="traffic-value active">{Math.max(0, b.active_connections)}</span>
          </div>
          <div className="traffic-item">
            <span className="traffic-label">Total Conn</span>
            <span className="traffic-value">{b.total_connections}</span>
          </div>
        </div>

        <div className="pool-row">
          <div className="pool-item">
            <span className="pool-label">Pool Hits</span>
            <span className="pool-value hit">{b.pool_hits}</span>
            <span className="pool-hit-rate">{hitRate}</span>
          </div>
          <div className="pool-item">
            <span className="pool-label">Pool Misses</span>
            <span className="pool-value miss">{b.pool_misses}</span>
            <span className="pool-hit-rate">pool empty → fresh</span>
          </div>
          <div className="pool-item">
            <span className="pool-label">Stale Evicted</span>
            <span className="pool-value stale">{b.pool_stale}</span>
            <span className="pool-hit-rate">dead → replaced</span>
          </div>
        </div>

        <div>
          <div className="history-title" style={{ marginBottom: '0.5rem' }}>Recent Health Checks (Max 5)</div>
          {recentHistory.length === 0 ? (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontStyle: 'italic' }}>No checks run yet</div>
          ) : (
            <table className="history-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {recentHistory.map((h, idx) => (
                  <tr key={idx}>
                    <td>{formatTime(h.timestamp)}</td>
                    <td className={h.success ? 'history-success' : 'history-fail'}>
                      {h.success ? '✓ OK' : '✗ FAIL'}
                    </td>
                    <td>{h.latency_ms != null ? `${h.latency_ms} ms` : '—'}</td>
                    <td className="error-text" title={h.error || ''}>
                      {h.error || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    );
  };

  // Helper to render tree/routing nodes
  const renderTreeItem = (item, index) => {
    if (item.type === 'backend') {
      return (
        <div key={`tree-${item.status.name}-${index}`} className="tree-node-wrapper">
          {renderBackendCard(item.status)}
        </div>
      );
    } else if (item.type === 'group') {
      // 3. Backend stats in group sorted by data usage (bytes_up + bytes_down) descending
      const sortedGroupBackends = [...(item.backends || [])].sort((a, b) => {
        const usageA = (a.bytes_up || 0) + (a.bytes_down || 0);
        const usageB = (b.bytes_up || 0) + (b.bytes_down || 0);
        return usageB - usageA;
      });

      return (
        <div key={`tree-${item.name}-${index}`} className="tree-node-wrapper">
          <div className="tree-group-card">
            <div className="tree-group-header">
              <div className="tree-group-title">
                <span>📂 Group: {item.name}</span>
              </div>
              <span className="tree-group-strategy">{item.strategy}</span>
            </div>
            <div className="tree-group-children">
              {sortedGroupBackends.map((b) => renderBackendCard(b))}
            </div>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="container">
      {/* Header controls & config */}
      <div className="header">
        <div className="header-title-area">
          <h1>⚡ ProxyLB Status</h1>
          <div className="subtitle">High-Performance SOCKS5 Proxy Load Balancer & Failover Management</div>
        </div>
        <div className="header-controls">
          <div className="api-config">
            <label htmlFor="apiHostInput">API:</label>
            <input
              id="apiHostInput"
              type="text"
              value={apiHost}
              onChange={handleApiHostChange}
              placeholder="e.g. http://localhost:9090"
            />
          </div>
          <div className="refresh-badge">
            <span className="refresh-dot"></span>
            Auto-refresh (5s)
          </div>
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div style={{ background: 'rgba(255, 61, 113, 0.1)', border: '1px solid var(--accent-red)', padding: '1rem', borderRadius: '12px', color: 'var(--accent-red)', fontSize: '0.9rem' }}>
          ⚠️ {error}
        </div>
      )}

      {/* 1. Overall Stats Panel */}
      <div className="summary-grid">
        {/* Health */}
        <div className="summary-card health">
          <div className="summary-card-header">
            <span className="summary-card-title">System Status</span>
            <div className="beacon-container">
              <span className="summary-card-subtext">{healthText}</span>
              <div className={`beacon ${healthStatusClass}`}>
                <span className="beacon-pulse"></span>
              </div>
            </div>
          </div>
          <div className="summary-card-value">
            {healthyCount} / {backends.length}
          </div>
          <div className="summary-card-subtext">Active load balancer nodes</div>
        </div>

        {/* Traffic */}
        <div className="summary-card">
          <div className="summary-card-header">
            <span className="summary-card-title">Total Bandwidth</span>
            <span className="summary-card-icon">⚡</span>
          </div>
          <div className="summary-card-value" style={{ fontSize: '1.6rem', marginBottom: '0.7rem' }}>
            {formatBytes(totalBytesUp + totalBytesDown)}
          </div>
          <div className="summary-card-subtext" style={{ gap: '12px' }}>
            <span style={{ color: '#ffa726' }}>▲ {formatBytes(totalBytesUp)}</span>
            <span style={{ color: 'var(--accent-green)' }}>▼ {formatBytes(totalBytesDown)}</span>
          </div>
        </div>

        {/* Connections */}
        <div className="summary-card">
          <div className="summary-card-header">
            <span className="summary-card-title">Active Connections</span>
            <span className="summary-card-icon">🔌</span>
          </div>
          <div className="summary-card-value">{totalActiveConns}</div>
          <div className="summary-card-subtext">Historical total: {totalConns}</div>
        </div>

        {/* Pool performance */}
        <div className="summary-card">
          <div className="summary-card-header">
            <span className="summary-card-title">Global Pool Hit Rate</span>
            <span className="summary-card-icon">💾</span>
          </div>
          <div className="summary-card-value">{globalHitRate.toFixed(1)}%</div>
          <div className="summary-card-subtext">
            Hits: {totalPoolHits} / Misses: {totalPoolMisses}
          </div>
        </div>

        {/* Memory Footprint */}
        <div className="summary-card">
          <div className="summary-card-header">
            <span className="summary-card-title">Memory Footprint</span>
            <span className="summary-card-icon">🧠</span>
          </div>
          <div className="summary-card-value">
            {data?.memory?.rss ? formatBytes(data.memory.rss) : 'N/A'}
          </div>
          <div className="summary-card-subtext">
            VM Size: {data?.memory?.vmsize ? formatBytes(data.memory.vmsize) : 'Linux only'}
          </div>
        </div>

        {/* AdBlock Guard */}
        <div className={`summary-card ${data?.adblock?.enabled ? 'adblock-enabled' : 'adblock-disabled'}`}>
          <div className="summary-card-header">
            <span className="summary-card-title">AdBlock Guard</span>
            <div className="beacon-container">
              <span className="summary-card-subtext">
                {data?.adblock?.enabled ? 'Active' : 'Disabled'}
              </span>
              <div className={`beacon ${data?.adblock?.enabled ? 'beacon-green' : 'beacon-red'}`}>
                <span className="beacon-pulse"></span>
              </div>
            </div>
          </div>
          <div className="summary-card-value">
            {data?.adblock?.blocked_requests || 0}
          </div>
          <div className="summary-card-subtext">
            Blocked / {((data?.adblock?.block_rules_count || 0) + (data?.adblock?.allow_rules_count || 0)).toLocaleString()} rules
          </div>
        </div>
      </div>

      {/* 2. Inbound stats sorted by data usage */}
      <div>
        <h2 className="section-title">🔌 Active Inbound Listeners</h2>
        {sortedInbounds.length === 0 ? (
          <div className="empty-state">No inbound listeners configured</div>
        ) : (
          <div className="inbounds-grid">
            {sortedInbounds.map((inbound) => {
              const badgeClass = inbound.inbound_type.toLowerCase();
              const usage = (inbound.tx_bytes || 0) + (inbound.rx_bytes || 0);
              return (
                <div key={inbound.listen} className="inbound-card">
                  <div className="inbound-header">
                    <div className="inbound-title">🔌 {inbound.name}</div>
                    <span className={`inbound-badge ${badgeClass}`}>{inbound.inbound_type}</span>
                  </div>
                  <div className="inbound-address">Listen: {inbound.listen}</div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Total Data: <strong>{formatBytes(usage)}</strong>
                  </div>
                  <div className="inbound-stats-list">
                    <div className="inbound-stat-item">
                      <span className="inbound-stat-label">Active Conn</span>
                      <span className="inbound-stat-value" style={{ color: 'var(--accent-blue)' }}>{inbound.active_connections}</span>
                    </div>
                    <div className="inbound-stat-item">
                      <span className="inbound-stat-label">Total Conn</span>
                      <span className="inbound-stat-value">{inbound.total_connections}</span>
                    </div>
                    <div className="inbound-stat-item" style={{ borderTop: '1px solid rgba(255,255,255,0.03)', paddingTop: '8px' }}>
                      <span className="inbound-stat-label">Uploaded</span>
                      <span className="inbound-stat-value" style={{ color: '#ffa726' }}>{formatBytes(inbound.tx_bytes)}</span>
                    </div>
                    <div className="inbound-stat-item" style={{ borderTop: '1px solid rgba(255,255,255,0.03)', paddingTop: '8px' }}>
                      <span className="inbound-stat-label">Downloaded</span>
                      <span className="inbound-stat-value" style={{ color: 'var(--accent-green)' }}>{formatBytes(inbound.rx_bytes)}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 3. Group and Standalone Backend Stats */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <h2 className="section-title" style={{ marginBottom: 0 }}>🌳 Backends & Routing Groups</h2>
          <div className="view-tabs">
            <button
              className={`tab-btn ${activeTab === 'all' ? 'active' : ''}`}
              onClick={() => setActiveTab('all')}
            >
              All (Failover order)
            </button>
            <button
              className={`tab-btn ${activeTab === 'groups' ? 'active' : ''}`}
              onClick={() => setActiveTab('groups')}
            >
              Groups
            </button>
            <button
              className={`tab-btn ${activeTab === 'backends' ? 'active' : ''}`}
              onClick={() => setActiveTab('backends')}
            >
              Standalone Backends
            </button>
          </div>
        </div>

        {activeTab === 'all' && (
          <div className="tree-root">
            {data?.tree && data.tree.length > 0 ? (
              data.tree.map((item, idx) => renderTreeItem(item, idx))
            ) : (
              <div className="empty-state">No routing hierarchy configured</div>
            )}
          </div>
        )}

        {activeTab === 'groups' && (
          <div className="groups-grid">
            {data?.tree && data.tree.filter(item => item.type === 'group').length > 0 ? (
              data.tree
                .filter(item => item.type === 'group')
                .map((item, idx) => {
                  // Sort backends inside the group by data usage descending
                  const sortedGroupBackends = [...(item.backends || [])].sort((a, b) => {
                    const usageA = (a.bytes_up || 0) + (a.bytes_down || 0);
                    const usageB = (b.bytes_up || 0) + (b.bytes_down || 0);
                    return usageB - usageA;
                  });

                  return (
                    <div key={`group-${item.name}-${idx}`} className="tree-group-card" style={{ borderLeft: '3px solid var(--accent-blue)' }}>
                      <div className="tree-group-header">
                        <div className="tree-group-title">
                          <span>📂 Group: {item.name}</span>
                        </div>
                        <span className="tree-group-strategy">{item.strategy}</span>
                      </div>
                      <div className="tree-group-children">
                        {sortedGroupBackends.map((b) => renderBackendCard(b))}
                      </div>
                    </div>
                  );
                })
            ) : (
              <div className="empty-state">No backend groups configured</div>
            )}
          </div>
        )}

        {activeTab === 'backends' && (
          <div className="backends-grid">
            {data?.tree && data.tree.filter(item => item.type === 'backend').length > 0 ? (
              data.tree
                .filter(item => item.type === 'backend')
                .map((item) => renderBackendCard(item.status))
            ) : (
              <div className="empty-state">No standalone backends configured</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
