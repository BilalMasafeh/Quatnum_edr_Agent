import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAlerts } from '../../hooks/useAlerts';
import { Search, Filter, RefreshCw } from 'lucide-react';

export default function Alerts() {
  const { alerts, loading, refresh } = useAlerts();
  const navigate = useNavigate();
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  const filteredAlerts = alerts.filter(a => {
    if (filter !== 'ALL' && a.classification !== filter) return false;
    if (search && !a.process_name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', padding: 0 }}>
      <div style={{ padding: '20px', borderBottom: '1px solid var(--border)' }}>
        <div className="flex justify-between items-center mb-16">
          <h3 style={{ fontSize: '16px', fontWeight: '600' }}>Endpoint Alerts</h3>
          <button className="btn" onClick={refresh} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
        
        <div className="filters-bar">
          <div className="flex gap-8">
            {['ALL', 'MALICIOUS', 'SUSPICIOUS', 'SAFE'].map(f => (
              <button 
                key={f}
                className={`filter-chip ${filter === f ? 'active' : ''}`}
                onClick={() => setFilter(f)}
              >
                {f}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-8" style={{ marginLeft: 'auto' }}>
            <Search size={16} className="text-muted" />
            <input 
              type="text" 
              className="search-input" 
              placeholder="Search process name..." 
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Process</th>
              <th>Classification</th>
              <th>Score</th>
              <th>AI Mode</th>
              <th>Time</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.map(alert => (
              <tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)}>
                <td className="text-muted">#{alert.id}</td>
                <td className="mono">{alert.process_name}</td>
                <td>
                  <span className={`badge ${alert.classification.toLowerCase()}`}>
                    {alert.classification}
                  </span>
                </td>
                <td>
                  <div className="score-bar">
                    <div className="score-bar-track">
                      <div 
                        className="score-bar-fill" 
                        style={{ 
                          width: `${alert.final_score * 100}%`,
                          background: alert.final_score > 0.8 ? 'var(--danger)' : alert.final_score > 0.5 ? 'var(--warning)' : 'var(--success)'
                        }}
                      />
                    </div>
                    <span>{(alert.final_score * 100).toFixed(0)}%</span>
                  </div>
                </td>
                <td className="text-muted" style={{ fontSize: '11px', textTransform: 'uppercase' }}>
                  {alert.mode.replace('_', ' ')}
                </td>
                <td>{new Date(alert.timestamp).toLocaleString()}</td>
                <td>{alert.status}</td>
              </tr>
            ))}
            {filteredAlerts.length === 0 && (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
                  No alerts match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
