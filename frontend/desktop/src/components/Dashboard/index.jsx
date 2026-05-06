import { useState, useEffect } from 'react';
import { useAlerts } from '../../hooks/useAlerts';
import { useWebSocket } from '../../hooks/useWebSocket';
import { ShieldAlert, Target, ShieldCheck, Activity } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { useNavigate } from 'react-router-dom';

function StatCard({ title, value, type, icon: Icon }) {
  return (
    <div className={`stat-card ${type}`}>
      <div className="stat-label">{title}</div>
      <div className="stat-value">{value}</div>
      <Icon className="stat-icon" size={32} />
    </div>
  );
}

function ThreatGauge({ rate }) {
  return (
    <div className="threat-gauge card">
      <div className="card-header">Current Threat Level</div>
      <div className="gauge-circle" style={{ borderColor: rate > 10 ? 'var(--danger)' : rate > 5 ? 'var(--warning)' : 'var(--success)' }}>
        <div className="gauge-value" style={{ color: rate > 10 ? 'var(--danger)' : rate > 5 ? 'var(--warning)' : 'var(--success)' }}>
          {rate}%
        </div>
        <div className="gauge-label">Malicious</div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { alerts, stats, loading, refresh, addAlert } = useAlerts();
  const navigate = useNavigate();

  useWebSocket('ws://localhost:8000/ws', (data) => {
    if (data.type === 'new_alert') {
      refresh();
    }
  });

  if (loading && !stats) {
    return <div className="loading-state"><div className="spinner" />Loading Dashboard...</div>;
  }

  // Simple timeline data aggregation
  const timelineData = alerts.slice(0, 20).reverse().map(a => ({
    time: new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    score: Math.round(a.final_score * 100)
  }));

  return (
    <div>
      <div className="stats-grid">
        <StatCard title="Total Events" value={stats?.total || 0} type="accent" icon={Activity} />
        <StatCard title="Malicious" value={stats?.malicious || 0} type="danger" icon={Target} />
        <StatCard title="Suspicious" value={stats?.suspicious || 0} type="warning" icon={ShieldAlert} />
        <StatCard title="Safe" value={stats?.safe || 0} type="success" icon={ShieldCheck} />
      </div>

      <div className="charts-grid">
        <div className="card">
          <div className="card-header">Threat Timeline (Last 20)</div>
          <div style={{ height: 250 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2a3148" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} domain={[0, 100]} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#1a1f2e', borderColor: '#2a3148' }}
                  itemStyle={{ color: '#06b6d4' }}
                />
                <Line type="monotone" dataKey="score" stroke="#06b6d4" strokeWidth={2} dot={{ r: 4, fill: '#0a0e1a' }} activeDot={{ r: 6 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <ThreatGauge rate={stats?.threat_rate || 0} />
      </div>

      <div className="card">
        <div className="flex justify-between items-center mb-16">
          <div className="card-header" style={{ marginBottom: 0 }}>Recent Alerts</div>
          <button className="btn btn-sm" onClick={() => navigate('/alerts')}>View All</button>
        </div>
        
        <table className="data-table">
          <thead>
            <tr>
              <th>Process</th>
              <th>Classification</th>
              <th>Score</th>
              <th>Time</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 5).map(alert => (
              <tr key={alert.id} onClick={() => navigate(`/alerts/${alert.id}`)}>
                <td className="mono">{alert.process_name}</td>
                <td>
                  <span className={`badge ${alert.classification.toLowerCase()}`}>
                    {alert.classification}
                  </span>
                </td>
                <td>{(alert.final_score * 100).toFixed(0)}%</td>
                <td>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                <td>{alert.status}</td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '30px' }}>No alerts found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
