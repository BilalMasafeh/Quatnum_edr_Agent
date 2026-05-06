import { useState } from 'react';
import { useWebSocket } from '../../hooks/useWebSocket';
import { Activity } from 'lucide-react';

export default function LiveMonitor() {
  const [events, setEvents] = useState([]);
  
  const { isConnected } = useWebSocket('ws://localhost:8000/ws', (data) => {
    if (data.type === 'new_alert') {
      setEvents(prev => [data, ...prev].slice(0, 100)); // Keep last 100
    }
  });

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 120px)', padding: 0 }}>
      <div className="live-feed-header">
        <div className="flex items-center gap-8">
          <Activity size={18} className="text-accent" />
          <span>Real-time Event Stream</span>
        </div>
        <div className="flex items-center gap-8">
          <span className={`status-dot ${isConnected ? 'online' : 'offline'}`} />
          <span className="text-muted" style={{ fontWeight: 'normal' }}>
            {isConnected ? 'Connected to Engine' : 'Disconnected'}
          </span>
        </div>
      </div>
      
      <div className="live-feed-body" style={{ background: 'var(--bg-primary)' }}>
        {events.length === 0 ? (
          <div className="empty-state" style={{ height: '100%' }}>
            {isConnected ? 'Waiting for security events...' : 'Connecting to event stream...'}
          </div>
        ) : (
          events.map((evt, i) => (
            <div key={i} className={`feed-entry ${evt.classification.toLowerCase()}`}>
              <div className="feed-time">
                {new Date(evt.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' })}
              </div>
              <div className="feed-process">{evt.process}</div>
              <div style={{ flex: 1 }}>
                <span className={`badge ${evt.classification.toLowerCase()}`} style={{ fontSize: '10px', padding: '2px 6px' }}>
                  {evt.classification} ({(evt.score * 100).toFixed(0)}%)
                </span>
              </div>
              <div className="text-muted" style={{ display: 'flex', gap: '8px' }}>
                {evt.indicators && evt.indicators.slice(0, 2).map((ind, idx) => (
                  <span key={idx} style={{ background: 'var(--bg-elevated)', padding: '2px 6px', borderRadius: '4px' }}>
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
