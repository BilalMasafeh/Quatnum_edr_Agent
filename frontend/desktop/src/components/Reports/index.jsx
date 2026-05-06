import { useState, useEffect } from 'react';
import { getStats } from '../../utils/api';
import { FileText, Download } from 'lucide-react';

export default function Reports() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    getStats().then(setStats).catch(console.error);
  }, []);

  return (
    <div>
      <div className="flex justify-between items-center mb-24">
        <p className="text-muted">Generated incident reports and system summaries.</p>
        <button className="btn btn-primary">
          <Download size={14} /> Export Global Report
        </button>
      </div>

      <div className="card">
        <div className="card-header">Weekly Summary</div>
        {stats ? (
          <div className="detail-grid">
            <div className="detail-row">
              <span className="detail-label">Total Events Analyzed</span>
              <span className="detail-value mono">{stats.total}</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">Malicious Threats Prevented</span>
              <span className="detail-value mono text-danger">{stats.malicious}</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">Suspicious Behaviors Detected</span>
              <span className="detail-value mono text-warning">{stats.suspicious}</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">Open Alerts Requiring Review</span>
              <span className="detail-value mono text-accent">{stats.open_alerts}</span>
            </div>
          </div>
        ) : (
          <div className="loading-state">Loading report data...</div>
        )}
      </div>
      
      <div className="empty-state" style={{ marginTop: '20px', border: '1px dashed var(--border)', borderRadius: 'var(--radius)' }}>
        <FileText size={32} className="text-muted" style={{ marginBottom: '10px' }} />
        <h3>No Custom Reports</h3>
        <p>Use the AI Analysis on specific alerts to generate detailed incident reports.</p>
      </div>
    </div>
  );
}
