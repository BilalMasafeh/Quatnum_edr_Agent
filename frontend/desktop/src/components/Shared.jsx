import { AlertTriangle, CheckCircle, HelpCircle } from 'lucide-react';

export function StatusBadge({ classification }) {
  const cls = (classification || '').toLowerCase();
  const icons = {
    safe:               <CheckCircle size={12} />,
    potential_zero_day: <HelpCircle size={12} />,
  };
  const labels = {
    potential_zero_day: 'Zero-Day?',
  };
  return (
    <span className={`badge ${cls}`}>
      {icons[cls] || <AlertTriangle size={12} />}
      {labels[cls] || classification}
    </span>
  );
}

export function ScoreBar({ score, classification }) {
  const colors = { MALICIOUS: '#ef4444', SUSPICIOUS: '#f59e0b', SAFE: '#22c55e', POTENTIAL_ZERO_DAY: '#a855f7' };
  const pct = Math.round((score || 0) * 100);
  return (
    <div className="score-bar">
      <div className="score-bar-track">
        <div className="score-bar-fill" style={{ width: `${pct}%`, backgroundColor: colors[classification] || '#64748b' }} />
      </div>
      <span style={{ fontSize: 12, color: '#94a3b8' }}>{pct}%</span>
    </div>
  );
}
