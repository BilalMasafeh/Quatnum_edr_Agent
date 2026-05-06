import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { getAlert, updateAlertStatus, analyzeAlert } from '../../utils/api';
import { ArrowLeft, ShieldAlert, Brain, Activity, Clock, Terminal } from 'lucide-react';
import { SEVERITY_COLORS } from '../../utils/constants';

export default function AlertDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);

  useEffect(() => {
    const fetchAlert = async () => {
      try {
        const res = await getAlert(id);
        setData(res);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchAlert();
  }, [id]);

  const handleStatusChange = async (status) => {
    try {
      await updateAlertStatus(id, status);
      setData({ ...data, alert: { ...data.alert, status } });
    } catch (err) {
      console.error(err);
    }
  };

  const handleAIAnalysis = async () => {
    setAnalyzing(true);
    try {
      await analyzeAlert(id);
      // Reload alert to get new analyses
      const res = await getAlert(id);
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(false);
    }
  };

  if (loading) return <div className="loading-state"><div className="spinner" />Loading Alert Details...</div>;
  if (!data) return <div className="empty-state">Alert not found</div>;

  const { alert, responses, analyses } = data;
  const latestAnalysis = analyses.length > 0 ? analyses[0] : null;

  return (
    <div>
      <div className="flex items-center gap-16 mb-24">
        <button className="btn-icon" onClick={() => navigate(-1)} style={{ border: '1px solid var(--border)' }}>
          <ArrowLeft size={16} />
        </button>
        <div>
          <div className="flex items-center gap-12">
            <h2 style={{ fontSize: '24px', fontWeight: '700' }}>{alert.process_name}</h2>
            <span className={`badge ${alert.classification.toLowerCase()}`}>
              {alert.classification}
            </span>
            <span className="badge info">PID: {alert.pid}</span>
          </div>
          <div className="text-muted mt-4">
            Alert #{alert.id} • Detected {new Date(alert.timestamp).toLocaleString()}
          </div>
        </div>
        <div className="flex gap-8" style={{ marginLeft: 'auto' }}>
          <select 
            className="search-input" 
            style={{ width: '120px' }}
            value={alert.status}
            onChange={(e) => handleStatusChange(e.target.value)}
          >
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="dismissed">Dismissed</option>
          </select>
          <button className="btn btn-primary" onClick={handleAIAnalysis} disabled={analyzing}>
            <Brain size={14} /> {analyzing ? 'Analyzing...' : 'Run AI Analysis'}
          </button>
        </div>
      </div>

      <div className="charts-grid">
        <div className="flex" style={{ flexDirection: 'column', gap: '16px' }}>
          
          {latestAnalysis ? (
            <div className="analysis-section" style={{ border: '1px solid var(--purple)', boxShadow: '0 0 15px var(--purple-bg)' }}>
              <div className="analysis-section-header" style={{ background: 'var(--purple-bg)', borderBottomColor: 'var(--purple)40' }}>
                <Brain size={16} color="var(--purple)" /> 
                <span>AI Threat Assessment</span>
                <span className="badge" style={{ marginLeft: 'auto', background: 'transparent', border: '1px solid var(--purple)', color: 'var(--purple)' }}>
                  {latestAnalysis.threat_type}
                </span>
              </div>
              <div className="analysis-section-body">
                <p style={{ marginBottom: '16px', lineHeight: '1.6' }}>{latestAnalysis.explanation}</p>
                
                <h4 style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>MITRE ATT&CK</h4>
                <div style={{ marginBottom: '16px' }}>
                  {latestAnalysis.mitre_techniques.map(t => (
                    <span key={t} className="mitre-tag">{t}</span>
                  ))}
                  {latestAnalysis.mitre_techniques.length === 0 && <span className="text-muted">No specific techniques identified</span>}
                </div>

                <h4 style={{ fontSize: '12px', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>Recommendation</h4>
                <div style={{ padding: '12px', background: 'var(--bg-secondary)', borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--warning)' }}>
                  {latestAnalysis.recommended_action}
                </div>
              </div>
            </div>
          ) : (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '40px 20px', gap: '16px', borderStyle: 'dashed' }}>
              <Brain size={48} className="text-muted" opacity={0.3} />
              <div style={{ textAlign: 'center' }}>
                <h3 style={{ color: 'var(--text-primary)', marginBottom: '8px' }}>No AI Analysis Available</h3>
                <p className="text-muted" style={{ marginBottom: '16px', maxWidth: '300px' }}>Run a deep AI analysis to get threat classification, MITRE mapping, and remediation steps.</p>
                <button className="btn btn-primary" onClick={handleAIAnalysis} disabled={analyzing}>
                  {analyzing ? 'Analyzing...' : 'Analyze Now'}
                </button>
              </div>
            </div>
          )}

          <div className="card">
            <div className="card-header"><Activity size={14} style={{ display: 'inline', marginRight: '6px' }}/> Behavioral Telemetry</div>
            <div className="detail-grid">
              <div className="detail-row">
                <span className="detail-label">Network Connections</span>
                <span className="detail-value mono">{alert.network_connections}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">File Writes</span>
                <span className="detail-value mono">{alert.file_writes}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Registry Changes</span>
                <span className="detail-value mono">{alert.registry_changes}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Child Processes</span>
                <span className="detail-value mono">{alert.child_processes}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Unique IPs</span>
                <span className="detail-value mono">{alert.unique_ips}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Suspicious Ports</span>
                <span className="detail-value mono text-danger">{alert.suspicious_ports}</span>
              </div>
            </div>
          </div>
        </div>

        <div className="flex" style={{ flexDirection: 'column', gap: '16px' }}>
          <div className="card">
            <div className="card-header"><Terminal size={14} style={{ display: 'inline', marginRight: '6px' }}/> Process Info</div>
            <div className="detail-row">
              <span className="detail-label">Process Name</span>
              <span className="detail-value mono">{alert.process_name}</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">PID</span>
              <span className="detail-value mono">{alert.pid}</span>
            </div>
            <div className="detail-row">
              <span className="detail-label">Parent Process</span>
              <span className="detail-value mono">{alert.parent_process}</span>
            </div>
          </div>

          <div className="card">
            <div className="card-header">Machine Learning Scores</div>
            <div style={{ marginBottom: '16px' }}>
              <div className="flex justify-between mb-8">
                <span className="text-muted" style={{ fontSize: '12px' }}>Final Hybrid Score</span>
                <span className="mono">{(alert.final_score * 100).toFixed(1)}%</span>
              </div>
              <div className="score-bar-track" style={{ width: '100%', height: '8px' }}>
                <div className="score-bar-fill" style={{ width: `${alert.final_score * 100}%`, background: 'var(--accent)' }} />
              </div>
            </div>
            
            <div style={{ marginBottom: '16px' }}>
              <div className="flex justify-between mb-8">
                <span className="text-muted" style={{ fontSize: '12px' }}>Classical RF</span>
                <span className="mono">{alert.rf_score ? `${(alert.rf_score * 100).toFixed(1)}%` : 'N/A'}</span>
              </div>
              <div className="score-bar-track" style={{ width: '100%' }}>
                <div className="score-bar-fill" style={{ width: `${(alert.rf_score || 0) * 100}%`, background: 'var(--text-muted)' }} />
              </div>
            </div>

            <div style={{ marginBottom: '8px' }}>
              <div className="flex justify-between mb-8">
                <span className="text-muted" style={{ fontSize: '12px' }}>Quantum SVM</span>
                <span className="mono">{alert.qsvm_score ? `${(alert.qsvm_score * 100).toFixed(1)}%` : 'N/A'}</span>
              </div>
              <div className="score-bar-track" style={{ width: '100%' }}>
                <div className="score-bar-fill" style={{ width: `${(alert.qsvm_score || 0) * 100}%`, background: 'var(--purple)' }} />
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-header"><Clock size={14} style={{ display: 'inline', marginRight: '6px' }}/> Automated Responses</div>
            {responses.length === 0 ? (
              <div className="text-muted" style={{ fontStyle: 'italic', fontSize: '12px' }}>No automated actions taken.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {responses.map(r => (
                  <div key={r.id} style={{ padding: '10px', background: 'var(--bg-secondary)', borderLeft: `3px solid ${r.success ? 'var(--success)' : 'var(--danger)'}`, borderRadius: '4px' }}>
                    <div className="flex justify-between items-center mb-4">
                      <span style={{ fontWeight: '600', fontSize: '13px' }}>{r.action_type.replace(/_/g, ' ')}</span>
                      <span className="text-muted" style={{ fontSize: '11px' }}>{new Date(r.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-muted" style={{ fontSize: '12px' }}>{r.details}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
