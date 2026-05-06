import { useState } from 'react';
import { Brain, Search } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { analyzeAlert } from '../../utils/api';

export default function AIAnalysis() {
  const [alertId, setAlertId] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const navigate = useNavigate();

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!alertId) return;
    
    setAnalyzing(true);
    try {
      await analyzeAlert(alertId);
      navigate(`/alerts/${alertId}`);
    } catch (err) {
      console.error(err);
      alert('Analysis failed. Please check the alert ID.');
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', paddingTop: '40px' }}>
      <div className="card" style={{ textAlign: 'center', padding: '40px' }}>
        <Brain size={48} className="text-purple" style={{ marginBottom: '20px' }} />
        <h2 style={{ fontSize: '24px', marginBottom: '12px' }}>Deep Threat Analysis</h2>
        <p className="text-muted" style={{ marginBottom: '32px' }}>
          Enter an Alert ID to run a multi-stage AI analysis pipeline. The system will classify the threat, extract behavioral indicators, map to MITRE ATT&CK, and generate response recommendations.
        </p>
        
        <form onSubmit={handleAnalyze} style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
          <div style={{ position: 'relative' }}>
            <Search size={16} className="text-muted" style={{ position: 'absolute', left: '12px', top: '10px' }} />
            <input 
              type="text" 
              className="search-input" 
              placeholder="Alert ID (e.g., 42)" 
              style={{ paddingLeft: '36px', width: '250px', height: '36px' }}
              value={alertId}
              onChange={(e) => setAlertId(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={analyzing || !alertId}>
            {analyzing ? 'Analyzing...' : 'Run Analysis'}
          </button>
        </form>
      </div>
    </div>
  );
}
