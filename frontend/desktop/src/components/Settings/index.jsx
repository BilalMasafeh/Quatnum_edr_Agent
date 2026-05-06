import { useState } from 'react';
import { Save } from 'lucide-react';

export default function Settings() {
  const [apiHost, setApiHost] = useState('http://localhost:8000');
  const [apiKey, setApiKey] = useState('');
  const [theme, setTheme] = useState('dark');
  const [notifications, setNotifications] = useState(true);

  const handleSave = () => {
    // In a real app, this would save to Electron store or local storage
    alert('Settings saved successfully!');
  };

  return (
    <div style={{ maxWidth: '800px' }}>
      <div className="card">
        <div className="settings-group">
          <h3>Connection Settings</h3>
          <div className="setting-row">
            <div className="setting-label">
              API Host URL
              <small>The URL of the Quantum EDR Backend API.</small>
            </div>
            <input 
              type="text" 
              className="text-input" 
              value={apiHost} 
              onChange={e => setApiHost(e.target.value)} 
            />
          </div>
          <div className="setting-row">
            <div className="setting-label">
              API Key
              <small>Authentication key for the backend API.</small>
            </div>
            <input 
              type="password" 
              className="text-input" 
              value={apiKey} 
              onChange={e => setApiKey(e.target.value)}
              placeholder="••••••••••••••••"
            />
          </div>
        </div>

        <div className="settings-group">
          <h3>Application Preferences</h3>
          <div className="setting-row">
            <div className="setting-label">
              Theme
              <small>Choose the application visual theme.</small>
            </div>
            <select className="search-input" style={{ width: '300px' }} value={theme} onChange={e => setTheme(e.target.value)}>
              <option value="dark">Dark Theme (Cyber)</option>
              <option value="light">Light Theme (Classic)</option>
            </select>
          </div>
          <div className="setting-row">
            <div className="setting-label">
              Desktop Notifications
              <small>Show native OS notifications for MALICIOUS alerts.</small>
            </div>
            <input 
              type="checkbox" 
              checked={notifications} 
              onChange={e => setNotifications(e.target.checked)} 
              style={{ width: '20px', height: '20px', accentColor: 'var(--accent)' }}
            />
          </div>
        </div>

        <div className="flex justify-end" style={{ marginTop: '30px' }}>
          <button className="btn btn-primary" onClick={handleSave}>
            <Save size={16} /> Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}
