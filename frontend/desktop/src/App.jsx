import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout/Layout';
import Dashboard from './components/Dashboard';
import Alerts from './components/Alerts';
import AlertDetail from './components/Alerts/AlertDetail';
import LiveMonitor from './components/Monitor';
import AIAnalysis from './components/AI';
import Reports from './components/Reports';
import Settings from './components/Settings';
import './index.css';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="alerts/:id" element={<AlertDetail />} />
          <Route path="monitor" element={<LiveMonitor />} />
          <Route path="analysis" element={<AIAnalysis />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
