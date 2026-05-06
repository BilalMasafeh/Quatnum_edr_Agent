import { NavLink } from 'react-router-dom';
import { LayoutDashboard, ShieldAlert, Activity, Brain, FileText, Settings, Shield } from 'lucide-react';

const icons = { LayoutDashboard, ShieldAlert, Activity, Brain, FileText, Settings };

const NAV = [
  { path: '/', label: 'Dashboard', icon: 'LayoutDashboard' },
  { path: '/alerts', label: 'Alerts', icon: 'ShieldAlert' },
  { path: '/monitor', label: 'Live Monitor', icon: 'Activity' },
  { path: '/analysis', label: 'AI Analysis', icon: 'Brain' },
  { path: '/reports', label: 'Reports', icon: 'FileText' },
  { path: '/settings', label: 'Settings', icon: 'Settings' },
];

export default function Sidebar({ apiStatus }) {
  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <h1><Shield size={22} /> Quantum EDR</h1>
        <p>Endpoint Protection</p>
      </div>
      <nav className="sidebar-nav">
        {NAV.map((item) => {
          const Icon = icons[item.icon];
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} />
              {item.label}
            </NavLink>
          );
        })}
      </nav>
      <div className="sidebar-status">
        <span className={`status-dot ${apiStatus ? 'online' : 'offline'}`} />
        {apiStatus ? 'System Online' : 'Disconnected'}
      </div>
    </div>
  );
}
