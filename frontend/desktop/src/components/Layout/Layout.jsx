import { Outlet, useLocation } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import { useApi } from '../../hooks/useApi';

const PAGE_TITLES = {
  '/': 'Dashboard Overview',
  '/alerts': 'Alert Management',
  '/monitor': 'Live Activity Monitor',
  '/analysis': 'AI Threat Analysis',
  '/reports': 'Incident Reports',
  '/settings': 'System Settings'
};

export default function Layout() {
  const location = useLocation();
  const { isOnline } = useApi();
  
  // Extract base path for detail pages (e.g. /alerts/123 -> /alerts)
  const basePath = '/' + location.pathname.split('/')[1];
  const title = PAGE_TITLES[basePath] || PAGE_TITLES[location.pathname] || 'Quantum EDR';

  return (
    <div className="app-layout">
      <Sidebar apiStatus={isOnline} />
      <main className="main-content">
        <Header title={title} />
        <div className="page-body">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
