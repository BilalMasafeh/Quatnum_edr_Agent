import { Bell, User } from 'lucide-react';

export default function Header({ title }) {
  return (
    <header className="page-header titlebar-drag">
      <div>
        <h2 className="titlebar-no-drag">{title}</h2>
      </div>
      <div className="flex items-center gap-16 titlebar-no-drag">
        <button className="btn-icon">
          <Bell size={18} className="text-muted" />
        </button>
        <div className="flex items-center gap-8">
          <div className="btn-icon" style={{ background: 'var(--bg-elevated)', borderRadius: '50%' }}>
            <User size={16} />
          </div>
          <span className="text-muted" style={{ fontSize: '13px' }}>Admin</span>
        </div>
      </div>
    </header>
  );
}
