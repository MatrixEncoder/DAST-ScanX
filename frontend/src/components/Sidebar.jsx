import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Target, Scan, Bug, FileText,
  Zap, Shield
} from 'lucide-react'

const navItems = [
  { to: '/',          icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/targets',   icon: Target,          label: 'Targets' },
  { to: '/scans',     icon: Scan,            label: 'Scans' },
  { to: '/findings',  icon: Bug,             label: 'Findings' },
  { to: '/reports',   icon: FileText,        label: 'Reports' },
]

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <span className="logo-text">SCAN-X</span>
        <div className="logo-sub">DAST Platform v1.0</div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-title">Main</div>
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <Zap size={12} color="#00d4ff" />
          <span style={{ color: '#00d4ff', fontSize: 11, fontWeight: 700 }}>Scan-X</span>
        </div>
        <div>DAST Platform</div>
        <div>Final Year Project 2024</div>
      </div>
    </aside>
  )
}
