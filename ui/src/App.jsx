import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import {
  Shield, Target, Activity, FileText,
  LayoutDashboard, Puzzle, Settings
} from 'lucide-react'
import Dashboard  from './pages/Dashboard.jsx'
import Targets    from './pages/Targets.jsx'
import Scans      from './pages/Scans.jsx'
import ScanDetail from './pages/ScanDetail.jsx'
import Reports    from './pages/Reports.jsx'
import Plugins    from './pages/Plugins.jsx'

const NAV = [
  { to: '/dashboard', label: 'Dashboard',  Icon: LayoutDashboard },
  { to: '/targets',   label: 'Targets',    Icon: Target },
  { to: '/scans',     label: 'Scans',      Icon: Activity },
  { to: '/reports',   label: 'Reports',    Icon: FileText },
  { to: '/plugins',   label: 'Plugins',    Icon: Puzzle },
]

export default function App() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      <aside style={{
        width: 220,
        background: 'var(--bg2)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        padding: '24px 0',
        flexShrink: 0,
        position: 'sticky',
        top: 0,
        height: '100vh',
      }}>
        {/* Logo */}
        <div style={{ padding: '0 20px 32px', display: 'flex', alignItems: 'center', gap: 10 }}>
          <Shield size={22} color="var(--accent)" />
          <span style={{ fontWeight: 800, fontSize: 16, letterSpacing: '-0.5px' }}>
            WAPT
          </span>
          <span style={{ fontSize: 10, color: 'var(--muted)', marginLeft: 2 }}>
            v0.1
          </span>
        </div>

        {/* Nav links */}
        <nav style={{ flex: 1 }}>
          {NAV.map(({ to, label, Icon }) => (
            <NavLink key={to} to={to} style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              padding: '10px 20px',
              color: isActive ? 'var(--accent2)' : 'var(--muted)',
              background: isActive ? 'rgba(99,102,241,0.1)' : 'transparent',
              borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
              textDecoration: 'none',
              fontSize: 13,
              fontWeight: isActive ? 600 : 400,
              transition: 'all 0.15s',
            })}>
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div style={{ padding: '16px 20px', fontSize: 11, color: 'var(--muted)' }}>
          Use only with permission.
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflow: 'auto' }}>
        <Routes>
          <Route path="/"           element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"  element={<Dashboard />} />
          <Route path="/targets"    element={<Targets />} />
          <Route path="/scans"      element={<Scans />} />
          <Route path="/scans/:id"  element={<ScanDetail />} />
          <Route path="/reports"    element={<Reports />} />
          <Route path="/plugins"    element={<Plugins />} />
        </Routes>
      </main>
    </div>
  )
}