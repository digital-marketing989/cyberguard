/**
 * Sidebar Navigation
 * — Responsive: full (240px) on desktop, icon-only (64px) below 1024px
 * — Active page: prominent left accent bar + gradient bg
 * — WS status in footer (green "Live" / red "Reconnecting…")
 */
import { useState, useEffect } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Mail, Link2, Camera, UserX,
  KeyRound, FileText, Shield, ChevronLeft, ChevronRight,
  Wifi, WifiOff
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/',              icon: LayoutDashboard, label: 'Dashboard',       exact: true },
  { to: '/phishing',     icon: Mail,            label: 'Phishing Scan'  },
  { to: '/url',          icon: Link2,           label: 'URL Scanner'    },
  { to: '/deepfake',     icon: Camera,          label: 'Deepfake Detect'},
  { to: '/impersonation',icon: UserX,           label: 'Impersonation'  },
  { to: '/auth',         icon: KeyRound,        label: 'Auth Anomaly'   },
  { to: '/incidents',    icon: FileText,        label: 'Incidents'      },
]

export function Sidebar({ wsConnected, reconnectAttempt }) {
  const [collapsed, setCollapsed] = useState(false)

  // Auto-collapse below 1024px
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 1023px)')
    const handler = (e) => setCollapsed(e.matches)
    setCollapsed(mq.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  const width = collapsed ? 64 : 240

  return (
    <aside
      style={{
        position: 'fixed', left: 0, top: 0,
        height: '100vh', width,
        background: 'rgba(8, 13, 26, 0.96)',
        backdropFilter: 'blur(24px)',
        borderRight: '1px solid rgba(96,165,250,0.10)',
        display: 'flex', flexDirection: 'column',
        zIndex: 40,
        transition: 'width 0.25s cubic-bezier(0.4,0,0.2,1)',
        overflow: 'hidden',
      }}
    >
      {/* Logo + collapse toggle */}
      <div
        style={{
          display: 'flex', alignItems: 'center',
          padding: collapsed ? '16px 0' : '16px 16px 16px 20px',
          justifyContent: collapsed ? 'center' : 'space-between',
          borderBottom: '1px solid rgba(96,165,250,0.08)',
          gap: 10,
          minHeight: 64,
        }}
      >
        {!collapsed && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}>
            <div style={{
              width: 34, height: 34, borderRadius: 8, flexShrink: 0,
              background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
              boxShadow: '0 0 18px rgba(59,130,246,0.4)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={16} color="white" />
            </div>
            <div style={{ overflow: 'hidden' }}>
              <p style={{ fontSize: 13, fontWeight: 700, color: 'white', whiteSpace: 'nowrap' }}>CyberGuard</p>
              <p style={{ fontSize: 10, color: '#38bdf8', fontWeight: 600, whiteSpace: 'nowrap' }}>by Krishna Das</p>
            </div>
          </div>
        )}
        {collapsed && (
          <div style={{
            width: 34, height: 34, borderRadius: 8,
            background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            boxShadow: '0 0 18px rgba(59,130,246,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Shield size={16} color="white" />
          </div>
        )}
        <button
          onClick={() => setCollapsed(c => !c)}
          style={{
            flexShrink: 0,
            width: 24, height: 24, borderRadius: 6,
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.08)',
            color: 'var(--text-muted)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer',
            transition: 'all 0.15s',
          }}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
        </button>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '12px 8px', display: 'flex', flexDirection: 'column', gap: 2, overflowY: 'auto', overflowX: 'hidden' }}>
        {NAV_ITEMS.map(({ to, icon: Icon, label, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            title={collapsed ? label : undefined}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: collapsed ? 0 : 10,
              padding: collapsed ? '10px 0' : '9px 12px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              borderRadius: 8,
              textDecoration: 'none',
              fontSize: 13,
              fontWeight: 500,
              transition: 'all 0.15s ease',
              position: 'relative',
              background: isActive
                ? 'linear-gradient(135deg, rgba(59,130,246,0.2), rgba(139,92,246,0.12))'
                : 'transparent',
              color: isActive ? 'white' : 'var(--text-secondary)',
              borderLeft: isActive ? '2px solid #3b82f6' : '2px solid transparent',
              boxShadow: isActive ? '0 2px 12px rgba(59,130,246,0.15)' : 'none',
            })}
            className={({ isActive }) => isActive ? '' : 'hover:text-white'}
            onMouseEnter={e => {
              if (!e.currentTarget.classList.contains('active')) {
                e.currentTarget.style.background = 'rgba(255,255,255,0.04)'
              }
            }}
            onMouseLeave={e => {
              if (!e.currentTarget.getAttribute('aria-current')) {
                // NavLink manages bg via style prop, just clear if non-active hover
              }
            }}
          >
            <Icon size={16} style={{ flexShrink: 0 }} />
            {!collapsed && (
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', transition: 'opacity 0.2s' }}>
                {label}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Footer — WS status */}
      <div style={{
        padding: collapsed ? '14px 0' : '14px 16px',
        borderTop: '1px solid rgba(96,165,250,0.08)',
        display: 'flex', flexDirection: 'column', gap: 6,
        alignItems: collapsed ? 'center' : 'flex-start',
      }}>
        {/* WS live indicator */}
        <div
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: collapsed ? '4px' : '5px 10px',
            borderRadius: 20,
            background: wsConnected ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
            border: `1px solid ${wsConnected ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)'}`,
          }}
          title={wsConnected ? 'WebSocket connected' : `Reconnecting… (attempt ${reconnectAttempt || 1})`}
        >
          {wsConnected
            ? <Wifi size={12} color="#10b981" />
            : <WifiOff size={12} color="#ef4444" />}
          {!collapsed && (
            <span style={{
              fontSize: 11, fontWeight: 600, whiteSpace: 'nowrap',
              color: wsConnected ? '#34d399' : '#f87171',
            }}>
              {wsConnected ? 'Live' : `Reconnecting${reconnectAttempt > 0 ? ` (${reconnectAttempt})` : '…'}`}
            </span>
          )}
        </div>

        {!collapsed && (
          <p style={{ fontSize: 10, color: 'var(--text-muted)' }}>Capstone Demo v1.0</p>
        )}
      </div>
    </aside>
  )
}
