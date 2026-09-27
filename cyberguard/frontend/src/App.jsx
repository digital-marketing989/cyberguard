import { useState, useCallback } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Sidebar } from './components/Sidebar'
import { ShieldCheck, Flame } from 'lucide-react'
import { ToastProvider } from './components/ui/ToastContext'
import { ToastContainer } from './components/ui/Toast'
import { useWebSocket } from './api/useWebSocket'
import Dashboard from './pages/Dashboard'
import PhishingScan from './pages/PhishingScan'
import DeepfakeScan from './pages/DeepfakeScan'
import ImpersonationScan from './pages/ImpersonationScan'
import AuthAnomalyMonitor from './pages/AuthAnomalyMonitor'
import IncidentDetail from './pages/IncidentDetail'

function AppShell() {
  const [sidebarWidth, setSidebarWidth] = useState(240)

  // Lift WS status to App level so Sidebar can display it
  const { connected: wsConnected, reconnectAttempt } = useWebSocket('/ws/timeline')

  return (
    <div className="flex min-h-screen grid-bg">
      <Sidebar wsConnected={wsConnected} reconnectAttempt={reconnectAttempt} />
      <main
        style={{
          flex: 1,
          overflow: 'auto',
          padding: '20px 32px 32px',
          marginLeft: 'clamp(64px, 15vw, 240px)',
          minWidth: 0,
        }}
      >
        {/* Top Creator Banner */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'linear-gradient(90deg, rgba(59, 130, 246, 0.15) 0%, rgba(139, 92, 246, 0.2) 50%, rgba(16, 185, 129, 0.15) 100%)',
          border: '1px solid rgba(139, 92, 246, 0.35)',
          borderRadius: '12px',
          padding: '10px 18px',
          marginBottom: '20px',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25), 0 0 15px rgba(139, 92, 246, 0.15)',
          backdropFilter: 'blur(10px)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
              color: '#ffffff',
              borderRadius: '6px',
              padding: '2px 8px',
              fontSize: '11px',
              fontWeight: 800,
              letterSpacing: '0.08em',
              textTransform: 'uppercase',
              boxShadow: '0 2px 8px rgba(59,130,246,0.4)'
            }}>
              CREATOR
            </span>
            <span style={{ fontSize: '13px', color: '#e2e8f0', fontWeight: 600, letterSpacing: '0.02em' }}>
              This tool created by — <span style={{ color: '#38bdf8', fontWeight: 800, textShadow: '0 0 12px rgba(56,189,248,0.5)' }}>KRISHNA DAS</span>
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontSize: '11px',
              fontWeight: 700,
              padding: '4px 12px',
              borderRadius: '20px',
              background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(249, 115, 22, 0.15))',
              border: '1px solid rgba(249, 115, 22, 0.4)',
              color: '#fb923c',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 0 12px rgba(249, 115, 22, 0.2)'
            }}>
              <Flame size={13} color="#f97316" className="animate-pulse" />
              <ShieldCheck size={13} color="#34d399" />
              Firewall Protection: ACTIVE
            </span>
          </div>
        </div>

        <Routes>
          <Route path="/"              element={<Dashboard />} />
          <Route path="/phishing"      element={<PhishingScan />} />
          <Route path="/url"           element={<PhishingScan />} />
          <Route path="/deepfake"      element={<DeepfakeScan />} />
          <Route path="/impersonation" element={<ImpersonationScan />} />
          <Route path="/auth"          element={<AuthAnomalyMonitor />} />
          <Route path="/incidents"     element={<IncidentDetail />} />
        </Routes>
      </main>
      <ToastContainer />
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AppShell />
      </ToastProvider>
    </BrowserRouter>
  )
}
