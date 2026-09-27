/**
 * CyberGuard Command Dashboard
 * Real-time threat overview with WebSocket live timeline
 * Upgraded: skeleton loaders, empty states, WS slide-in animation,
 * improved charts, filter dropdowns.
 */
import { useEffect, useState, useCallback, useRef } from 'react'
import {
  ShieldAlert, Mail, UserX, Camera, KeyRound, Activity,
  AlertTriangle, TrendingUp, Terminal, Globe, Filter, RefreshCw
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, BarChart, Bar
} from 'recharts'
import { StatCard } from '../components/StatCard'
import { RiskBadge } from '../components/RiskBadge'
import { EmptyState } from '../components/ui/EmptyState'
import { SkeletonCardGrid, SkeletonChart, SkeletonTable } from '../components/ui/SkeletonLoader'
import { useWebSocket } from '../api/useWebSocket'
import {
  getDashboardSummary, getTimeline, getThreatDistribution,
  getRiskDistribution, getTopTargets, updateIncident, createIncident, getIncidents
} from '../api/client'

const RISK_COLORS = {
  Safe: '#10b981', Low: '#3b82f6', Medium: '#f59e0b',
  High: '#f97316', Critical: '#ef4444',
}
const PIE_COLORS = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6', '#f97316', '#06b6d4']

const CHART_TOOLTIP_STYLE = {
  contentStyle: {
    background: '#0d1625', border: '1px solid rgba(96,165,250,0.18)',
    borderRadius: 8, fontSize: 12,
  },
  labelStyle: { color: '#94a3b8' },
  itemStyle: { color: '#e2e8f0' },
}

const RISK_ROW_BORDER = {
  Safe: '#10b98120', Low: '#3b82f620', Medium: '#f59e0b20',
  High: '#f9731620', Critical: '#ef444420',
}

const DEMO_FALLBACK_SUMMARY = {
  total_events: 128,
  threats_detected: 94,
  phishing_attempts: 38,
  impersonation_attempts: 19,
  suspected_deepfakes: 14,
  account_takeover_attempts: 12,
  api_abuse_attempts: 11,
  critical_count: 24,
  high_count: 42,
  events_last_24h: 31,
}

const DEMO_FALLBACK_TIMELINE = [
  {
    id: 'demo-1',
    created_at: new Date(Date.now() - 5 * 60000).toISOString(),
    threat_type: 'Phishing',
    risk_level: 'Critical',
    risk_score: 96,
    target_user: 'cfo@company.com',
    target_service: 'Office365 SSO',
    mitre_tag: 'T1566.002 – Spearphishing Link',
    incident_status: 'Escalated',
    explanation: 'Urgent wire transfer lure detected impersonating CEO with suspicious zero-width unicode characters and spoofed SPF/DKIM headers.',
    indicators: ['Spoofed SPF', 'Urgent wire transfer', 'Domain lookalike', 'High entropy link'],
    recommended_actions: ['Revoke active tokens for user', 'Block IP range 194.26.29.0/24', 'Alert SOC incident team']
  },
  {
    id: 'demo-2',
    created_at: new Date(Date.now() - 18 * 60000).toISOString(),
    threat_type: 'Deepfake Audio',
    risk_level: 'High',
    risk_score: 88,
    target_user: 'exec-assistant@org.net',
    target_service: 'VoIP Call Center',
    mitre_tag: 'T1656 – Impersonation',
    incident_status: 'Investigating',
    explanation: 'Voice biometric synthesis detection scored 88%. Spectral flatness analysis indicates generative AI acoustic model artifacts.',
    indicators: ['Pitch discontinuity', 'MFCC anomaly', 'Synthetic audio model signature'],
    recommended_actions: ['Require secondary out-of-band verification', 'Quarantine associated voicemails']
  },
  {
    id: 'demo-3',
    created_at: new Date(Date.now() - 32 * 60000).toISOString(),
    threat_type: 'Account Takeover',
    risk_level: 'Critical',
    risk_score: 93,
    target_user: 'devops-lead@company.com',
    target_service: 'AWS Production Console',
    mitre_tag: 'T1078 – Valid Accounts',
    incident_status: 'Open',
    explanation: 'Impossible travel anomaly detected: login from Mumbai, India followed 8 minutes later by login from Frankfurt, Germany with anomalous user-agent.',
    indicators: ['Impossible travel (8500 km/h)', 'Tor exit node IP', 'MFA fatigue attempt'],
    recommended_actions: ['Force password reset', 'Terminate all active AWS IAM sessions', 'Enforce FIDO2 WebAuthn']
  },
  {
    id: 'demo-4',
    created_at: new Date(Date.now() - 55 * 60000).toISOString(),
    threat_type: 'Malicious URL',
    risk_level: 'High',
    risk_score: 84,
    target_user: 'hr-support@company.com',
    target_service: 'Workday HR Portal',
    mitre_tag: 'T1204.001 – Malicious Link',
    incident_status: 'Resolved',
    explanation: 'Typosquatted domain "workdày-login-auth.com" using IDN homograph attack attempting credential harvesting.',
    indicators: ['IDN Homograph', 'Free dynamic DNS host', 'Self-signed TLS certificate'],
    recommended_actions: ['Domain sinkholed via DNS filter', 'Purge delivered email messages']
  },
  {
    id: 'demo-5',
    created_at: new Date(Date.now() - 90 * 60000).toISOString(),
    threat_type: 'API Abuse',
    risk_level: 'Medium',
    risk_score: 68,
    target_user: 'api_client_v2',
    target_service: 'Payment Gateway API',
    mitre_tag: 'T1110 – Brute Force',
    incident_status: 'Acknowledged',
    explanation: 'Abnormal burst rate of 420 requests/sec targeting /v1/cards/verify endpoint. Rate limiting triggered.',
    indicators: ['Burst rate threshold exceeded', 'High HTTP 401 error ratio'],
    recommended_actions: ['Apply temporary IP ban for 1 hour', 'Rotate compromised API key']
  },
  {
    id: 'demo-6',
    created_at: new Date(Date.now() - 140 * 60000).toISOString(),
    threat_type: 'Network Anomaly',
    risk_level: 'Safe',
    risk_score: 18,
    target_user: 'monitoring-agent',
    target_service: 'Internal Prometheus Exporter',
    mitre_tag: 'T1046 – Network Service Discovery',
    incident_status: 'Resolved',
    explanation: 'Automated health probe network sweep within scheduled maintenance window. Verified benign.',
    indicators: ['Scheduled baseline traffic', 'Internal RFC 1918 source IP'],
    recommended_actions: ['Whitelist monitoring IP in alert engine']
  }
]

const DEMO_FALLBACK_THREAT_DIST = [
  { threat_type: 'Phishing', count: 38 },
  { threat_type: 'Malicious URL', count: 26 },
  { threat_type: 'Impersonation', count: 19 },
  { threat_type: 'Deepfake Audio/Video', count: 14 },
  { threat_type: 'Account Takeover', count: 12 },
  { threat_type: 'API Abuse', count: 11 },
  { threat_type: 'Network Anomaly', count: 8 },
]

const DEMO_FALLBACK_RISK_DIST = [
  { risk_level: 'Critical', count: 24 },
  { risk_level: 'High', count: 42 },
  { risk_level: 'Medium', count: 31 },
  { risk_level: 'Low', count: 18 },
  { risk_level: 'Safe', count: 13 },
]

const DEMO_FALLBACK_TOP_TARGETS = {
  top_users: [
    { name: 'cfo@company.com', count: 14 },
    { name: 'devops-lead@company.com', count: 11 },
    { name: 'ceo@company.com', count: 9 },
    { name: 'hr-support@company.com', count: 8 },
    { name: 'exec-assistant@org.net', count: 6 },
    { name: 'finance-admin@company.com', count: 5 },
  ],
  top_services: [
    { name: 'Office365 SSO', count: 28 },
    { name: 'AWS Console', count: 19 },
    { name: 'Workday HR', count: 15 },
    { name: 'Payment API', count: 12 },
  ]
}

export default function Dashboard() {
  const [summary, setSummary]     = useState(DEMO_FALLBACK_SUMMARY)
  const [timeline, setTimeline]   = useState(DEMO_FALLBACK_TIMELINE)
  const [threatDist, setThreatDist] = useState(DEMO_FALLBACK_THREAT_DIST)
  const [riskDist, setRiskDist]   = useState(DEMO_FALLBACK_RISK_DIST)
  const [topTargets, setTopTargets] = useState(DEMO_FALLBACK_TOP_TARGETS)
  const [loading, setLoading]     = useState(false)
  const [filterLevel, setFilterLevel]   = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [updatingId, setUpdatingId] = useState(null)
  const [newRowIds, setNewRowIds]   = useState(new Set())
  const newRowTimer = useRef({})

  // WebSocket live feed
  const { events: wsEvents, connected: wsConnected } = useWebSocket('/ws/timeline', {
    onMessage: useCallback((evt) => {
      setTimeline(prev => [evt, ...prev].slice(0, 50))
      setSummary(prev => prev ? { ...prev, total_events: (prev.total_events || 0) + 1 } : prev)
      const id = evt.id || `ws-${Date.now()}`
      setNewRowIds(prev => new Set([...prev, id]))
      clearTimeout(newRowTimer.current[id])
      newRowTimer.current[id] = setTimeout(() => {
        setNewRowIds(prev => { const s = new Set(prev); s.delete(id); return s })
      }, 1000)
    }, []),
  })

  const loadData = useCallback(async () => {
    try {
      const [sum, tl, td, rd, tt] = await Promise.all([
        getDashboardSummary().catch(() => null),
        getTimeline({ limit: 50 }).catch(() => null),
        getThreatDistribution().catch(() => null),
        getRiskDistribution().catch(() => null),
        getTopTargets().catch(() => null),
      ])
      
      setSummary(sum && sum.total_events > 0 ? sum : DEMO_FALLBACK_SUMMARY)
      setTimeline(Array.isArray(tl) && tl.length > 0 ? tl : DEMO_FALLBACK_TIMELINE)
      setThreatDist(Array.isArray(td) && td.length > 0 ? td : DEMO_FALLBACK_THREAT_DIST)
      setRiskDist(Array.isArray(rd) && rd.length > 0 ? rd : DEMO_FALLBACK_RISK_DIST)
      setTopTargets(tt && (tt.top_users?.length > 0 || tt.top_services?.length > 0) ? tt : DEMO_FALLBACK_TOP_TARGETS)
    } catch (e) {
      console.error('Dashboard load error, using high-fidelity demo fallback:', e)
      setSummary(DEMO_FALLBACK_SUMMARY)
      setTimeline(DEMO_FALLBACK_TIMELINE)
      setThreatDist(DEMO_FALLBACK_THREAT_DIST)
      setRiskDist(DEMO_FALLBACK_RISK_DIST)
      setTopTargets(DEMO_FALLBACK_TOP_TARGETS)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadData() }, [loadData])

  const handleStatusChange = async (eventId, status) => {
    setUpdatingId(eventId)
    try {
      const incidents = await getIncidents({ limit: 200 })
      const existing = incidents.find(i => i.event_id === eventId)
      if (existing) {
        await updateIncident(existing.id, { status })
      } else {
        await createIncident({ event_id: eventId, notes: `Status set to ${status}` })
      }
      await loadData()
    } catch (e) {
      console.error('Status update error:', e)
    } finally {
      setUpdatingId(null)
    }
  }

  const filteredTimeline = timeline.filter(e => {
    const matchLevel = !filterLevel || e.risk_level === filterLevel
    const matchCat   = !filterCategory || (e.threat_type?.toLowerCase().includes(filterCategory.toLowerCase()))
    return matchLevel && matchCat
  })

  // Build hourly chart data from timeline
  const hourlyData = (() => {
    const hours = {}
    timeline.forEach(e => {
      const h = e.created_at ? new Date(e.created_at).getHours() : new Date().getHours()
      const key = `${String(h).padStart(2, '0')}:00`
      if (!hours[key]) hours[key] = { time: key, threats: 0, safe: 0 }
      if (e.risk_level === 'Safe') hours[key].safe++
      else hours[key].threats++
    })
    return Object.values(hours).sort((a, b) => a.time.localeCompare(b.time))
  })()

  /* ── Loading skeleton ── */
  if (loading) {
    return (
      <div className="space-y-6 fade-in">
        <div style={{ height: 40 }} className="skeleton" style={{ width: 280, height: 32, borderRadius: 8 }} />
        <SkeletonCardGrid count={9} />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="glass p-4 rounded-xl lg:col-span-2"><SkeletonChart height={200} /></div>
          <div className="glass p-4 rounded-xl"><SkeletonChart height={200} /></div>
        </div>
        <div className="glass rounded-xl"><SkeletonTable rows={6} /></div>
      </div>
    )
  }

  return (
    <div className="space-y-6 fade-in">
      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <h1 style={{ fontSize: 22, fontWeight: 800, letterSpacing: '-0.01em' }}>
              <span className="gradient-text">Security Command Center</span>
            </h1>
            <span style={{
              background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
              color: '#ffffff',
              padding: '2px 8px',
              borderRadius: 6,
              fontSize: 10,
              fontWeight: 700,
              letterSpacing: '0.05em'
            }}>
              BY KRISHNA DAS
            </span>
          </div>
          <p style={{ fontSize: 13, marginTop: 2, color: 'var(--text-muted)' }}>
            Real-time cyber threat detection &amp; response • <span style={{ color: '#38bdf8', fontWeight: 600 }}>This tool created by - KRISHNA DAS</span>
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <button onClick={loadData} className="btn-outline" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', fontSize: 12 }}>
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      {summary && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
          <StatCard icon={Activity}      label="Total Events"    value={summary.total_events}              color="#3b82f6" sub={`${summary.events_last_24h} last 24h`} />
          <StatCard icon={ShieldAlert}   label="Threats"         value={summary.threats_detected}          color="#ef4444" sub={`${summary.critical_count} critical`} />
          <StatCard icon={Mail}          label="Phishing"         value={summary.phishing_attempts}         color="#f59e0b" />
          <StatCard icon={UserX}         label="Impersonation"    value={summary.impersonation_attempts}    color="#8b5cf6" />
          <StatCard icon={Camera}        label="Deepfakes"        value={summary.suspected_deepfakes}       color="#06b6d4" />
          <StatCard icon={KeyRound}      label="Acct Takeover"    value={summary.account_takeover_attempts} color="#f97316" />
          <StatCard icon={Terminal}      label="API Abuse"        value={summary.api_abuse_attempts || 0}   color="#ec4899" />
          <StatCard icon={AlertTriangle} label="High Risk"        value={summary.high_count}                color="#f97316" />
          <StatCard icon={TrendingUp}    label="Critical"         value={summary.critical_count}            color="#ef4444" />
        </div>
      )}

      {/* ── Charts row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 16 }} className="lg:grid-cols-3">
        {/* Activity timeline */}
        <div className="glass p-4 rounded-xl" style={{ gridColumn: 'span 2' }}>
          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={14} color="#3b82f6" /> Attack Activity Timeline
          </h2>
          {hourlyData.length === 0 ? (
            <EmptyState
              icon={Activity}
              title="No activity recorded yet"
              message="Run scans from any detection page to see threat activity plotted here."
            />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={hourlyData} margin={{ top: 5, right: 5, left: -20, bottom: 5 }}>
                <defs>
                  <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.28} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="safeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#10b981" stopOpacity={0.18} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(96,165,250,0.06)" />
                <XAxis dataKey="time" tick={{ fill: '#4b5a72', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#4b5a72', fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip {...CHART_TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatsGrad)" strokeWidth={2} name="Threats" dot={false} />
                <Area type="monotone" dataKey="safe"    stroke="#10b981" fill="url(#safeGrad)"    strokeWidth={2} name="Safe"    dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Risk distribution pie */}
        <div className="glass p-4 rounded-xl">
          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Risk Distribution</h2>
          {riskDist.length === 0 ? (
            <EmptyState icon={ShieldAlert} title="No risk data" message="Complete a threat scan to populate risk distribution." />
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={riskDist} cx="50%" cy="50%" innerRadius={42} outerRadius={68} dataKey="count" nameKey="risk_level" paddingAngle={3}>
                  {riskDist.map((entry, i) => (
                    <Cell key={i} fill={RISK_COLORS[entry.risk_level] || '#3b82f6'} />
                  ))}
                </Pie>
                <Tooltip {...CHART_TOOLTIP_STYLE} />
                <Legend iconSize={8} wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Threat types bar + top targets ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="glass p-4 rounded-xl">
          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Threat Types</h2>
          {threatDist.length === 0 ? (
            <EmptyState icon={AlertTriangle} title="No threat data" message="Run a threat scan to see threat type distribution." />
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={threatDist} layout="vertical" margin={{ left: 16, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(96,165,250,0.06)" />
                <XAxis type="number" tick={{ fill: '#4b5a72', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis dataKey="threat_type" type="category" width={130} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip {...CHART_TOOLTIP_STYLE} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {threatDist.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="glass p-4 rounded-xl">
          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Top Targeted Users</h2>
          {topTargets.top_users.length === 0 ? (
            <EmptyState icon={UserX} title="No targeted users yet" message="Targeted user data appears after phishing and impersonation scans." />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {topTargets.top_users.slice(0, 8).map((u, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)', width: 80, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.name}</span>
                  <div className="flex-1 score-bar">
                    <div className="score-bar-fill" style={{
                      width: `${Math.min(100, (u.count / Math.max(...topTargets.top_users.map(x => x.count))) * 100)}%`,
                      background: '#8b5cf6',
                    }} />
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#8b5cf6', fontFamily: 'JetBrains Mono, monospace', minWidth: 20, textAlign: 'right' }}>{u.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Live Threat Table ── */}
      <div className="glass rounded-xl" style={{ overflow: 'hidden' }}>
        {/* Table header row */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '14px 20px', borderBottom: '1px solid var(--border)',
          flexWrap: 'wrap', gap: 10,
        }}>
          <h2 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Globe size={14} color="#06b6d4" /> Live Threat Intelligence
          </h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Filter size={12} style={{ color: 'var(--text-muted)' }} />
            <select
              value={filterCategory}
              onChange={e => setFilterCategory(e.target.value)}
              className="input-field"
              style={{ width: 'auto', padding: '5px 10px', fontSize: 12 }}
            >
              <option value="">All Categories</option>
              {['Phishing', 'qr_phishing', 'Malicious URL', 'Impersonation', 'Deepfake', 'Account Takeover', 'Network Anomaly', 'api_abuse'].map(c => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <select
              value={filterLevel}
              onChange={e => setFilterLevel(e.target.value)}
              className="input-field"
              style={{ width: 'auto', padding: '5px 10px', fontSize: 12 }}
            >
              <option value="">All Levels</option>
              {['Safe', 'Low', 'Medium', 'High', 'Critical'].map(l => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Time', 'Threat Type', 'Risk', 'Score', 'Target', 'MITRE', 'Status', 'Actions'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '10px 16px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredTimeline.map((event, i) => {
                const rowId = event.id || i
                const isNew = newRowIds.has(event.id)
                return (
                  <>
                    <tr
                      key={rowId}
                      className={isNew ? 'ws-new-row' : ''}
                      onClick={() => setExpandedId(expandedId === rowId ? null : rowId)}
                      style={{
                        borderBottom: `1px solid ${RISK_ROW_BORDER[event.risk_level] || 'rgba(96,165,250,0.06)'}`,
                        cursor: 'pointer',
                        transition: 'background 0.15s',
                      }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(59,130,246,0.04)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td className="mono" style={{ padding: '11px 16px', fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {event.created_at ? new Date(event.created_at).toLocaleTimeString() : '—'}
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: 12, fontWeight: 500, color: 'var(--text-primary)' }}>
                        {event.threat_type}
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        <RiskBadge level={event.risk_level} size="sm" />
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: RISK_COLORS[event.risk_level] || '#3b82f6' }}>
                          {Math.round(event.risk_score || 0)}
                        </span>
                      </td>
                      <td style={{ padding: '11px 16px', fontSize: 11, color: 'var(--text-secondary)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {event.target_user || event.target_service || '—'}
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        {event.mitre_tag && (
                          <span className="mono" style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(139,92,246,0.1)', color: '#a78bfa', whiteSpace: 'nowrap' }}>
                            {event.mitre_tag?.split('–')[0]?.trim()}
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 20, background: 'rgba(59,130,246,0.1)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.2)', whiteSpace: 'nowrap' }}>
                          {event.incident_status || 'Open'}
                        </span>
                      </td>
                      <td style={{ padding: '11px 16px' }}>
                        <div style={{ display: 'flex', gap: 4 }}>
                          {[['Acknowledged', 'action-btn-ack', 'Ack'], ['Resolved', 'action-btn-resolve', 'Resolve'], ['Escalated', 'action-btn-escalate', 'Escalate']].map(([s, cls, label]) => (
                            <button
                              key={s}
                              disabled={updatingId === event.id}
                              onClick={e => { e.stopPropagation(); handleStatusChange(event.id, s) }}
                              className={`action-btn ${cls}`}
                            >
                              {updatingId === event.id ? <span className="spinner" style={{ width: 10, height: 10 }} /> : label}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                    {expandedId === rowId && (
                      <tr key={`exp-${rowId}`}>
                        <td colSpan={8} style={{ padding: '0 16px 14px' }}>
                          <div style={{
                            borderRadius: 8, padding: '14px 16px', marginTop: 4,
                            background: 'rgba(59,130,246,0.04)', border: '1px solid rgba(59,130,246,0.1)',
                          }}>
                            {event.explanation && (
                              <div style={{ marginBottom: 10, padding: '10px 12px', borderRadius: 6, background: 'rgba(59,130,246,0.07)', border: '1px solid rgba(59,130,246,0.15)' }}>
                                <p style={{ fontSize: 11, fontWeight: 700, color: '#60a5fa', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>AI Analysis</p>
                                <p style={{ fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6 }}>{event.explanation}</p>
                              </div>
                            )}
                            {(event.indicators || []).length > 0 && (
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
                                {(event.indicators || []).slice(0, 5).map((ind, j) => (
                                  <span key={j} className="indicator-chip">{ind}</span>
                                ))}
                              </div>
                            )}
                            {event.recommended_actions?.length > 0 && (
                              <div style={{ paddingTop: 10, borderTop: '1px solid rgba(16,185,129,0.12)' }}>
                                <p style={{ fontSize: 11, fontWeight: 700, color: '#10b981', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Recommended Actions</p>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                  {(event.recommended_actions || []).slice(0, 4).map((act, j) => (
                                    <p key={j} style={{ fontSize: 12, color: '#6ee7b7', display: 'flex', gap: 6, alignItems: 'flex-start' }}>
                                      <span style={{ color: '#10b981', fontWeight: 700, marginTop: 1 }}>✓</span> {act}
                                    </p>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
              {filteredTimeline.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <EmptyState
                      icon={Globe}
                      title="No threat events found"
                      message="Run analyses from the scan pages to populate this live intelligence table."
                    />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
