/**
 * Incident Management Dashboard
 * Upgraded: toast notifications, risk level filter, real-time sync with WS,
 * inline action buttons, loading skeletons.
 */
import { useEffect, useState, useCallback, useMemo } from 'react'
import { FileText, Search, Filter, AlertTriangle, ShieldCheck, Clock, RefreshCw, XCircle } from 'lucide-react'
import { getIncidents, updateIncident, createIncident } from '../api/client'
import { EvidencePanel } from '../components/EvidencePanel'
import { RiskBadge } from '../components/RiskBadge'
import { EmptyState } from '../components/ui/EmptyState'
import { SkeletonCardGrid, SkeletonTable } from '../components/ui/SkeletonLoader'
import { useToast } from '../components/ui/ToastContext'
import { useWebSocket } from '../api/useWebSocket'

const INCIDENT_STATUSES = ['Open', 'Acknowledged', 'Escalated', 'Resolved', 'False Positive']

const RISK_ROW_BORDER = {
  Safe: '#10b98120', Low: '#3b82f620', Medium: '#f59e0b20',
  High: '#f9731620', Critical: '#ef444420',
}

const RISK_COLORS = {
  Safe: '#10b981', Low: '#3b82f6', Medium: '#f59e0b',
  High: '#f97316', Critical: '#ef4444',
}

export default function IncidentDetail() {
  const { addToast } = useToast()
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading]     = useState(true)
  const [search, setSearch]       = useState('')
  const [statusFilter, setStatusFilter] = useState('Open,Acknowledged,Escalated')
  const [riskFilter, setRiskFilter]     = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [updatingId, setUpdatingId] = useState(null)

  // Sync new events from WebSocket into the incidents list automatically
  useWebSocket('/ws/timeline', {
    onMessage: useCallback((evt) => {
      // Avoid adding duplicate events. If it's a new event, we might need to create an incident for it
      // or just refresh. Let's just refresh if we see a new event that matches our current filters.
      // But to be gentle on the API, we only auto-refresh if we are viewing 'Open' incidents.
      if (statusFilter.includes('Open') && !search) {
        loadData(false)
      }
    }, [statusFilter, search])
  })

  const loadData = useCallback(async (showLoading = true) => {
    if (showLoading) setLoading(true)
    try {
      const data = await getIncidents({ limit: 200, status: statusFilter === 'ALL' ? undefined : statusFilter })
      // Sort by creation date DESC
      data.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      setIncidents(data)
    } catch (e) {
      console.error('Failed to load incidents:', e)
      if (showLoading) addToast({ message: 'Failed to load incidents', type: 'error' })
    } finally {
      if (showLoading) setLoading(false)
    }
  }, [statusFilter, addToast])

  useEffect(() => { loadData() }, [loadData])

  const handleStatusUpdate = async (id, newStatus, currentEvent) => {
    setUpdatingId(id || currentEvent?.id)
    try {
      if (id) {
        await updateIncident(id, { status: newStatus })
      } else if (currentEvent) {
        // Incident doesn't exist yet, create it from the event
        await createIncident({ event_id: currentEvent.id, notes: `Status set to ${newStatus}` })
      }
      addToast({ message: `Incident marked as ${newStatus}`, type: 'success' })
      await loadData(false)
    } catch (e) {
      addToast({ message: `Failed to update status: ${e.message}`, type: 'error' })
    } finally {
      setUpdatingId(null)
      if (['Resolved', 'False Positive'].includes(newStatus) && !statusFilter.includes(newStatus)) {
        setExpandedId(null)
      }
    }
  }

  // Filter client-side by search and risk level
  const filtered = useMemo(() => {
    return incidents.filter(inc => {
      const matchSearch = search.trim() === '' ||
        (inc.event?.threat_type || '').toLowerCase().includes(search.toLowerCase()) ||
        (inc.id).toLowerCase().includes(search.toLowerCase()) ||
        (inc.event?.target_user || '').toLowerCase().includes(search.toLowerCase())
      
      const matchRisk = riskFilter === '' || (inc.event?.risk_level === riskFilter)

      return matchSearch && matchRisk
    })
  }, [incidents, search, riskFilter])

  // Stats
  const stats = useMemo(() => {
    let open = 0, escalated = 0, resolved = 0, fp = 0
    incidents.forEach(inc => {
      if (inc.status === 'Open' || inc.status === 'Acknowledged') open++
      else if (inc.status === 'Escalated') escalated++
      else if (inc.status === 'Resolved') resolved++
      else if (inc.status === 'False Positive') fp++
    })
    return { open, escalated, resolved, fp }
  }, [incidents])

  if (loading && incidents.length === 0) {
    return (
      <div className="space-y-6 fade-in">
        <div className="skeleton" style={{ width: 280, height: 32, borderRadius: 8 }} />
        <SkeletonCardGrid count={4} />
        <div className="glass rounded-xl"><SkeletonTable rows={10} /></div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }} className="fade-in">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
            <FileText size={22} color="#f97316" />
            <span className="gradient-text">Incident Management</span>
          </h1>
          <p style={{ marginTop: 4, fontSize: 13, color: 'var(--text-secondary)' }}>
            Investigate, triage, and resolve detected security events.
          </p>
        </div>
        <button onClick={() => loadData()} className="btn-outline" style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', fontSize: 12 }}>
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
        <div className="glass" style={{ padding: '16px 20px', borderTop: '2px solid #3b82f6' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', marginBottom: 8 }}>
            <AlertTriangle size={14} color="#3b82f6" />
            <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Open / Ack</span>
          </div>
          <p className="mono" style={{ fontSize: 28, fontWeight: 800, color: '#60a5fa' }}>{stats.open}</p>
        </div>
        <div className="glass" style={{ padding: '16px 20px', borderTop: '2px solid #ef4444' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', marginBottom: 8 }}>
            <AlertTriangle size={14} color="#ef4444" />
            <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Escalated</span>
          </div>
          <p className="mono" style={{ fontSize: 28, fontWeight: 800, color: '#f87171' }}>{stats.escalated}</p>
        </div>
        <div className="glass" style={{ padding: '16px 20px', borderTop: '2px solid #10b981' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', marginBottom: 8 }}>
            <ShieldCheck size={14} color="#10b981" />
            <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Resolved</span>
          </div>
          <p className="mono" style={{ fontSize: 28, fontWeight: 800, color: '#34d399' }}>{stats.resolved}</p>
        </div>
        <div className="glass" style={{ padding: '16px 20px', borderTop: '2px solid #94a3b8' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)', marginBottom: 8 }}>
            <XCircle size={14} color="#94a3b8" />
            <span style={{ fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>False Positive</span>
          </div>
          <p className="mono" style={{ fontSize: 28, fontWeight: 800, color: '#cbd5e1' }}>{stats.fp}</p>
        </div>
      </div>

      {/* Main Table Area */}
      <div className="glass" style={{ borderRadius: 12, overflow: 'hidden' }}>
        
        {/* Toolbar */}
        <div style={{
          padding: '16px 20px', borderBottom: '1px solid var(--border)',
          display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', justifyContent: 'space-between',
          background: 'rgba(59,130,246,0.02)',
        }}>
          {/* Search */}
          <div style={{ position: 'relative', width: 260 }}>
            <Search size={14} color="var(--text-muted)" style={{ position: 'absolute', left: 12, top: 10 }} />
            <input
              className="input-field"
              style={{ paddingLeft: 34, fontSize: 13, height: 34, borderRadius: 8 }}
              placeholder="Search ID, threat type, target..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          {/* Filters */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Filter size={12} color="var(--text-muted)" />
              <select
                className="input-field"
                style={{ fontSize: 12, height: 32, padding: '4px 10px', width: 'auto', borderRadius: 6 }}
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
              >
                <option value="ALL">All Statuses</option>
                <option value="Open,Acknowledged,Escalated">Active (Open/Ack/Esc)</option>
                <option value="Open">Open</option>
                <option value="Acknowledged">Acknowledged</option>
                <option value="Escalated">Escalated</option>
                <option value="Resolved">Resolved</option>
                <option value="False Positive">False Positive</option>
              </select>
            </div>
            
            <select
              className="input-field"
              style={{ fontSize: 12, height: 32, padding: '4px 10px', width: 'auto', borderRadius: 6 }}
              value={riskFilter}
              onChange={e => setRiskFilter(e.target.value)}
            >
              <option value="">All Risks</option>
              {['Critical', 'High', 'Medium', 'Low', 'Safe'].map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Table */}
        <div style={{ overflowX: 'auto', minHeight: 400 }}>
          <table style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['ID', 'Created', 'Threat', 'Risk', 'Target', 'Status', 'Actions'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '12px 20px', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(inc => {
                const event = inc.event || {}
                const isExpanded = expandedId === inc.id
                const riskLvl = event.risk_level || 'Low'
                const borderC = RISK_ROW_BORDER[riskLvl] || 'rgba(96,165,250,0.06)'
                
                return (
                  <>
                    <tr
                      key={inc.id}
                      onClick={() => setExpandedId(isExpanded ? null : inc.id)}
                      style={{
                        borderBottom: `1px solid ${borderC}`,
                        cursor: 'pointer', transition: 'background 0.15s',
                        background: isExpanded ? 'rgba(59,130,246,0.05)' : 'transparent',
                      }}
                      onMouseEnter={e => { if(!isExpanded) e.currentTarget.style.background = 'rgba(59,130,246,0.03)' }}
                      onMouseLeave={e => { if(!isExpanded) e.currentTarget.style.background = 'transparent' }}
                    >
                      {/* ID */}
                      <td style={{ padding: '14px 20px' }}>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {inc.id.split('-')[0]}
                        </span>
                      </td>
                      {/* Created */}
                      <td style={{ padding: '14px 20px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)', fontSize: 12 }}>
                          <Clock size={12} />
                          {new Date(inc.created_at).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' })}
                        </div>
                      </td>
                      {/* Threat */}
                      <td style={{ padding: '14px 20px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {event.threat_type || 'Unknown'}
                      </td>
                      {/* Risk */}
                      <td style={{ padding: '14px 20px' }}>
                        <RiskBadge level={riskLvl} size="sm" score={event.risk_score} />
                      </td>
                      {/* Target */}
                      <td style={{ padding: '14px 20px', fontSize: 12, color: 'var(--text-secondary)' }}>
                        {event.target_user || event.target_service || '—'}
                      </td>
                      {/* Status */}
                      <td style={{ padding: '14px 20px' }}>
                        <span style={{
                          fontSize: 11, padding: '3px 10px', borderRadius: 20, fontWeight: 600,
                          background: inc.status === 'Resolved' ? 'rgba(16,185,129,0.15)' :
                                      inc.status === 'Escalated' ? 'rgba(239,68,68,0.15)' :
                                      inc.status === 'False Positive' ? 'rgba(148,163,184,0.15)' :
                                      'rgba(59,130,246,0.15)',
                          color:      inc.status === 'Resolved' ? '#34d399' :
                                      inc.status === 'Escalated' ? '#f87171' :
                                      inc.status === 'False Positive' ? '#cbd5e1' :
                                      '#60a5fa',
                        }}>
                          {inc.status}
                        </span>
                      </td>
                      {/* Actions */}
                      <td style={{ padding: '14px 20px' }}>
                        <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
                          {inc.status !== 'Acknowledged' && inc.status !== 'Resolved' && inc.status !== 'False Positive' && (
                            <button
                              disabled={updatingId === inc.id}
                              onClick={() => handleStatusUpdate(inc.id, 'Acknowledged')}
                              className="action-btn action-btn-ack"
                            >
                              Ack
                            </button>
                          )}
                          {inc.status !== 'Escalated' && inc.status !== 'Resolved' && inc.status !== 'False Positive' && (
                            <button
                              disabled={updatingId === inc.id}
                              onClick={() => handleStatusUpdate(inc.id, 'Escalated')}
                              className="action-btn action-btn-escalate"
                            >
                              Escalate
                            </button>
                          )}
                          {inc.status !== 'Resolved' && inc.status !== 'False Positive' && (
                            <>
                              <button
                                disabled={updatingId === inc.id}
                                onClick={() => handleStatusUpdate(inc.id, 'Resolved')}
                                className="action-btn action-btn-resolve"
                              >
                                Resolve
                              </button>
                              <button
                                disabled={updatingId === inc.id}
                                onClick={() => handleStatusUpdate(inc.id, 'False Positive')}
                                className="action-btn action-btn-fp"
                              >
                                False Pos
                              </button>
                            </>
                          )}
                          {updatingId === inc.id && <span className="spinner" style={{ width: 14, height: 14, alignSelf: 'center' }} />}
                        </div>
                      </td>
                    </tr>

                    {/* Expanded Detail View */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={7} style={{ padding: '0 20px 20px', background: 'rgba(59,130,246,0.02)' }}>
                          <div style={{
                            marginTop: 10, padding: 16, borderRadius: 10,
                            background: 'rgba(8,13,26,0.6)', border: '1px solid rgba(96,165,250,0.1)'
                          }}>
                            <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>
                              Event Evidence
                            </h4>
                            <EvidencePanel result={event} compact={false} />
                            
                            {inc.notes && (
                              <div style={{ marginTop: 16, padding: '12px 14px', borderRadius: 8, background: 'rgba(255,255,255,0.03)' }}>
                                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Incident Notes</span>
                                <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>{inc.notes}</p>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                )
              })}
              
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <EmptyState
                      icon={ShieldCheck}
                      title={search || riskFilter ? "No incidents match your filters" : "All clear"}
                      message={search || riskFilter ? "Try clearing your search or adjusting filters." : "No active incidents found in this view."}
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
