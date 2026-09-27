/**
 * Auth Anomaly Monitor Page
 * Upgraded: toast notifications, styled CSV drop zone, loading dim.
 */
import { useState } from 'react'
import { KeyRound, Upload, Play, AlertCircle, Network } from 'lucide-react'
import { uploadAuthCSV, runSampleAuthAnalysis, runSampleNetworkAnalysis } from '../api/client'
import { EvidencePanel } from '../components/EvidencePanel'
import { useToast } from '../components/ui/ToastContext'

const DETECTION_TYPES = [
  { label: '🔨 Brute Force',       desc: 'Repeated failed logins from same IP',              color: '#ef4444' },
  { label: '💧 Password Spray',    desc: 'Many users, few attempts, same IP',                color: '#f97316' },
  { label: '✈️ Impossible Travel', desc: 'Login from geographically impossible locations',   color: '#8b5cf6' },
  { label: '📱 New Device/Geo',    desc: 'Unrecognised device or location',                  color: '#06b6d4' },
]

export default function AuthAnomalyMonitor() {
  const { addToast } = useToast()
  const [result, setResult]       = useState(null)
  const [netResult, setNetResult] = useState(null)
  const [loading, setLoading]     = useState(false)
  const [netLoading, setNetLoading] = useState(false)
  const [file, setFile]           = useState(null)
  const [dragOver, setDragOver]   = useState(false)
  const [error, setError]         = useState(null)

  const runSample = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await runSampleAuthAnalysis()
      setResult(data)
      addToast({ message: `Auth analysis complete — ${data.risk_level} risk`, type: data.risk_level === 'Safe' ? 'success' : 'warning' })
    } catch (e) {
      const msg = e.response?.data?.detail || e.message
      setError(msg)
      addToast({ message: `Analysis failed: ${msg}`, type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const runNetSample = async () => {
    setNetLoading(true)
    try {
      const data = await runSampleNetworkAnalysis()
      setNetResult(data)
      addToast({ message: `Network analysis complete — ${data.risk_level} risk`, type: data.risk_level === 'Safe' ? 'success' : 'warning' })
    } catch (e) {
      addToast({ message: `Network analysis failed: ${e.message}`, type: 'error' })
    } finally {
      setNetLoading(false)
    }
  }

  const handleCSVUpload = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const data = await uploadAuthCSV(file)
      setResult(data)
      addToast({ message: 'CSV analysis complete', type: 'success' })
    } catch (e) {
      const msg = e.response?.data?.detail || e.message
      setError(msg)
      addToast({ message: `Upload failed: ${msg}`, type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 740, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }} className="fade-in">
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
          <KeyRound size={22} color="#f97316" />
          <span className="gradient-text">Auth Anomaly &amp; Account Takeover</span>
        </h1>
        <p style={{ marginTop: 4, fontSize: 13, color: 'var(--text-secondary)' }}>
          Detect brute force attacks, password spraying, impossible travel, and new-device logins using Isolation Forest + statistical analysis.
        </p>
      </div>

      {/* Detection types grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {DETECTION_TYPES.map(({ label, desc, color }) => (
          <div key={label} className="glass" style={{ padding: '14px 16px', borderColor: `${color}20` }}>
            <p style={{ fontSize: 13, fontWeight: 600, color }}>{label}</p>
            <p style={{ fontSize: 11, marginTop: 4, color: 'var(--text-muted)', lineHeight: 1.5 }}>{desc}</p>
          </div>
        ))}
      </div>

      {/* Auth Log Analysis card */}
      <div className="glass" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Auth Log Analysis</h2>

        {/* Sample data */}
        <div style={{ padding: '14px 16px', borderRadius: 10, background: 'rgba(249,115,22,0.07)', border: '1px solid rgba(249,115,22,0.2)' }}>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 10, lineHeight: 1.6 }}>
            Run analysis on the built-in synthetic dataset (200 events including brute force, password spray, and impossible travel attacks).
          </p>
          <button
            onClick={runSample}
            disabled={loading}
            className="btn-primary"
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', fontSize: 13 }}
          >
            {loading ? <><span className="spinner" /> Analyzing…</> : <><Play size={14} /> Run Sample Auth Analysis</>}
          </button>
        </div>

        {/* CSV Upload drop zone */}
        <div>
          <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>Or upload your own CSV</p>
          <div
            className={`drop-zone ${dragOver ? 'drop-zone-active' : ''}`}
            style={file ? { borderColor: '#f97316', background: 'rgba(249,115,22,0.04)' } : {}}
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => { e.preventDefault(); setDragOver(false); setFile(e.dataTransfer.files[0]) }}
            onClick={() => document.getElementById('auth-csv-input').click()}
          >
            <Upload size={28} color={file ? '#f97316' : 'var(--text-muted)'} style={{ margin: '0 auto 8px' }} />
            <p style={{ fontSize: 13, color: file ? 'var(--text-primary)' : 'var(--text-secondary)', fontWeight: 500 }}>
              {file ? file.name : 'Drag & drop CSV or click to browse'}
            </p>
            {file && <p style={{ fontSize: 11, color: '#f97316', marginTop: 4 }}>{(file.size / 1024).toFixed(1)} KB</p>}
          </div>
          <input id="auth-csv-input" type="file" accept=".csv" className="hidden" onChange={e => setFile(e.target.files[0])} />
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6, lineHeight: 1.5 }}>
            Required columns: username, timestamp, ip_address, success, geo_country, geo_city, latitude, longitude, device_fingerprint
          </p>
          {file && (
            <button
              onClick={handleCSVUpload}
              disabled={loading}
              className="btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 10, padding: '8px 18px', fontSize: 13 }}
            >
              {loading ? <><span className="spinner" /> Analyzing…</> : <><Upload size={13} /> Analyze CSV</>}
            </button>
          )}
        </div>

        {error && (
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 14px', borderRadius: 8, fontSize: 13,
            background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.28)', color: '#fca5a5',
          }}>
            <AlertCircle size={15} style={{ flexShrink: 0, marginTop: 1 }} /> {error}
          </div>
        )}
      </div>

      {/* Auth result stats + evidence */}
      {result && (
        <>
          {result.extra_data?.stats && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              {[
                { label: 'Total Events',  value: result.extra_data.stats.total_events,                                    color: '#3b82f6' },
                { label: 'Unique Users',  value: result.extra_data.stats.unique_users,                                    color: '#8b5cf6' },
                { label: 'Failure Rate',  value: `${Math.round((result.extra_data.stats.failure_rate || 0) * 100)}%`,    color: '#ef4444' },
              ].map(({ label, value, color }) => (
                <div key={label} className="glass" style={{ padding: '14px 16px', textAlign: 'center' }}>
                  <p style={{ fontSize: 24, fontWeight: 800, color, fontFamily: 'JetBrains Mono, monospace' }}>{value}</p>
                  <p style={{ fontSize: 11, marginTop: 4, color: 'var(--text-muted)' }}>{label}</p>
                </div>
              ))}
            </div>
          )}
          <EvidencePanel result={result} />
        </>
      )}

      {/* Network Analysis */}
      <div className="glass" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Network size={18} color="#06b6d4" />
          <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Network Anomaly Analysis</h2>
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Detect port scanning, DDoS patterns, and data exfiltration from network logs using the built-in sample dataset.
        </p>
        <button
          onClick={runNetSample}
          disabled={netLoading}
          className="btn-outline"
          style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', fontSize: 13, width: 'fit-content' }}
        >
          {netLoading ? <><span className="spinner" /> Analyzing…</> : <><Play size={14} /> Run Network Analysis</>}
        </button>
        {netResult && <EvidencePanel result={netResult} />}
      </div>
    </div>
  )
}
