/**
 * Impersonation Detection Scan Page
 * Upgraded: toast notifications, field-level validation highlights,
 * animated sub-score bars, improved layout.
 */
import { useState } from 'react'
import { UserX, AlertCircle } from 'lucide-react'
import { analyzeImpersonation } from '../api/client'
import { EvidencePanel } from '../components/EvidencePanel'
import { useToast } from '../components/ui/ToastContext'

const SAMPLES = [
  {
    label: 'CEO BEC Attack',
    data: {
      display_name: 'CEO',
      email_address: 'ceo@gmail.com',
      claimed_role: 'Chief Executive Officer',
      claimed_organisation: 'Company Inc.',
      subject: 'URGENT - Wire Transfer Required',
      message_body: 'I need you to process an urgent wire transfer of $75,000 to a new vendor account immediately. This is time-sensitive and must be done today without fail. Do not discuss with anyone else. I will be in meetings all day.',
    }
  },
  {
    label: 'IT Credential Phish',
    data: {
      display_name: 'IT Department',
      email_address: 'support@gmail.com',
      claimed_role: 'IT Support',
      claimed_organisation: 'Company IT',
      subject: 'Critical: Password Expiration Notice',
      message_body: 'Your network password will expire in 24 hours. Please click the link below to verify your credentials and prevent account lockout. Enter your username and current password to continue.',
    }
  },
  {
    label: 'Legitimate HR Email',
    data: {
      display_name: 'HR Department',
      email_address: 'hr@company.com',
      claimed_role: 'HR',
      claimed_organisation: 'Company Inc.',
      subject: 'Updated Leave Policy - Please Review',
      message_body: 'Please find attached the updated leave policy document for your review. If you have any questions, feel free to reach out to the HR team at your convenience.',
    }
  },
]

const SUB_SCORES = [
  { label: 'Domain Mismatch',   key: 'domain_mismatch_score',  color: '#ef4444' },
  { label: 'Authority Claim',   key: 'authority_claim_score',  color: '#f97316' },
  { label: 'Urgency / Pressure',key: 'urgency_score',          color: '#f59e0b' },
  { label: 'Style Deviation',   key: 'style_deviation_score',  color: '#8b5cf6' },
]

export default function ImpersonationScan() {
  const { addToast } = useToast()
  const [form, setForm] = useState({
    display_name: '', email_address: '', claimed_role: '',
    claimed_organisation: '', subject: '', message_body: '',
  })
  const [result, setResult]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [errors, setErrors]     = useState({})

  const set = (key, val) => {
    setForm(f => ({ ...f, [key]: val }))
    if (errors[key]) setErrors(e => { const n = { ...e }; delete n[key]; return n })
  }

  const loadSample = (s) => {
    setForm(s.data)
    setResult(null)
    setErrors({})
  }

  const validate = () => {
    const errs = {}
    if (!form.display_name.trim())  errs.display_name  = 'Display name is required'
    if (!form.message_body.trim())  errs.message_body  = 'Message body is required'
    return errs
  }

  const handleAnalyze = async () => {
    const errs = validate()
    if (Object.keys(errs).length > 0) {
      setErrors(errs)
      addToast({ message: 'Please fill in the required fields.', type: 'warning' })
      return
    }
    setLoading(true)
    setErrors({})
    try {
      const data = await analyzeImpersonation(form)
      setResult(data)
      addToast({
        message: `Impersonation analysis complete — ${data.risk_level} risk`,
        type: data.risk_level === 'Safe' ? 'success' : data.risk_level === 'Critical' || data.risk_level === 'High' ? 'error' : 'warning',
      })
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || 'Analysis failed'
      addToast({ message: `Analysis failed: ${msg}`, type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 740, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }} className="fade-in">
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
          <UserX size={22} color="#8b5cf6" />
          <span className="gradient-text">Impersonation Detection</span>
        </h1>
        <p style={{ marginTop: 4, fontSize: 13, color: 'var(--text-secondary)' }}>
          Detect digital impersonation attempts by comparing sender metadata against known contacts and analysing authority claims.
        </p>
      </div>

      {/* Quick samples */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {SAMPLES.map(s => (
          <button
            key={s.label}
            onClick={() => loadSample(s)}
            style={{
              fontSize: 12, padding: '6px 14px', borderRadius: 8, cursor: 'pointer',
              background: 'rgba(139,92,246,0.1)', color: '#a78bfa',
              border: '1px solid rgba(139,92,246,0.25)', fontWeight: 500,
              transition: 'all 0.15s',
            }}
          >
            Load: {s.label}
          </button>
        ))}
      </div>

      {/* Form */}
      <div className="glass" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, opacity: loading ? 0.65 : 1, transition: 'opacity 0.2s' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          {[
            { key: 'display_name',        label: 'Display Name',          placeholder: 'e.g. CEO',                         required: true  },
            { key: 'email_address',        label: 'Email Address',         placeholder: 'sender@domain.com',                required: false },
            { key: 'claimed_role',         label: 'Claimed Role',          placeholder: 'e.g. Chief Executive Officer',     required: false },
            { key: 'claimed_organisation', label: 'Claimed Organisation',  placeholder: 'e.g. Company Inc.',               required: false },
          ].map(({ key, label, placeholder, required }) => (
            <div key={key}>
              <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>
                {label} {required && <span style={{ color: '#ef4444' }}>*</span>}
              </label>
              <input
                className={`input-field ${errors[key] ? 'input-error' : ''}`}
                style={{ fontSize: 13 }}
                placeholder={placeholder}
                value={form[key]}
                onChange={e => set(key, e.target.value)}
              />
              {errors[key] && (
                <p style={{ fontSize: 11, color: '#f87171', marginTop: 3, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <AlertCircle size={10} /> {errors[key]}
                </p>
              )}
            </div>
          ))}
        </div>

        <div>
          <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>Subject Line</label>
          <input className="input-field" style={{ fontSize: 13 }} placeholder="Email subject"
            value={form.subject} onChange={e => set('subject', e.target.value)} />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>
            Message Body <span style={{ color: '#ef4444' }}>*</span>
          </label>
          <textarea
            className={`input-field ${errors.message_body ? 'input-error' : ''}`}
            style={{ fontSize: 13 }} rows={6}
            placeholder="Paste the message body here…"
            value={form.message_body} onChange={e => set('message_body', e.target.value)}
          />
          {errors.message_body && (
            <p style={{ fontSize: 11, color: '#f87171', marginTop: 3, display: 'flex', alignItems: 'center', gap: 4 }}>
              <AlertCircle size={10} /> {errors.message_body}
            </p>
          )}
        </div>

        <button
          onClick={handleAnalyze}
          disabled={loading}
          className="btn-primary"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
        >
          {loading ? <><span className="spinner" /> Analyzing…</> : '🔍 Detect Impersonation'}
        </button>
      </div>

      {/* Sub-score breakdown */}
      {result && (
        <div className="glass" style={{ padding: 20 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 16 }}>Sub-Score Breakdown</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {SUB_SCORES.map(({ label, key, color }) => {
              const val = result.extra_data?.[key] || 0
              return (
                <div key={key}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 5 }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                    <span className="mono" style={{ color, fontWeight: 700 }}>{Math.round(val)}/100</span>
                  </div>
                  <div className="score-bar">
                    <div className="score-bar-fill" style={{ width: `${val}%`, background: color }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {result && <EvidencePanel result={result} />}
    </div>
  )
}
