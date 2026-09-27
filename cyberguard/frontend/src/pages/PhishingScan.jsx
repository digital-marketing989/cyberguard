/**
 * Phishing Scan Page
 * Supports text input, .eml file upload, URL scanning, and QR code image scanning.
 * Upgraded: QR image preview, toast notifications, inline validation,
 * loading dim, ResultCard for results.
 */
import { useState, useCallback } from 'react'
import { Mail, Upload, Link2, QrCode, Loader2, AlertCircle, ImageIcon } from 'lucide-react'
import { analyzePhishingText, analyzePhishingFile, scanURL, analyzePhishingQR } from '../api/client'
import { EvidencePanel } from '../components/EvidencePanel'
import { useToast } from '../components/ui/ToastContext'

const TABS = [
  { id: 'text', label: 'Email / SMS Text', icon: Mail  },
  { id: 'file', label: 'Upload .eml File', icon: Upload},
  { id: 'url',  label: 'URL Scan',         icon: Link2 },
  { id: 'qr',   label: 'QR Code Scan',     icon: QrCode},
]

const SAMPLE_PHISHING = `From: PayPal Security <security@paypa1-secure.xyz>
Subject: URGENT: Your PayPal account has been limited!

Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account access has been temporarily limited.

To restore full access, please verify your information immediately by clicking the link below:

http://paypa1-verify.secure-login.tk/restore-account?id=abc123

Failure to verify within 24 hours will result in permanent account suspension.

Please enter your:
- Email address and password
- Credit card number and CVV
- Social Security Number (for identity verification)

PayPal Security Team`

function DropZone({ onFile, accept, inputId, icon: Icon, iconColor, file, hint, preview }) {
  const [active, setActive] = useState(false)

  return (
    <div>
      <div
        className={`drop-zone ${active ? 'drop-zone-active' : ''}`}
        style={file ? { borderColor: iconColor, background: `${iconColor}08` } : {}}
        onDragOver={e => { e.preventDefault(); setActive(true) }}
        onDragLeave={() => setActive(false)}
        onDrop={e => { e.preventDefault(); setActive(false); onFile(e.dataTransfer.files[0]) }}
        onClick={() => document.getElementById(inputId).click()}
      >
        <Icon size={34} color={file ? iconColor : 'var(--text-muted)'} style={{ margin: '0 auto 10px' }} />
        <p style={{ fontSize: 13, fontWeight: 500, color: file ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
          {file ? file.name : hint}
        </p>
        {file && (
          <p style={{ fontSize: 11, marginTop: 4, color: iconColor }}>
            {file.type || 'unknown type'} · {(file.size / 1024).toFixed(1)} KB
          </p>
        )}
        {!file && (
          <p style={{ fontSize: 11, marginTop: 4, color: 'var(--text-muted)' }}>
            Drag &amp; drop or click to browse
          </p>
        )}
      </div>
      <input id={inputId} type="file" accept={accept} className="hidden" onChange={e => onFile(e.target.files[0])} />

      {/* Image preview for QR */}
      {preview && (
        <div style={{ marginTop: 12 }}>
          <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Preview</p>
          <img
            src={preview}
            alt="QR preview"
            style={{
              maxHeight: 180, maxWidth: '100%', display: 'block',
              borderRadius: 8, border: '1px solid var(--border)',
              objectFit: 'contain',
            }}
          />
        </div>
      )}
    </div>
  )
}

export default function PhishingScan() {
  const { addToast } = useToast()
  const [activeTab, setActiveTab] = useState('text')
  const [text, setText]     = useState('')
  const [sender, setSender] = useState('')
  const [subject, setSubject] = useState('')
  const [url, setUrl]       = useState('')
  const [file, setFile]     = useState(null)
  const [qrPreview, setQrPreview] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [fieldError, setFieldError] = useState('')

  const reset = () => { setResult(null); setFieldError('') }

  const switchTab = (id) => {
    setActiveTab(id)
    setFile(null)
    setQrPreview(null)
    reset()
  }

  const handleQRFile = (f) => {
    if (!f) return
    setFile(f)
    reset()
    if (f.type.startsWith('image/')) {
      setQrPreview(URL.createObjectURL(f))
    }
  }

  const validate = () => {
    if (activeTab === 'text' && !text.trim()) {
      setFieldError('Email / SMS body is required — paste the message content to analyze.')
      return false
    }
    if (activeTab === 'file' && !file) {
      setFieldError('Please select a .eml or .txt file.')
      return false
    }
    if (activeTab === 'url' && !url.trim()) {
      setFieldError('Please enter a URL to scan.')
      return false
    }
    if (activeTab === 'qr' && !file) {
      setFieldError('Please upload a QR code image.')
      return false
    }
    return true
  }

  const handleAnalyze = async () => {
    reset()
    if (!validate()) return
    setLoading(true)
    try {
      let data
      if (activeTab === 'text')      data = await analyzePhishingText({ text, sender: sender || undefined, subject: subject || undefined })
      else if (activeTab === 'file') data = await analyzePhishingFile(file)
      else if (activeTab === 'url')  data = await scanURL(url)
      else if (activeTab === 'qr')   data = await analyzePhishingQR(file)
      setResult(data)
      addToast({ message: `Analysis complete — risk level: ${data.risk_level}`, type: data.risk_level === 'Safe' ? 'success' : data.risk_level === 'Critical' || data.risk_level === 'High' ? 'error' : 'warning' })
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || 'Analysis failed'
      setFieldError(msg)
      addToast({ message: `Scan failed: ${msg}`, type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 740, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }} className="fade-in">
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Mail size={22} color="#f59e0b" />
          <span className="gradient-text">Phishing Detection</span>
        </h1>
        <p style={{ marginTop: 4, fontSize: 13, color: 'var(--text-secondary)' }}>
          Analyze emails, SMS messages, URLs, and QR codes for phishing indicators using NLP + rule-based detection.
        </p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, padding: 4, borderRadius: 12, background: 'rgba(8,13,26,0.8)', border: '1px solid var(--border)' }}>
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => switchTab(id)}
            style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              padding: '9px 8px', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: 'pointer',
              transition: 'all 0.18s',
              background: activeTab === id ? 'linear-gradient(135deg, rgba(59,130,246,0.28), rgba(139,92,246,0.18))' : 'transparent',
              color: activeTab === id ? 'white' : 'var(--text-secondary)',
              border: activeTab === id ? '1px solid rgba(59,130,246,0.3)' : '1px solid transparent',
            }}
          >
            <Icon size={13} /> {label}
          </button>
        ))}
      </div>

      {/* Input area */}
      <div className="glass" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, opacity: loading ? 0.65 : 1, transition: 'opacity 0.2s' }}>
        {activeTab === 'text' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>Sender (optional)</label>
                <input className="input-field" style={{ fontSize: 13 }} placeholder="sender@example.com" value={sender} onChange={e => setSender(e.target.value)} />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>Subject (optional)</label>
                <input className="input-field" style={{ fontSize: 13 }} placeholder="Email subject line" value={subject} onChange={e => setSubject(e.target.value)} />
              </div>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>
                Email / SMS Body <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <textarea
                className={`input-field mono ${fieldError && !text.trim() ? 'input-error' : ''}`}
                style={{ fontSize: 12 }} rows={10}
                placeholder="Paste email or SMS text here…"
                value={text} onChange={e => { setText(e.target.value); if (fieldError) setFieldError('') }}
              />
            </div>
            <button
              onClick={() => { setText(SAMPLE_PHISHING); setSender('security@paypa1-secure.xyz'); setSubject('URGENT: Your account has been limited!') }}
              style={{ fontSize: 12, color: 'var(--text-muted)', textDecoration: 'underline', background: 'none', border: 'none', cursor: 'pointer', alignSelf: 'flex-start' }}
            >
              Load sample phishing email
            </button>
          </>
        )}

        {activeTab === 'file' && (
          <DropZone
            onFile={f => { setFile(f); reset() }}
            accept=".eml,.txt,.msg"
            inputId="phishing-file-input"
            icon={Upload}
            iconColor="#3b82f6"
            file={file}
            hint="Drag & drop or click to upload .eml / .txt file"
          />
        )}

        {activeTab === 'url' && (
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>
              URL to scan <span style={{ color: '#ef4444' }}>*</span>
            </label>
            <input
              className={`input-field mono ${fieldError && !url.trim() ? 'input-error' : ''}`}
              style={{ fontSize: 13 }}
              placeholder="https://suspicious-domain.xyz/verify-account"
              value={url} onChange={e => { setUrl(e.target.value); if (fieldError) setFieldError('') }}
            />
            <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
              {[
                'http://paypa1-secure.xyz/verify',
                'https://microsoft-secure.tk/reset',
                'http://192.168.1.1/admin/login',
                'https://www.google.com',
              ].map(u => (
                <button key={u} onClick={() => setUrl(u)} style={{
                  fontSize: 11, padding: '3px 10px', borderRadius: 6, cursor: 'pointer',
                  background: 'rgba(59,130,246,0.1)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.2)',
                }}>
                  {u.slice(0, 32)}…
                </button>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'qr' && (
          <>
            <DropZone
              onFile={handleQRFile}
              accept="image/*,.png,.jpg,.jpeg,.webp"
              inputId="phishing-qr-input"
              icon={QrCode}
              iconColor="#f59e0b"
              file={file}
              hint="Drag & drop or click to upload QR code image (PNG, JPG, WebP)"
              preview={qrPreview}
            />
            <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Decodes embedded QR code URLs to detect quishing campaigns, typosquatted destinations, and malicious credential traps.
            </p>
          </>
        )}

        {/* Inline validation message */}
        {fieldError && (
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 14px', borderRadius: 8, fontSize: 13,
            background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.28)', color: '#fca5a5',
          }}>
            <AlertCircle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
            {fieldError}
          </div>
        )}

        <button
          onClick={handleAnalyze}
          disabled={loading}
          className="btn-primary"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
        >
          {loading ? <><span className="spinner" /> Analyzing…</> : '🔍 Analyze for Threats'}
        </button>
      </div>

      {/* Result */}
      {result && <EvidencePanel result={result} />}
    </div>
  )
}
