/**
 * Deepfake Detection Scan Page
 * Upgraded: toast notifications, drag-drop highlight, ResultCard for results.
 */
import { useState, useRef } from 'react'
import { Camera, Film, Mic, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { analyzeDeepfake } from '../api/client'
import { EvidencePanel } from '../components/EvidencePanel'
import { RiskBadge, RiskScoreBar } from '../components/RiskBadge'
import { useToast } from '../components/ui/ToastContext'

const SUPPORTED_FORMATS = [
  { label: '🖼 Images', types: 'JPEG · PNG · WebP',  color: '#06b6d4' },
  { label: '🎵 Audio',  types: 'WAV · MP3 · FLAC',   color: '#10b981' },
  { label: '🎬 Video',  types: 'MP4 · AVI · MOV',    color: '#8b5cf6' },
]

function getMediaIcon(file) {
  if (!file) return <Camera size={38} color="#06b6d4" />
  if (file.type.startsWith('video/')) return <Film size={38} color="#8b5cf6" />
  if (file.type.startsWith('audio/')) return <Mic size={38} color="#10b981" />
  return <Camera size={38} color="#06b6d4" />
}

export default function DeepfakeScan() {
  const { addToast } = useToast()
  const [file, setFile]         = useState(null)
  const [preview, setPreview]   = useState(null)
  const [result, setResult]     = useState(null)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState(null)
  const [showPreview, setShowPreview] = useState(true)
  const [dragOver, setDragOver] = useState(false)

  const handleFile = (f) => {
    if (!f) return
    setFile(f)
    setResult(null)
    setError(null)
    if (f.type.startsWith('image/')) {
      const reader = new FileReader()
      reader.onload = e => setPreview(e.target.result)
      reader.readAsDataURL(f)
    } else {
      setPreview(null)
    }
  }

  const handleAnalyze = async () => {
    if (!file) { setError('Please select a file to analyze.'); return }
    setLoading(true)
    setError(null)
    try {
      const data = await analyzeDeepfake(file)
      setResult(data)
      addToast({
        message: `Deepfake analysis complete — ${data.risk_level} risk detected`,
        type: data.risk_level === 'Safe' ? 'success' : data.risk_level === 'Critical' || data.risk_level === 'High' ? 'error' : 'warning',
      })
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || 'Analysis failed'
      setError(msg)
      addToast({ message: `Analysis failed: ${msg}`, type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const authenticity = result?.extra_data?.authenticity_score

  return (
    <div style={{ maxWidth: 740, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }} className="fade-in">
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Camera size={22} color="#06b6d4" />
          <span className="gradient-text">Deepfake Detection</span>
        </h1>
        <p style={{ marginTop: 4, fontSize: 13, color: 'var(--text-secondary)' }}>
          Analyze images, audio, and video files for AI-generated manipulation artifacts using computer vision heuristics.
        </p>
      </div>

      {/* Supported formats */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {SUPPORTED_FORMATS.map(({ label, types, color }) => (
          <div key={label} style={{
            padding: '6px 12px', borderRadius: 8, fontSize: 12,
            background: `${color}12`, border: `1px solid ${color}28`, color,
          }}>
            <span style={{ fontWeight: 600 }}>{label}</span>
            <span style={{ opacity: 0.7, marginLeft: 6 }}>{types}</span>
          </div>
        ))}
      </div>

      {/* Upload */}
      <div className="glass" style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, opacity: loading ? 0.65 : 1, transition: 'opacity 0.2s' }}>
        <div
          className={`drop-zone ${dragOver ? 'drop-zone-active' : ''}`}
          style={file ? { borderColor: '#06b6d4', background: 'rgba(6,182,212,0.04)' } : {}}
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]) }}
          onClick={() => document.getElementById('deepfake-input').click()}
        >
          <div style={{ marginBottom: 8 }}>{getMediaIcon(file)}</div>
          <p style={{ fontSize: 13, fontWeight: 500, color: file ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
            {file ? file.name : 'Drop your image, audio, or video here'}
          </p>
          {file ? (
            <p style={{ fontSize: 11, marginTop: 4, color: '#06b6d4' }}>
              {file.type} · {(file.size / 1024 / 1024).toFixed(2)} MB
            </p>
          ) : (
            <p style={{ fontSize: 11, marginTop: 4, color: 'var(--text-muted)' }}>
              Drag & drop or click to browse (max 50 MB)
            </p>
          )}
        </div>
        <input id="deepfake-input" type="file" accept="image/*,audio/*,video/*" className="hidden" onChange={e => handleFile(e.target.files[0])} />

        {/* Image preview */}
        {preview && file?.type.startsWith('image/') && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Preview</span>
              <button
                onClick={() => setShowPreview(s => !s)}
                style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer' }}
              >
                {showPreview ? <EyeOff size={12} /> : <Eye size={12} />} {showPreview ? 'Hide' : 'Show'}
              </button>
            </div>
            {showPreview && (
              <img src={preview} alt="Preview" style={{
                borderRadius: 8, maxHeight: 240, width: '100%', objectFit: 'contain',
                display: 'block', border: '1px solid var(--border)',
              }} />
            )}
          </div>
        )}

        {error && (
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 8, padding: '10px 14px', borderRadius: 8, fontSize: 13,
            background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.28)', color: '#fca5a5',
          }}>
            <AlertCircle size={15} style={{ flexShrink: 0, marginTop: 1 }} /> {error}
          </div>
        )}

        <button
          onClick={handleAnalyze}
          disabled={loading || !file}
          className="btn-primary"
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}
        >
          {loading ? <><span className="spinner" /> Analyzing (may take a moment)…</> : '🔍 Analyze for Deepfake Artifacts'}
        </button>
      </div>

      {/* Authenticity score ring */}
      {result && authenticity !== undefined && (
        <div className="glass" style={{ padding: 20 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, textAlign: 'center', color: 'var(--text-primary)', marginBottom: 20 }}>
            Authenticity Score
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 32 }}>
            {/* Ring */}
            <div style={{ position: 'relative', width: 110, height: 110, flexShrink: 0 }}>
              <svg viewBox="0 0 100 100" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
                <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
                <circle cx="50" cy="50" r="40" fill="none"
                  stroke={authenticity > 60 ? '#10b981' : authenticity > 30 ? '#f59e0b' : '#ef4444'}
                  strokeWidth="10"
                  strokeDasharray={`${authenticity * 2.513} 251.3`}
                  strokeLinecap="round"
                  style={{ transition: 'stroke-dasharray 1s ease' }}
                />
              </svg>
              <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <span style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1, fontFamily: 'JetBrains Mono, monospace' }}>
                  {Math.round(authenticity)}%
                </span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>authentic</span>
              </div>
            </div>
            {/* Bars */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4, color: 'var(--text-muted)' }}>
                  <span>Fake probability</span>
                  <span>{Math.round(result.risk_score)}%</span>
                </div>
                <RiskScoreBar score={result.risk_score} level={result.risk_level} />
              </div>
              <RiskBadge level={result.risk_level} score={result.risk_score} />
              <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                Confidence: <strong>{Math.round(result.confidence * 100)}%</strong>
              </p>
            </div>
          </div>
        </div>
      )}

      {result && <EvidencePanel result={result} />}
    </div>
  )
}
