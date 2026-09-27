/**
 * ResultCard — premium scan result display component
 * Shows: risk badge, animated score ring, indicator chips,
 * AI explanation callout, and recommended-actions checklist.
 * All backend fields are rendered; no backend dependency.
 */
import { useState } from 'react'
import { Zap, AlertTriangle, Shield, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import { RiskBadge, RiskScoreBar } from '../RiskBadge'

const RISK_COLORS = {
  Safe: '#10b981', Low: '#3b82f6', Medium: '#f59e0b',
  High: '#f97316', Critical: '#ef4444',
}

function ScoreRing({ score, level }) {
  const color = RISK_COLORS[level] || '#3b82f6'
  const radius = 40
  const circumference = 2 * Math.PI * radius
  const dash = (Math.min(100, score) / 100) * circumference

  return (
    <div style={{ position: 'relative', width: 112, height: 112, flexShrink: 0 }}>
      <svg viewBox="0 0 100 100" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
        <circle cx="50" cy="50" r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle
          cx="50" cy="50" r={radius} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1s cubic-bezier(0.4,0,0.2,1)' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: 22, fontWeight: 800, color, lineHeight: 1, fontFamily: "'JetBrains Mono', monospace" }}>
          {Math.round(score)}
        </span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>/ 100</span>
      </div>
    </div>
  )
}

export function ResultCard({ result, showRing = true }) {
  const [showExtra, setShowExtra] = useState(false)
  if (!result) return null

  const {
    threat_type, risk_level, risk_score = 0, confidence = 0,
    indicators = [], explanation, recommended_actions = [],
    mitre_tag, extra_data = {},
  } = result

  const borderColor = `${RISK_COLORS[risk_level] || '#3b82f6'}28`
  const headerBg = `${RISK_COLORS[risk_level] || '#3b82f6'}10`

  return (
    <div
      className="glass fade-in"
      style={{ borderColor, overflow: 'hidden' }}
    >
      {/* ── Header band ── */}
      <div style={{ background: headerBg, padding: '16px 20px', borderBottom: '1px solid ' + borderColor }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 20, flexWrap: 'wrap' }}>
          {showRing && <ScoreRing score={risk_score} level={risk_level} />}
          <div style={{ flex: 1, minWidth: 180 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
                {threat_type || 'Analysis Result'}
              </span>
              <RiskBadge level={risk_level} score={risk_score} />
              {mitre_tag && (
                <span
                  className="mono"
                  style={{
                    fontSize: 11, padding: '2px 8px', borderRadius: 4,
                    background: 'rgba(139,92,246,0.15)', color: '#a78bfa',
                    border: '1px solid rgba(139,92,246,0.3)',
                  }}
                >
                  {mitre_tag}
                </span>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div style={{ flex: 1, maxWidth: 220 }}>
                <RiskScoreBar score={risk_score} level={risk_level} />
              </div>
              <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                Confidence: <strong style={{ color: 'var(--text-secondary)' }}>{Math.round(confidence * 100)}%</strong>
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* AI Explanation */}
        {explanation && (
          <div style={{
            background: 'rgba(59,130,246,0.07)',
            border: '1px solid rgba(59,130,246,0.18)',
            borderRadius: 10, padding: '14px 16px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Zap size={14} color="#60a5fa" />
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#60a5fa' }}>
                AI Analysis
              </span>
            </div>
            <p style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-primary)' }}>{explanation}</p>
          </div>
        )}

        {/* Indicators */}
        {indicators.length > 0 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <AlertTriangle size={14} color="#f59e0b" />
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#f59e0b' }}>
                Detected Indicators ({indicators.length})
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {indicators.map((ind, i) => (
                <span key={i} className="indicator-chip">
                  <AlertTriangle size={10} />
                  {ind}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Recommended Actions */}
        {recommended_actions.length > 0 && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <Shield size={14} color="#10b981" />
              <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#10b981' }}>
                Recommended Actions
              </span>
            </div>
            <ol style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 8 }}>
              {recommended_actions.map((action, i) => (
                <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <span style={{
                    flexShrink: 0, width: 20, height: 20, borderRadius: '50%',
                    background: 'rgba(16,185,129,0.15)', color: '#10b981',
                    fontSize: 11, fontWeight: 700,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    marginTop: 1,
                  }}>
                    {i + 1}
                  </span>
                  <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.55 }}>{action}</span>
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* Extra data (URLs found, decoded QR, etc.) */}
        {(extra_data?.urls_found?.length > 0 || extra_data?.decoded_url || extra_data?.qr_url) && (
          <div>
            <button
              onClick={() => setShowExtra(s => !s)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em',
                color: 'var(--text-muted)', background: 'none', border: 'none',
                cursor: 'pointer', padding: 0, marginBottom: showExtra ? 10 : 0,
              }}
            >
              {showExtra ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
              Additional Data
            </button>
            {showExtra && (
              <div style={{
                background: 'rgba(0,0,0,0.2)', borderRadius: 8, padding: '12px 14px',
                border: '1px solid rgba(255,255,255,0.06)',
              }}>
                {(extra_data.decoded_url || extra_data.qr_url) && (
                  <div style={{ marginBottom: 8 }}>
                    <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Decoded URL</p>
                    <p className="mono" style={{ fontSize: 12, color: '#a78bfa', wordBreak: 'break-all' }}>
                      {extra_data.decoded_url || extra_data.qr_url}
                    </p>
                  </div>
                )}
                {extra_data.urls_found?.map((url, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <ExternalLink size={11} color="var(--text-muted)" />
                    <p className="mono" style={{ fontSize: 12, color: '#a78bfa', wordBreak: 'break-all' }}>{url}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
