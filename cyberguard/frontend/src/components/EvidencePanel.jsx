/**
 * EvidencePanel — expandable analysis result panel
 * Upgraded: indicator chips, styled recommended-actions checklist,
 * AI explanation callout, cleaner section separation.
 */
import { useState } from 'react'
import { ChevronDown, ChevronUp, AlertTriangle, Zap, Shield, ExternalLink } from 'lucide-react'
import { RiskBadge, RiskScoreBar } from './RiskBadge'

function getRiskBorderColor(level) {
  const map = {
    Safe: 'rgba(16,185,129,0.18)', Low: 'rgba(59,130,246,0.18)',
    Medium: 'rgba(245,158,11,0.18)', High: 'rgba(249,115,22,0.18)', Critical: 'rgba(239,68,68,0.18)',
  }
  return map[level] || map.Low
}

function getRiskHeaderBg(level) {
  const map = {
    Safe: 'rgba(16,185,129,0.07)', Low: 'rgba(59,130,246,0.07)',
    Medium: 'rgba(245,158,11,0.07)', High: 'rgba(249,115,22,0.07)', Critical: 'rgba(239,68,68,0.07)',
  }
  return map[level] || map.Low
}

export function EvidencePanel({ result, compact = false }) {
  const [expanded, setExpanded] = useState(!compact)

  if (!result) return null

  const {
    threat_type, risk_level, risk_score, confidence,
    indicators = [], explanation, recommended_actions = [],
    mitre_tag, extra_data = {},
  } = result

  return (
    <div
      className="glass fade-in"
      style={{ borderColor: getRiskBorderColor(risk_level), overflow: 'hidden' }}
    >
      {/* ── Header ── */}
      <div
        style={{
          display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px',
          background: getRiskHeaderBg(risk_level),
          borderBottom: expanded ? `1px solid ${getRiskBorderColor(risk_level)}` : 'none',
          cursor: compact ? 'pointer' : 'default',
        }}
        onClick={() => compact && setExpanded(e => !e)}
      >
        <div style={{ flex: 1 }}>
          {/* Title row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
            <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
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
          {/* Score bar + confidence */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{ flex: 1, maxWidth: 220 }}>
              <RiskScoreBar score={risk_score} level={risk_level} />
            </div>
            {confidence !== undefined && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                Confidence: <strong style={{ color: 'var(--text-secondary)' }}>{Math.round(confidence * 100)}%</strong>
              </span>
            )}
          </div>
        </div>
        {compact && (
          <button style={{ color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', padding: 4 }}>
            {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
          </button>
        )}
      </div>

      {/* ── Body ── */}
      {expanded && (
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: 18 }}>

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

          {/* Indicators as chips */}
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

          {/* Recommended Actions as numbered checklist */}
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
                    <span style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Extra data — URLs */}
          {extra_data?.urls_found?.length > 0 && (
            <div>
              <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 8 }}>
                URLs Found
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {extra_data.urls_found.map((url, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <ExternalLink size={11} color="var(--text-muted)" />
                    <p className="mono" style={{ fontSize: 12, color: '#a78bfa', wordBreak: 'break-all' }}>{url}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Decoded QR URL */}
          {(extra_data?.decoded_url || extra_data?.qr_url) && (
            <div>
              <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 4 }}>
                Decoded QR URL
              </p>
              <p className="mono" style={{ fontSize: 12, color: '#a78bfa', wordBreak: 'break-all' }}>
                {extra_data.decoded_url || extra_data.qr_url}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
