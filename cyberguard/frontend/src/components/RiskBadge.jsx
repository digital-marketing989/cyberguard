/**
 * RiskBadge — coloured pill showing risk level
 * RiskScoreBar — horizontal progress bar
 */

const RISK_CONFIG = {
  Safe:     { bg: 'rgba(16,185,129,0.15)',  border: 'rgba(16,185,129,0.35)',  dot: '#10b981', text: '#6ee7b7', label: 'SAFE'     },
  Low:      { bg: 'rgba(59,130,246,0.15)',  border: 'rgba(59,130,246,0.35)',  dot: '#3b82f6', text: '#93c5fd', label: 'LOW'      },
  Medium:   { bg: 'rgba(245,158,11,0.15)',  border: 'rgba(245,158,11,0.35)',  dot: '#f59e0b', text: '#fde68a', label: 'MEDIUM'   },
  High:     { bg: 'rgba(249,115,22,0.15)',  border: 'rgba(249,115,22,0.35)',  dot: '#f97316', text: '#fdba74', label: 'HIGH'     },
  Critical: { bg: 'rgba(239,68,68,0.15)',   border: 'rgba(239,68,68,0.35)',   dot: '#ef4444', text: '#fca5a5', label: 'CRITICAL' },
}

export function RiskBadge({ level, score, size = 'md' }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.Low
  const isSmall = size === 'sm'

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: isSmall ? '2px 8px' : '3px 10px',
        borderRadius: 20,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        color: cfg.text,
        fontSize: isSmall ? 10 : 11,
        fontWeight: 700,
        letterSpacing: '0.07em',
        fontFamily: "'Inter', sans-serif",
        whiteSpace: 'nowrap',
      }}
    >
      <span
        className="pulse-dot"
        style={{
          background: cfg.dot,
          width: isSmall ? 6 : 7,
          height: isSmall ? 6 : 7,
        }}
      />
      {cfg.label}
      {score !== undefined && (
        <span style={{ opacity: 0.75, fontFamily: "'JetBrains Mono', monospace", fontSize: isSmall ? 9 : 10 }}>
          {Math.round(score)}
        </span>
      )}
    </span>
  )
}

const SCORE_COLORS = {
  Safe: '#10b981', Low: '#3b82f6', Medium: '#f59e0b',
  High: '#f97316', Critical: '#ef4444',
}

export function RiskScoreBar({ score, level }) {
  const color = SCORE_COLORS[level] || '#3b82f6'
  return (
    <div className="score-bar w-full">
      <div
        className="score-bar-fill"
        style={{ width: `${Math.min(100, Math.max(0, score))}%`, background: color }}
      />
    </div>
  )
}
