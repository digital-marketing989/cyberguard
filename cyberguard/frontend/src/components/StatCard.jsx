/**
 * StatCard — animated metric card for dashboard
 * Counts up from 0 to `value` on mount.
 */
import { useEffect, useRef, useState } from 'react'

function useCountUp(target, duration = 800) {
  const [display, setDisplay] = useState(0)
  const frameRef = useRef(null)

  useEffect(() => {
    if (typeof target !== 'number' || isNaN(target)) {
      setDisplay(target)
      return
    }
    const start = performance.now()
    const step = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(eased * target))
      if (progress < 1) {
        frameRef.current = requestAnimationFrame(step)
      }
    }
    frameRef.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(frameRef.current)
  }, [target, duration])

  return display
}

export function StatCard({ icon: Icon, label, value, sub, color = '#3b82f6', trend }) {
  const displayValue = useCountUp(typeof value === 'number' ? value : 0)
  const shown = typeof value === 'number' ? displayValue : (value ?? '—')

  return (
    <div
      className="glass"
      style={{
        padding: '18px 20px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: 16,
        borderColor: `${color}22`,
        transition: 'transform 0.2s ease, box-shadow 0.2s ease',
        cursor: 'default',
      }}
      onMouseEnter={e => {
        e.currentTarget.style.transform = 'translateY(-2px)'
        e.currentTarget.style.boxShadow = `0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px ${color}22`
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = 'translateY(0)'
        e.currentTarget.style.boxShadow = ''
      }}
    >
      {/* Icon badge */}
      <div
        style={{
          flexShrink: 0, width: 46, height: 46,
          borderRadius: 10,
          background: `${color}18`,
          border: `1px solid ${color}28`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: `0 0 16px ${color}20`,
        }}
      >
        <Icon size={20} style={{ color }} />
      </div>

      {/* Text */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
          {label}
        </p>
        <p className="count-up" style={{ fontSize: 26, fontWeight: 800, lineHeight: 1.1, marginTop: 3, color }}>
          {typeof shown === 'number' ? shown.toLocaleString() : shown}
        </p>
        {sub && (
          <p style={{ fontSize: 11, marginTop: 3, color: 'var(--text-muted)' }}>{sub}</p>
        )}
      </div>

      {/* Trend */}
      {trend !== undefined && (
        <span
          style={{
            fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 20,
            background: trend >= 0 ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
            color: trend >= 0 ? '#ef4444' : '#10b981',
            flexShrink: 0,
          }}
        >
          {trend >= 0 ? '▲' : '▼'} {Math.abs(trend)}%
        </span>
      )}
    </div>
  )
}
