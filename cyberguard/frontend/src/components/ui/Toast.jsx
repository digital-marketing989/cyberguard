/**
 * Toast — dismissible notification component + container
 */
import { useEffect, useState } from 'react'
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from 'lucide-react'
import { useToast } from './ToastContext'

const TOAST_STYLES = {
  success: {
    icon: CheckCircle2,
    bg: 'rgba(16,185,129,0.12)',
    border: 'rgba(16,185,129,0.3)',
    iconColor: '#34d399',
    textColor: '#a7f3d0',
  },
  error: {
    icon: XCircle,
    bg: 'rgba(239,68,68,0.12)',
    border: 'rgba(239,68,68,0.3)',
    iconColor: '#f87171',
    textColor: '#fca5a5',
  },
  warning: {
    icon: AlertTriangle,
    bg: 'rgba(245,158,11,0.12)',
    border: 'rgba(245,158,11,0.3)',
    iconColor: '#fbbf24',
    textColor: '#fde68a',
  },
  info: {
    icon: Info,
    bg: 'rgba(59,130,246,0.12)',
    border: 'rgba(59,130,246,0.3)',
    iconColor: '#60a5fa',
    textColor: '#bfdbfe',
  },
}

function Toast({ id, message, type = 'info', onRemove }) {
  const [exiting, setExiting] = useState(false)
  const cfg = TOAST_STYLES[type] || TOAST_STYLES.info
  const Icon = cfg.icon

  const dismiss = () => {
    setExiting(true)
    setTimeout(() => onRemove(id), 250)
  }

  return (
    <div
      className={exiting ? 'toast-exit' : 'toast-enter'}
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        padding: '12px 16px',
        borderRadius: 10,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        backdropFilter: 'blur(16px)',
        boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
        maxWidth: 360,
        minWidth: 260,
      }}
    >
      <Icon size={16} color={cfg.iconColor} style={{ flexShrink: 0, marginTop: 2 }} />
      <p style={{ flex: 1, fontSize: 13, lineHeight: 1.5, color: cfg.textColor }}>{message}</p>
      <button
        onClick={dismiss}
        style={{ flexShrink: 0, color: 'rgba(255,255,255,0.35)', cursor: 'pointer', background: 'none', border: 'none', padding: 0, marginTop: 1 }}
      >
        <X size={14} />
      </button>
    </div>
  )
}

export function ToastContainer() {
  const { toasts, removeToast } = useToast()

  return (
    <div className="toast-container">
      {toasts.map(t => (
        <Toast key={t.id} {...t} onRemove={removeToast} />
      ))}
    </div>
  )
}
