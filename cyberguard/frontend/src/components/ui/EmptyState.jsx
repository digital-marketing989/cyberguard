/**
 * EmptyState — consistent empty/no-data placeholder
 */
export function EmptyState({ icon: Icon, title, message, action }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3rem 2rem',
        textAlign: 'center',
        gap: 12,
      }}
    >
      {Icon && (
        <div
          style={{
            width: 52,
            height: 52,
            borderRadius: '50%',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: 4,
          }}
        >
          <Icon size={22} style={{ color: 'var(--text-muted)', opacity: 0.7 }} />
        </div>
      )}
      {title && (
        <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-secondary)' }}>{title}</p>
      )}
      {message && (
        <p style={{ fontSize: 12, color: 'var(--text-muted)', maxWidth: 280, lineHeight: 1.6 }}>
          {message}
        </p>
      )}
      {action && <div style={{ marginTop: 8 }}>{action}</div>}
    </div>
  )
}
