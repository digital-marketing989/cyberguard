/**
 * SkeletonLoader — shimmer placeholders for loading states
 */

/** Single line skeleton */
export function SkeletonLine({ width = '100%', height = 14, style = {} }) {
  return (
    <div
      className="skeleton"
      style={{ width, height, borderRadius: 4, ...style }}
    />
  )
}

/** Mimics a StatCard */
export function SkeletonCard() {
  return (
    <div
      className="glass"
      style={{ padding: '20px', display: 'flex', alignItems: 'flex-start', gap: 16 }}
    >
      <div className="skeleton" style={{ width: 48, height: 48, borderRadius: 10, flexShrink: 0 }} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <SkeletonLine width="60%" height={11} />
        <SkeletonLine width="40%" height={28} />
        <SkeletonLine width="50%" height={11} />
      </div>
    </div>
  )
}

/** Mimics a chart area */
export function SkeletonChart({ height = 180 }) {
  return (
    <div className="skeleton" style={{ width: '100%', height, borderRadius: 8 }} />
  )
}

/** Mimics table rows */
export function SkeletonTable({ rows = 5 }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          style={{
            display: 'flex',
            gap: 16,
            padding: '14px 16px',
            borderBottom: '1px solid rgba(96,165,250,0.06)',
            alignItems: 'center',
          }}
        >
          <SkeletonLine width={70} height={11} />
          <SkeletonLine width={110} height={11} />
          <SkeletonLine width={60} height={20} style={{ borderRadius: 20 }} />
          <SkeletonLine width={40} height={11} />
          <SkeletonLine width={80} height={11} />
        </div>
      ))}
    </div>
  )
}

/** Grid of skeleton cards */
export function SkeletonCardGrid({ count = 5 }) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
      gap: 12,
    }}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} />
      ))}
    </div>
  )
}
