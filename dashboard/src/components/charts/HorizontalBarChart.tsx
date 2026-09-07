export interface HBarSegment {
  value: number
  color: string
}

export interface HBarRow {
  label: string
  segments: HBarSegment[]
  labelStyle?: React.CSSProperties
}

/** Horizontal (stacked) bar chart: a label column, the bars, and a total-value column. */
export function HorizontalBarChart({ rows, rowHeight = 30, barHeight = 16 }: { rows: HBarRow[]; rowHeight?: number; barHeight?: number }) {
  const maxTotal = Math.max(1, ...rows.map(r => r.segments.reduce((sum, s) => sum + s.value, 0)))
  const vbWidth = 300
  const height = rows.length * rowHeight

  return (
    <div style={{ display: 'flex', gap: 10 }}>
      <div style={{ display: 'flex', flexDirection: 'column', flexShrink: 0, minWidth: 0 }}>
        {rows.map(r => (
          <div key={r.label} style={{
            height: rowHeight, display: 'flex', alignItems: 'center',
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 11.5, color: 'var(--text-secondary)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', ...r.labelStyle,
          }}>
            {r.label}
          </div>
        ))}
      </div>
      {/* The label and total-value columns beside this already convey the same data as text. */}
      <svg width="100%" height={height} viewBox={`0 0 ${vbWidth} ${height}`} preserveAspectRatio="none" style={{ flex: 1, minWidth: 0 }} aria-hidden="true">
        {rows.map((r, i) => {
          const y = i * rowHeight + (rowHeight - barHeight) / 2
          let xCursor = 0
          return (
            <g key={r.label}>
              {r.segments.map((s, j) => {
                const w = (s.value / maxTotal) * vbWidth
                const rect = <rect key={j} x={xCursor} y={y} width={Math.max(w, s.value > 0 ? 2 : 0)} height={barHeight} rx={3} fill={s.color} opacity={0.85} />
                xCursor += w
                return rect
              })}
            </g>
          )
        })}
      </svg>
      <div style={{ display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        {rows.map(r => (
          <div key={r.label} style={{
            height: rowHeight, display: 'flex', alignItems: 'center', justifyContent: 'flex-end',
            fontFamily: 'IBM Plex Mono, monospace', fontSize: 11.5, fontWeight: 600, color: 'var(--text-primary)',
            fontVariantNumeric: 'tabular-nums',
          }}>
            {r.segments.reduce((sum, s) => sum + s.value, 0)}
          </div>
        ))}
      </div>
    </div>
  )
}
