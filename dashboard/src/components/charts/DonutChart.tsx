export interface DonutSegment {
  label: string
  value: number
  color: string
}

function arcPath(cx: number, cy: number, r: number, rInner: number, startAngle: number, endAngle: number): string {
  const pt = (angle: number, radius: number) => {
    const rad = ((angle - 90) * Math.PI) / 180
    return [cx + radius * Math.cos(rad), cy + radius * Math.sin(rad)]
  }
  const large = endAngle - startAngle > 180 ? 1 : 0
  const [x1, y1] = pt(startAngle, r)
  const [x2, y2] = pt(endAngle, r)
  const [x3, y3] = pt(endAngle, rInner)
  const [x4, y4] = pt(startAngle, rInner)
  return `M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} L ${x3.toFixed(2)} ${y3.toFixed(2)} A ${rInner} ${rInner} 0 ${large} 0 ${x4.toFixed(2)} ${y4.toFixed(2)} Z`
}

/** Donut chart with a centered total/label and a value legend beside it. */
export function DonutChart({
  segments, size = 140, centerLabel, centerSublabel,
}: {
  segments: DonutSegment[]
  size?: number
  centerLabel: string
  centerSublabel: string
}) {
  const total = segments.reduce((sum, s) => sum + s.value, 0)
  const vb = 180
  const cx = vb / 2, cy = vb / 2, r = 78, rInner = 50
  let angle = 0
  const arcs = total > 0 ? segments.filter(s => s.value > 0).map(s => {
    const sweep = (360 * s.value) / total
    const path = arcPath(cx, cy, r, rInner, angle, angle + Math.min(sweep, 359.99))
    angle += sweep
    return { path, color: s.color, key: s.label }
  }) : []

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
      {/* The legend list below already conveys label+value as text, so the drawing itself is decorative. */}
      <svg width={size} height={size} viewBox={`0 0 ${vb} ${vb}`} aria-hidden="true">
        {arcs.length > 0 ? arcs.map(a => <path key={a.key} d={a.path} fill={a.color} />)
          : <circle cx={cx} cy={cy} r={(r + rInner) / 2} fill="none" stroke="var(--border)" strokeWidth={r - rInner} />}
        <text x={cx} y={cy - 5} textAnchor="middle" style={{ font: '700 26px "Public Sans", sans-serif', fill: 'var(--text-primary)' }}>{centerLabel}</text>
        <text x={cx} y={cy + 12} textAnchor="middle" style={{ font: '9px "JetBrains Mono", monospace', fill: 'var(--text-muted)', letterSpacing: '0.05em' }}>{centerSublabel}</text>
      </svg>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
        {segments.map(s => (
          <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 7, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: '1 1 auto', minWidth: 0 }}>
              <span style={{ width: 9, height: 9, borderRadius: 2, background: s.color, flexShrink: 0 }} />
              {s.label}
            </span>
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>{s.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
