export function Sparkline({
  values, color = 'var(--accent-blue)', width = 80, height = 26,
}: { values: number[]; color?: string; width?: number; height?: number }) {
  if (values.length < 2) return null
  const w = 110, h = 32
  const vmin = Math.min(...values)
  const vmax = Math.max(...values)
  const range = vmax - vmin || 1
  const n = values.length
  const pts = values.map((v, i) => {
    const x = (i / (n - 1)) * w
    const y = h - ((v - vmin) / range) * h
    return [x, y] as const
  })
  const path = 'M ' + pts.map(([x, y]) => `${x.toFixed(1)} ${y.toFixed(1)}`).join(' L ')
  const area = `${path} L ${w} ${h} L 0 ${h} Z`

  return (
    <svg width={width} height={height} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
      <path d={area} fill={color} opacity={0.12} />
      <path d={path} fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
