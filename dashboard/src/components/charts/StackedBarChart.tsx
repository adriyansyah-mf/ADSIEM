export interface StackedBarSeries {
  key: string
  color: string
}

export interface StackedBarDatum {
  label: string
  values: Record<string, number>
}

/** Vertical stacked bar chart, drawn to scale with gridlines and axis labels. */
export function StackedBarChart({
  data, series, height = 180, yTickCount = 4, xLabelEvery = 4, ariaLabel,
}: {
  data: StackedBarDatum[]
  series: StackedBarSeries[]
  height?: number
  yTickCount?: number
  xLabelEvery?: number
  /** Unlike the donut/horizontal-bar charts, this one has no sibling text legend,
   * so it needs its own accessible summary rather than aria-hidden. */
  ariaLabel?: string
}) {
  const width = 700
  const plotLeft = 34, plotRight = width - 10
  const plotTop = 12, plotBottom = height - 22
  const plotW = plotRight - plotLeft
  const plotH = plotBottom - plotTop
  const n = data.length || 1

  const totals = data.map(d => series.reduce((sum, s) => sum + (d.values[s.key] ?? 0), 0))
  const rawMax = Math.max(1, ...totals)
  // round the axis max up to a "nice" step so gridline labels aren't awkward fractions
  const step = Math.max(1, Math.ceil(rawMax / yTickCount / 5) * 5)
  const yMax = step * yTickCount
  const pxPerUnit = plotH / yMax

  const slotW = plotW / n
  const barW = slotW * 0.68

  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ overflow: 'visible', display: 'block' }}
      role="img" aria-label={ariaLabel ?? 'Stacked bar chart'}>
      {Array.from({ length: yTickCount + 1 }, (_, i) => {
        const val = step * i
        const y = plotBottom - val * pxPerUnit
        return (
          <g key={val}>
            <line x1={plotLeft} y1={y} x2={plotRight} y2={y} stroke="var(--border)" strokeWidth={1} />
            <text x={plotLeft - 8} y={y + 3} textAnchor="end" style={{ font: '9.5px "JetBrains Mono", monospace', fill: 'var(--text-muted)' }}>{val}</text>
          </g>
        )
      })}

      {data.map((d, i) => {
        const x = plotLeft + i * slotW + (slotW - barW) / 2
        let yCursor = plotBottom
        return (
          <g key={d.label}>
            {series.map(s => {
              const val = d.values[s.key] ?? 0
              if (val <= 0) return null
              const segH = val * pxPerUnit
              const y = yCursor - segH
              yCursor = y
              return <rect key={s.key} x={x} y={y} width={barW} height={segH} fill={s.color} rx={1.5} />
            })}
          </g>
        )
      })}

      {data.map((d, i) => {
        if (i % xLabelEvery !== 0) return null
        const x = plotLeft + i * slotW + barW / 2
        return (
          <text key={d.label} x={x} y={plotBottom + 16} textAnchor="middle" style={{ font: '9.5px "JetBrains Mono", monospace', fill: 'var(--text-muted)' }}>
            {d.label}
          </text>
        )
      })}
    </svg>
  )
}
