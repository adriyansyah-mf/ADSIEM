import { useMemo, useState } from 'react'
import { ParentSize } from '@visx/responsive'
import { Group } from '@visx/group'
import { scaleTime, scaleLinear, scaleBand } from '@visx/scale'
import { LinePath, AreaClosed, Bar } from '@visx/shape'
import { AxisBottom, AxisLeft } from '@visx/axis'
import { GridRows } from '@visx/grid'
import { LinearGradient } from '@visx/gradient'
import { curveMonotoneX } from '@visx/curve'
import { useTooltip, TooltipWithBounds, defaultStyles } from '@visx/tooltip'
import type { TimeseriesPoint, MttrPoint, TopSource } from '@/hooks/useMetrics'

const C = {
  cyan: '#00d4ff',
  green: '#00ff88',
  orange: '#ff6b00',
  red: '#ff2244',
  yellow: '#ffd700',
  border: '#1a2d45',
  text: '#6b8aad',
  muted: '#3a5070',
}

const SEV = [
  ['critical', C.red],
  ['high', C.orange],
  ['medium', C.yellow],
  ['low', C.green],
  ['info', C.cyan],
] as const

const tooltipStyles = {
  ...defaultStyles,
  background: '#0b1524',
  border: '1px solid #1a2d45',
  borderRadius: 4,
  color: '#e0eaff',
  fontFamily: 'Rajdhani, sans-serif',
  fontSize: 12,
  padding: '6px 10px',
}

function fmtTime(iso: string) {
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

export function AlertsOverTimeChart({
  points,
  height = 200,
}: {
  points: TimeseriesPoint[]
  height?: number
}) {
  const { tooltipData, tooltipLeft, tooltipTop, showTooltip, hideTooltip } =
    useTooltip<TimeseriesPoint>()

  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || points.length === 0) {
          return <EmptyChart height={height} label="No alerts in this window" />
        }
        const margin = { top: 12, right: 12, bottom: 26, left: 34 }
        const w = width - margin.left - margin.right
        const h = height - margin.top - margin.bottom

        const dates = points.map(p => new Date(p.t))
        const xScale = scaleTime({
          domain: [dates[0], dates[dates.length - 1]],
          range: [0, w],
        })
        const maxY = Math.max(1, ...points.map(p => p.total))
        const yScale = scaleLinear({ domain: [0, maxY], range: [h, 0], nice: true })

        return (
          <div style={{ position: 'relative' }}>
            <svg width={width} height={height}>
              <LinearGradient id="alertArea" from={C.cyan} to="transparent" fromOpacity={0.35} toOpacity={0} />
              <Group left={margin.left} top={margin.top}>
                <GridRows scale={yScale} width={w} stroke={C.border} strokeOpacity={0.5} numTicks={4} />
                <AreaClosed
                  data={points}
                  x={p => xScale(new Date(p.t))}
                  y={p => yScale(p.total)}
                  yScale={yScale}
                  curve={curveMonotoneX}
                  fill="url(#alertArea)"
                />
                <LinePath
                  data={points}
                  x={p => xScale(new Date(p.t))}
                  y={p => yScale(p.total)}
                  stroke={C.cyan}
                  strokeWidth={1.5}
                  curve={curveMonotoneX}
                />
                {points.map((p, i) => (
                  <circle
                    key={i}
                    cx={xScale(new Date(p.t))}
                    cy={yScale(p.total)}
                    r={8}
                    fill="transparent"
                    onMouseMove={() =>
                      showTooltip({
                        tooltipData: p,
                        tooltipLeft: margin.left + xScale(new Date(p.t)),
                        tooltipTop: margin.top + yScale(p.total),
                      })
                    }
                    onMouseLeave={hideTooltip}
                  />
                ))}
                <AxisBottom
                  top={h}
                  scale={xScale}
                  numTicks={Math.min(6, points.length)}
                  tickFormat={d => fmtTime((d as Date).toISOString())}
                  stroke={C.border}
                  tickStroke={C.border}
                  tickLabelProps={() => ({
                    fill: C.text,
                    fontSize: 10,
                    fontFamily: 'Rajdhani, sans-serif',
                    textAnchor: 'middle',
                  })}
                />
                <AxisLeft
                  scale={yScale}
                  numTicks={4}
                  stroke={C.border}
                  tickStroke={C.border}
                  tickLabelProps={() => ({
                    fill: C.text,
                    fontSize: 10,
                    fontFamily: 'Rajdhani, sans-serif',
                    textAnchor: 'end',
                  })}
                />
              </Group>
            </svg>
            {tooltipData && (
              <TooltipWithBounds left={tooltipLeft} top={tooltipTop} style={tooltipStyles}>
                <strong>{fmtTime(tooltipData.t)}</strong>
                <div>{tooltipData.total} alerts</div>
                {SEV.filter(([k]) => tooltipData[k as keyof TimeseriesPoint]).map(([k, col]) => (
                  <div key={k} style={{ color: col }}>
                    {k}: {tooltipData[k as keyof TimeseriesPoint] as number}
                  </div>
                ))}
              </TooltipWithBounds>
            )}
          </div>
        )
      }}
    </ParentSize>
  )
}

export function SeverityBars({
  bySeverity,
  height = 200,
}: {
  bySeverity: Record<string, number>
  height?: number
}) {
  const rows = useMemo(
    () => SEV.map(([k, col]) => ({ key: k, color: col, value: bySeverity[k] ?? 0 })).filter(r => r.value > 0),
    [bySeverity],
  )

  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || rows.length === 0) {
          return <EmptyChart height={height} label="No severity data" />
        }
        const margin = { top: 8, right: 40, bottom: 8, left: 74 }
        const w = width - margin.left - margin.right
        const h = height - margin.top - margin.bottom
        const maxV = Math.max(...rows.map(r => r.value), 1)

        const yScale = scaleBand({
          domain: rows.map(r => r.key),
          range: [0, h],
          padding: 0.3,
        })
        const xScale = scaleLinear({ domain: [0, maxV], range: [0, w], nice: true })

        return (
          <svg width={width} height={height}>
            <Group left={margin.left} top={margin.top}>
              {rows.map(r => {
                const y = yScale(r.key) ?? 0
                const barW = xScale(r.value)
                return (
                  <g key={r.key}>
                    <text
                      x={-8}
                      y={y + (yScale.bandwidth() ?? 0) / 2}
                      dy="0.32em"
                      textAnchor="end"
                      fill={C.text}
                      fontSize={11}
                      fontFamily="Rajdhani, sans-serif"
                      style={{ textTransform: 'uppercase' }}
                    >
                      {r.key}
                    </text>
                    <Bar x={0} y={y} width={barW} height={yScale.bandwidth()} fill={r.color} fillOpacity={0.75} rx={2} />
                    <text
                      x={barW + 6}
                      y={y + (yScale.bandwidth() ?? 0) / 2}
                      dy="0.32em"
                      fill={r.color}
                      fontSize={11}
                      fontFamily="Rajdhani, sans-serif"
                      fontWeight={700}
                    >
                      {r.value}
                    </text>
                  </g>
                )
              })}
            </Group>
          </svg>
        )
      }}
    </ParentSize>
  )
}

export function TopSourcesChart({
  sources,
  height = 200,
}: {
  sources: TopSource[]
  height?: number
}) {
  const [hover, setHover] = useState<string | null>(null)

  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || sources.length === 0) {
          return <EmptyChart height={height} label="No source IPs recorded" />
        }
        const rowH = 22
        const needed = sources.length * rowH + 16
        const h = Math.max(height, needed)
        const margin = { top: 8, right: 40, bottom: 8, left: 110 }
        const w = width - margin.left - margin.right
        const maxV = Math.max(...sources.map(s => s.count), 1)

        const yScale = scaleBand({
          domain: sources.map(s => s.ip),
          range: [0, h - 16],
          padding: 0.25,
        })
        const xScale = scaleLinear({ domain: [0, maxV], range: [0, w], nice: true })

        return (
          <svg width={width} height={h}>
            <Group left={margin.left} top={margin.top}>
              {sources.map(s => {
                const y = yScale(s.ip) ?? 0
                const barW = xScale(s.count)
                const active = hover === s.ip
                return (
                  <g
                    key={s.ip}
                    onMouseEnter={() => setHover(s.ip)}
                    onMouseLeave={() => setHover(null)}
                  >
                    <text
                      x={-8}
                      y={y + (yScale.bandwidth() ?? 0) / 2}
                      dy="0.32em"
                      textAnchor="end"
                      fill={active ? C.cyan : C.text}
                      fontSize={11}
                      fontFamily="monospace"
                    >
                      {s.ip}
                    </text>
                    <Bar
                      x={0}
                      y={y}
                      width={barW}
                      height={yScale.bandwidth()}
                      fill={C.cyan}
                      fillOpacity={active ? 0.9 : 0.55}
                      rx={2}
                    />
                    <text
                      x={barW + 6}
                      y={y + (yScale.bandwidth() ?? 0) / 2}
                      dy="0.32em"
                      fill={C.text}
                      fontSize={11}
                      fontFamily="Rajdhani, sans-serif"
                    >
                      {s.count}
                    </text>
                  </g>
                )
              })}
            </Group>
          </svg>
        )
      }}
    </ParentSize>
  )
}

export function MttrTrendChart({
  points,
  height = 200,
}: {
  points: MttrPoint[]
  height?: number
}) {
  const usable = points.filter(p => p.avg_ack_minutes != null || p.avg_mttr_minutes != null)

  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || usable.length === 0) {
          return <EmptyChart height={height} label="No acknowledge/resolve data yet" />
        }
        const margin = { top: 12, right: 12, bottom: 26, left: 40 }
        const w = width - margin.left - margin.right
        const h = height - margin.top - margin.bottom

        const xScale = scaleTime({
          domain: [new Date(usable[0].day), new Date(usable[usable.length - 1].day)],
          range: [0, w],
        })
        const maxY = Math.max(
          1,
          ...usable.flatMap(p => [p.avg_ack_minutes ?? 0, p.avg_mttr_minutes ?? 0]),
        )
        const yScale = scaleLinear({ domain: [0, maxY], range: [h, 0], nice: true })
        const series = [
          { key: 'avg_ack_minutes' as const, color: C.cyan, label: 'Ack' },
          { key: 'avg_mttr_minutes' as const, color: C.orange, label: 'Resolve' },
        ]

        return (
          <div>
            <svg width={width} height={height}>
              <Group left={margin.left} top={margin.top}>
                <GridRows scale={yScale} width={w} stroke={C.border} strokeOpacity={0.5} numTicks={4} />
                {series.map(s => (
                  <LinePath
                    key={s.key}
                    data={usable.filter(p => p[s.key] != null)}
                    x={p => xScale(new Date(p.day))}
                    y={p => yScale(p[s.key] as number)}
                    stroke={s.color}
                    strokeWidth={1.5}
                    curve={curveMonotoneX}
                  />
                ))}
                <AxisBottom
                  top={h}
                  scale={xScale}
                  numTicks={Math.min(6, usable.length)}
                  tickFormat={d => {
                    const dd = d as Date
                    return `${dd.getMonth() + 1}/${dd.getDate()}`
                  }}
                  stroke={C.border}
                  tickStroke={C.border}
                  tickLabelProps={() => ({
                    fill: C.text,
                    fontSize: 10,
                    fontFamily: 'Rajdhani, sans-serif',
                    textAnchor: 'middle',
                  })}
                />
                <AxisLeft
                  scale={yScale}
                  numTicks={4}
                  stroke={C.border}
                  tickStroke={C.border}
                  tickLabelProps={() => ({
                    fill: C.text,
                    fontSize: 10,
                    fontFamily: 'Rajdhani, sans-serif',
                    textAnchor: 'end',
                  })}
                />
              </Group>
            </svg>
            <div style={{ display: 'flex', gap: 14, paddingLeft: margin.left, paddingTop: 4 }}>
              {series.map(s => (
                <span key={s.key} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: C.text }}>
                  <span style={{ width: 10, height: 2, background: s.color, display: 'inline-block' }} />
                  {s.label} (min)
                </span>
              ))}
            </div>
          </div>
        )
      }}
    </ParentSize>
  )
}

function EmptyChart({ height, label }: { height: number; label: string }) {
  return (
    <div
      style={{
        height,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        color: C.muted,
        fontSize: 12,
        fontFamily: 'Rajdhani, sans-serif',
      }}
    >
      {label}
    </div>
  )
}
