import { ParentSize } from '@visx/responsive'
import { Group } from '@visx/group'
import { scaleTime, scaleLinear, scaleBand } from '@visx/scale'
import { LinePath, AreaClosed, Bar } from '@visx/shape'
import { AxisBottom, AxisLeft } from '@visx/axis'
import { GridRows } from '@visx/grid'
import { LinearGradient } from '@visx/gradient'
import { curveMonotoneX } from '@visx/curve'
import type { VolumePoint, TopValue } from '@/hooks/useElastic'

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

const LAYER_COLORS = [C.cyan, C.orange, C.green, C.yellow, C.red, '#a78bfa', '#22d3ee', '#f472b6']

function Empty({ height, label }: { height: number; label: string }) {
  return (
    <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.muted, fontSize: 12, fontFamily: 'Rajdhani, sans-serif' }}>
      {label}
    </div>
  )
}

export function EventVolumeChart({ points, height = 200 }: { points: VolumePoint[]; height?: number }) {
  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || points.length === 0) return <Empty height={height} label="No events in this window" />
        const m = { top: 12, right: 12, bottom: 26, left: 42 }
        const w = width - m.left - m.right
        const h = height - m.top - m.bottom
        const xScale = scaleTime({
          domain: [new Date(points[0].t), new Date(points[points.length - 1].t)],
          range: [0, w],
        })
        const maxY = Math.max(1, ...points.map(p => p.total))
        const yScale = scaleLinear({ domain: [0, maxY], range: [h, 0], nice: true })

        return (
          <svg width={width} height={height}>
            <LinearGradient id="volArea" from={C.cyan} to="transparent" fromOpacity={0.3} toOpacity={0} />
            <Group left={m.left} top={m.top}>
              <GridRows scale={yScale} width={w} stroke={C.border} strokeOpacity={0.5} numTicks={4} />
              <AreaClosed data={points} x={p => xScale(new Date(p.t))} y={p => yScale(p.total)} yScale={yScale} curve={curveMonotoneX} fill="url(#volArea)" />
              <LinePath data={points} x={p => xScale(new Date(p.t))} y={p => yScale(p.total)} stroke={C.cyan} strokeWidth={1.5} curve={curveMonotoneX} />
              <AxisBottom
                top={h}
                scale={xScale}
                numTicks={Math.min(6, points.length)}
                tickFormat={d => (d as Date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                stroke={C.border}
                tickStroke={C.border}
                tickLabelProps={() => ({ fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif', textAnchor: 'middle' })}
              />
              <AxisLeft
                scale={yScale}
                numTicks={4}
                stroke={C.border}
                tickStroke={C.border}
                tickLabelProps={() => ({ fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif', textAnchor: 'end' })}
              />
            </Group>
          </svg>
        )
      }}
    </ParentSize>
  )
}

export function HorizontalBars({
  values,
  height = 200,
  color = C.cyan,
  labelWidth = 110,
}: {
  values: TopValue[]
  height?: number
  color?: string
  labelWidth?: number
}) {
  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || values.length === 0) return <Empty height={height} label="No data" />
        const rowH = 22
        const h = Math.max(height, values.length * rowH + 16)
        const m = { top: 8, right: 44, bottom: 8, left: labelWidth }
        const w = width - m.left - m.right
        const maxV = Math.max(...values.map(v => v.count), 1)
        const yScale = scaleBand({ domain: values.map(v => v.value), range: [0, h - 16], padding: 0.25 })
        const xScale = scaleLinear({ domain: [0, maxV], range: [0, w], nice: true })

        return (
          <svg width={width} height={h}>
            <Group left={m.left} top={m.top}>
              {values.map(v => {
                const y = yScale(v.value) ?? 0
                const barW = xScale(v.count)
                return (
                  <g key={v.value}>
                    <text x={-8} y={y + (yScale.bandwidth() ?? 0) / 2} dy="0.32em" textAnchor="end" fill={C.text} fontSize={10} fontFamily="monospace">
                      {v.value.length > 16 ? `${v.value.slice(0, 15)}…` : v.value}
                    </text>
                    <Bar x={0} y={y} width={barW} height={yScale.bandwidth()} fill={color} fillOpacity={0.7} rx={2} />
                    <text x={barW + 6} y={y + (yScale.bandwidth() ?? 0) / 2} dy="0.32em" fill={C.text} fontSize={10} fontFamily="Rajdhani, sans-serif">
                      {v.count.toLocaleString()}
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

export function StackedTypeBars({ points, height = 200 }: { points: VolumePoint[]; height?: number }) {
  const types = Array.from(new Set(points.flatMap(p => Object.keys(p.types ?? {})))).slice(0, 6)

  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || points.length === 0) return <Empty height={height} label="No events in this window" />
        const m = { top: 12, right: 12, bottom: 26, left: 42 }
        const w = width - m.left - m.right
        const h = height - m.top - m.bottom
        const xScale = scaleBand({
          domain: points.map(p => p.t),
          range: [0, w],
          padding: 0.25,
        })
        const maxY = Math.max(1, ...points.map(p => p.total))
        const yScale = scaleLinear({ domain: [0, maxY], range: [h, 0], nice: true })
        const bw = xScale.bandwidth()

        return (
          <>
            <svg width={width} height={height}>
              <Group left={m.left} top={m.top}>
                <GridRows scale={yScale} width={w} stroke={C.border} strokeOpacity={0.5} numTicks={4} />
                {points.map(p => {
                  let acc = 0
                  return (
                    <g key={p.t}>
                      {types.map((t, i) => {
                        const v = p.types?.[t] ?? 0
                        if (!v) return null
                        const yTop = yScale(acc + v)
                        const heightPx = yScale(acc) - yTop
                        acc += v
                        return (
                          <rect
                            key={t}
                            x={xScale(p.t)}
                            y={yTop}
                            width={bw}
                            height={heightPx}
                            fill={LAYER_COLORS[i % LAYER_COLORS.length]}
                            fillOpacity={0.8}
                          />
                        )
                      })}
                    </g>
                  )
                })}
                <AxisLeft
                  scale={yScale}
                  numTicks={4}
                  stroke={C.border}
                  tickStroke={C.border}
                  tickLabelProps={() => ({ fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif', textAnchor: 'end' })}
                />
                <AxisBottom
                  top={h}
                  scale={xScale}
                  numTicks={Math.min(6, points.length)}
                  tickFormat={d => new Date(d as string).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  stroke={C.border}
                  tickStroke={C.border}
                  tickLabelProps={() => ({ fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif', textAnchor: 'middle' })}
                />
              </Group>
            </svg>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, paddingLeft: m.left, paddingTop: 4 }}>
              {types.map((t, i) => (
                <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: C.text, fontFamily: 'Rajdhani, sans-serif' }}>
                  <span style={{ width: 8, height: 8, background: LAYER_COLORS[i % LAYER_COLORS.length], display: 'inline-block', borderRadius: 1 }} />
                  {t}
                </span>
              ))}
            </div>
          </>
        )
      }}
    </ParentSize>
  )
}

export function AuthFailuresChart({ points, height = 180 }: { points: { t: string; count: number }[]; height?: number }) {
  const mapped = points.map(p => ({ t: p.t, total: p.count, types: {} }))
  return (
    <ParentSize>
      {({ width }) => {
        if (width < 10 || mapped.length === 0) return <Empty height={height} label="No authentication failures" />
        const m = { top: 12, right: 12, bottom: 26, left: 42 }
        const w = width - m.left - m.right
        const h = height - m.top - m.bottom
        const xScale = scaleTime({
          domain: [new Date(mapped[0].t), new Date(mapped[mapped.length - 1].t)],
          range: [0, w],
        })
        const maxY = Math.max(1, ...mapped.map(p => p.total))
        const yScale = scaleLinear({ domain: [0, maxY], range: [h, 0], nice: true })

        return (
          <svg width={width} height={height}>
            <LinearGradient id="authArea" from={C.red} to="transparent" fromOpacity={0.35} toOpacity={0} />
            <Group left={m.left} top={m.top}>
              <GridRows scale={yScale} width={w} stroke={C.border} strokeOpacity={0.5} numTicks={4} />
              <AreaClosed data={mapped} x={p => xScale(new Date(p.t))} y={p => yScale(p.total)} yScale={yScale} curve={curveMonotoneX} fill="url(#authArea)" />
              <LinePath data={mapped} x={p => xScale(new Date(p.t))} y={p => yScale(p.total)} stroke={C.red} strokeWidth={1.5} curve={curveMonotoneX} />
              <AxisBottom
                top={h}
                scale={xScale}
                numTicks={Math.min(6, mapped.length)}
                tickFormat={d => (d as Date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                stroke={C.border}
                tickStroke={C.border}
                tickLabelProps={() => ({ fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif', textAnchor: 'middle' })}
              />
              <AxisLeft
                scale={yScale}
                numTicks={4}
                stroke={C.border}
                tickStroke={C.border}
                tickLabelProps={() => ({ fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif', textAnchor: 'end' })}
              />
            </Group>
          </svg>
        )
      }}
    </ParentSize>
  )
}
