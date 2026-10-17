import { useMemo } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from 'recharts'
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

const LAYER_COLORS = [C.cyan, C.orange, C.green, C.yellow, C.red, '#a78bfa']

const AXIS_PROPS = {
  stroke: C.border,
  tick: { fill: C.text, fontSize: 10, fontFamily: 'Rajdhani, sans-serif' },
  tickLine: { stroke: C.border },
} as const

const TOOLTIP_STYLE = {
  background: '#0b1524',
  border: '1px solid #1a2d45',
  borderRadius: 4,
  color: '#e0eaff',
  fontFamily: 'Rajdhani, sans-serif',
  fontSize: 12,
  padding: '6px 10px',
} as const

function Empty({ height, label }: { height: number; label: string }) {
  return (
    <div style={{ height, display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.muted, fontSize: 12, fontFamily: 'Rajdhani, sans-serif' }}>
      {label}
    </div>
  )
}

export function EventVolumeChart({ points, height = 200 }: { points: VolumePoint[]; height?: number }) {
  if (points.length === 0) return <Empty height={height} label="No events in this window" />

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={points} margin={{ top: 12, right: 12, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="volArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={C.cyan} stopOpacity={0.3} />
            <stop offset="100%" stopColor={C.cyan} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={C.border} strokeOpacity={0.5} vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={(t: string) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          {...AXIS_PROPS}
        />
        <YAxis allowDecimals={false} width={42} {...AXIS_PROPS} />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={(t) => new Date(t as string).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          formatter={(value) => [`${value} events`, 'total']}
        />
        <Area type="monotone" dataKey="total" stroke={C.cyan} strokeWidth={1.5} fill="url(#volArea)" />
      </AreaChart>
    </ResponsiveContainer>
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
  if (values.length === 0) return <Empty height={height} label="No data" />

  const rowH = 24
  const chartH = Math.max(height, values.length * rowH + 24)

  return (
    <ResponsiveContainer width="100%" height={chartH}>
      <BarChart data={values} layout="vertical" margin={{ top: 4, right: 44, bottom: 4, left: 8 }} barCategoryGap="25%">
        <XAxis type="number" allowDecimals={false} {...AXIS_PROPS} />
        <YAxis
          type="category"
          dataKey="value"
          width={labelWidth}
          tickFormatter={(v: string) => (v.length > 16 ? `${v.slice(0, 15)}…` : v)}
          tick={{ fill: C.text, fontSize: 10, fontFamily: 'monospace' }}
          tickLine={{ stroke: C.border }}
          stroke={C.border}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          cursor={{ fill: 'rgba(255,255,255,0.04)' }}
          formatter={(value) => [Number(value).toLocaleString(), 'count']}
        />
        <Bar dataKey="count" fill={color} fillOpacity={0.7} radius={[0, 2, 2, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function StackedTypeBars({ points, height = 200 }: { points: VolumePoint[]; height?: number }) {
  const types = useMemo(
    () => Array.from(new Set(points.flatMap(p => Object.keys(p.types ?? {})))).slice(0, 6),
    [points],
  )
  const data = useMemo(
    () => points.map(p => {
      const row: Record<string, string | number> = { t: p.t, total: p.total }
      types.forEach(t => { row[t] = p.types?.[t] ?? 0 })
      return row
    }),
    [points, types],
  )

  if (points.length === 0) return <Empty height={height} label="No events in this window" />

  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: 0 }}>
          <CartesianGrid stroke={C.border} strokeOpacity={0.5} vertical={false} />
          <XAxis
            dataKey="t"
            tickFormatter={(t: string) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            {...AXIS_PROPS}
          />
          <YAxis allowDecimals={false} width={42} {...AXIS_PROPS} />
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            labelFormatter={(t) => new Date(t as string).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            cursor={{ fill: 'rgba(255,255,255,0.04)' }}
          />
          {types.map((t, i) => (
            <Bar key={t} dataKey={t} stackId="ev" fill={LAYER_COLORS[i % LAYER_COLORS.length]} fillOpacity={0.8} isAnimationActive={false} />
          ))}
        </BarChart>
      </ResponsiveContainer>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, paddingLeft: 42, paddingTop: 4 }}>
        {types.map((t, i) => (
          <span key={t} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: C.text, fontFamily: 'Rajdhani, sans-serif' }}>
            <span style={{ width: 8, height: 8, background: LAYER_COLORS[i % LAYER_COLORS.length], display: 'inline-block', borderRadius: 1 }} />
            {t}
          </span>
        ))}
      </div>
    </div>
  )
}

export function AuthFailuresChart({ points, height = 180 }: { points: { t: string; count: number }[]; height?: number }) {
  if (points.length === 0) return <Empty height={height} label="No authentication failures" />

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={points} margin={{ top: 12, right: 12, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="authArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={C.red} stopOpacity={0.35} />
            <stop offset="100%" stopColor={C.red} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={C.border} strokeOpacity={0.5} vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={(t: string) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          {...AXIS_PROPS}
        />
        <YAxis allowDecimals={false} width={42} {...AXIS_PROPS} />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={(t) => new Date(t as string).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          formatter={(value) => [`${value} failures`, 'auth failures']}
        />
        <Area type="monotone" dataKey="count" stroke={C.red} strokeWidth={1.5} fill="url(#authArea)" />
      </AreaChart>
    </ResponsiveContainer>
  )
}
