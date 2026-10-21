import { useMemo } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
} from 'recharts'
import type { TimeseriesPoint, MttrPoint, TopSource } from '@/hooks/useMetrics'

const C = {
  cyan: 'var(--accent-cyan)',
  green: 'var(--accent-green)',
  orange: 'var(--accent-orange)',
  red: 'var(--accent-red)',
  yellow: 'var(--accent-yellow)',
  border: 'var(--border-default)',
  text: 'var(--text-secondary)',
  muted: 'var(--text-muted)',
}

const SEV = [
  ['critical', C.red],
  ['high', C.orange],
  ['medium', C.yellow],
  ['low', C.green],
  ['info', C.cyan],
] as const

const AXIS_PROPS = {
  stroke: C.border,
  tick: { fill: C.text, fontSize: 12, fontFamily: 'var(--font-ui)' },
  tickLine: { stroke: C.border },
} as const

const TOOLTIP_STYLE = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border-default)',
  borderRadius: 4,
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-ui)',
  fontSize: 12,
  padding: '6px 10px',
} as const

function fmtTime(iso: string) {
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
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
        fontFamily: 'var(--font-ui)',
      }}
    >
      {label}
    </div>
  )
}

export function AlertsOverTimeChart({
  points,
  height = 200,
}: {
  points: TimeseriesPoint[]
  height?: number
}) {
  const data = useMemo(
    () => points.map(p => ({ ...p, time: new Date(p.t).getTime() })),
    [points],
  )

  if (data.length === 0) {
    return <EmptyChart height={height} label="No alerts in this window" />
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id="alertArea" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={C.cyan} stopOpacity={0.35} />
            <stop offset="100%" stopColor={C.cyan} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={C.border} strokeOpacity={0.5} vertical={false} />
        <XAxis
          dataKey="time"
          type="number"
          scale="time"
          domain={['dataMin', 'dataMax']}
          tickFormatter={(t: number) => fmtTime(new Date(t).toISOString())}
          {...AXIS_PROPS}
        />
        <YAxis allowDecimals={false} width={34} {...AXIS_PROPS} />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          labelFormatter={(t) => fmtTime(new Date(t as number).toISOString())}
          formatter={(value, name) => {
            if (name === 'total') return [`${value} alerts`, 'total']
            return [value, name]
          }}
        />
        <Area
          type="monotone"
          dataKey="total"
          stroke={C.cyan}
          strokeWidth={1.5}
          fill="url(#alertArea)"
        />
      </AreaChart>
    </ResponsiveContainer>
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

  if (rows.length === 0) {
    return <EmptyChart height={height} label="No severity data" />
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 36, bottom: 4, left: 8 }} barCategoryGap="28%">
        <XAxis type="number" allowDecimals={false} {...AXIS_PROPS} />
        <YAxis
          type="category"
          dataKey="key"
          width={64}
          tickFormatter={(k: string) => k.toUpperCase()}
          {...AXIS_PROPS}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          cursor={{ fill: 'rgba(255,255,255,0.04)' }}
          formatter={(value) => [value, 'alerts']}
        />
        <Bar dataKey="value" radius={[0, 2, 2, 0]} isAnimationActive={false}>
          {rows.map(r => <Cell key={r.key} fill={r.color} fillOpacity={0.75} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TopSourcesChart({
  sources,
  height = 200,
}: {
  sources: TopSource[]
  height?: number
}) {
  if (sources.length === 0) {
    return <EmptyChart height={height} label="No source IPs recorded" />
  }

  const rowH = 24
  const chartH = Math.max(height, sources.length * rowH + 24)

  return (
    <ResponsiveContainer width="100%" height={chartH}>
      <BarChart data={sources} layout="vertical" margin={{ top: 4, right: 36, bottom: 4, left: 8 }} barCategoryGap="24%">
        <XAxis type="number" allowDecimals={false} {...AXIS_PROPS} />
        <YAxis
          type="category"
          dataKey="ip"
          width={100}
          tick={{ fill: C.text, fontSize: 11, fontFamily: 'monospace' }}
          tickLine={{ stroke: C.border }}
          stroke={C.border}
        />
        <Tooltip
          contentStyle={TOOLTIP_STYLE}
          cursor={{ fill: 'rgba(255,255,255,0.04)' }}
          formatter={(value) => [value, 'alerts']}
        />
        <Bar dataKey="count" fill={C.cyan} fillOpacity={0.55} radius={[0, 2, 2, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function MttrTrendChart({
  points,
  height = 200,
}: {
  points: MttrPoint[]
  height?: number
}) {
  const usable = useMemo(
    () => points.filter(p => p.avg_ack_minutes != null || p.avg_mttr_minutes != null),
    [points],
  )

  if (usable.length === 0) {
    return <EmptyChart height={height} label="No acknowledge/resolve data yet" />
  }

  return (
    <div>
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={usable} margin={{ top: 12, right: 12, bottom: 0, left: 0 }}>
          <CartesianGrid stroke={C.border} strokeOpacity={0.5} vertical={false} />
          <XAxis
            dataKey="day"
            tickFormatter={(d: string) => {
              const dd = new Date(d)
              return `${dd.getMonth() + 1}/${dd.getDate()}`
            }}
            {...AXIS_PROPS}
          />
          <YAxis allowDecimals={false} width={34} {...AXIS_PROPS} />
          <Tooltip
            contentStyle={TOOLTIP_STYLE}
            labelFormatter={(d) => {
              const dd = new Date(d as string)
              return `${dd.getMonth() + 1}/${dd.getDate()}`
            }}
            formatter={(value, name) => {
              const labels: Record<string, string> = { avg_ack_minutes: 'Ack (min)', avg_mttr_minutes: 'Resolve (min)' }
              return [value, labels[name as string] ?? name]
            }}
          />
          <Line type="monotone" dataKey="avg_ack_minutes" stroke={C.cyan} strokeWidth={1.5} dot={false} connectNulls />
          <Line type="monotone" dataKey="avg_mttr_minutes" stroke={C.orange} strokeWidth={1.5} dot={false} connectNulls />
        </LineChart>
      </ResponsiveContainer>
      <div style={{ display: 'flex', gap: 14, paddingLeft: 34, paddingTop: 4 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: C.text }}>
          <span style={{ width: 10, height: 2, background: C.cyan, display: 'inline-block' }} />
          Ack (min)
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: C.text }}>
          <span style={{ width: 10, height: 2, background: C.orange, display: 'inline-block' }} />
          Resolve (min)
        </span>
      </div>
    </div>
  )
}
