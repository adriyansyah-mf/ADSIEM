import type { ReactNode } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { format } from 'date-fns'
import {
  Activity, ArrowDown, ArrowUp, ChartBar, ChartColumnStacked, ChartPie, Cloud, Fingerprint, Grid3x3, Hash,
  List, Rows3, Table2, TrendingUp,
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import type { LucideIcon } from 'lucide-react'
import { api } from '@/api/client'

// Visualizations for custom dashboards (server-api/app/api/routes/dashboards.py,
// services/saved_searches.py run()).

export type Viz = 'count' | 'trend' | 'unique' | 'timeline' | 'split' | 'top' | 'donut' | 'datatable'
  | 'tagcloud' | 'rare' | 'heatmap' | 'table'
export type Chart = 'area' | 'line' | 'bar'

export interface Widget {
  id?: string
  title: string
  search_id: string | null
  kind: 'logs' | 'events'
  query: string
  viz: Viz
  field: string
  limit: number
  hours: number
  chart: Chart
  x?: number
  y?: number
  w?: number
  h?: number
  width?: 1 | 2 | 3
}

export interface Pin { field: string; value: string; negate: boolean }

/** What the dashboard's toolbar applies to every widget. hours null = each widget's own window. */
export interface Scope { hours: number | null; query: string; filters: Pin[]; refreshMs: number | false }

export interface RunResult {
  search: { id: string | null; name: string | null; kind: 'logs' | 'events'; query: string }
  viz: Viz
  hours: number
  total: number
  previous?: number
  change_pct?: number | null
  unique?: number
  field?: string
  other?: number
  interval?: string
  keys?: string[]
  points?: { t: string; count: number; series?: Record<string, number> }[]
  values?: { value: string; count: number }[]
  grid?: number[][]
  tz?: string
  rows?: { id: string; created_at: string; log_type: string | null; hostname: string | null; event_action: string | null; message: string }[]
}

export const VIZ: Record<Viz, { label: string; hint: string; icon: LucideIcon; field?: boolean; size?: boolean; w: number; h: number }> = {
  count: { label: 'Metric', hint: 'One number: the events that match', icon: Hash, w: 3, h: 3 },
  trend: { label: 'Metric + change', hint: 'The count against the window before it', icon: TrendingUp, w: 3, h: 3 },
  unique: { label: 'Unique count', hint: 'How many distinct values a field has', icon: Fingerprint, field: true, w: 3, h: 3 },
  timeline: { label: 'Events over time', hint: 'Area, line or bar chart of the count', icon: Activity, w: 6, h: 6 },
  split: { label: 'Split over time', hint: 'One series per top value of a field', icon: ChartColumnStacked, field: true, size: true, w: 6, h: 6 },
  top: { label: 'Horizontal bar', hint: 'Top values of a field', icon: ChartBar, field: true, size: true, w: 4, h: 6 },
  donut: { label: 'Pie', hint: 'Share of each top value', icon: ChartPie, field: true, size: true, w: 4, h: 6 },
  datatable: { label: 'Data table', hint: 'Top values with count and share', icon: Table2, field: true, size: true, w: 4, h: 6 },
  tagcloud: { label: 'Tag cloud', hint: 'Top values sized by count', icon: Cloud, field: true, size: true, w: 4, h: 5 },
  rare: { label: 'Rare values', hint: 'The least frequent values: oddities to check', icon: List, field: true, size: true, w: 4, h: 6 },
  heatmap: { label: 'Heat map', hint: 'Day of week by hour of day', icon: Grid3x3, w: 6, h: 6 },
  table: { label: 'Latest events', hint: 'The newest matching rows', icon: Rows3, w: 12, h: 7 },
}

export const INDEX_FIELDS = ['log_type', 'event_action', 'event_category', 'source_ip', 'user_name', 'agent_id']
export const DECODED_FIELDS = [
  'host.name', 'source.ip', 'destination.ip', 'user.name', 'process.name', 'process.executable',
  'process.parent.name', 'file.path', 'url.domain', 'dns.question.name', 'http.request.method',
  'user_agent.original', 'network.protocol', 'event.outcome', 'rule.name', 'threat.indicator.ip',
  'device.vendor_id', 'device.model.name',
]

export const TIME_WINDOWS: [number, string][] = [
  [1, 'Last 1 hour'], [6, 'Last 6 hours'], [12, 'Last 12 hours'], [24, 'Last 24 hours'],
  [72, 'Last 3 days'], [168, 'Last 7 days'], [336, 'Last 14 days'], [720, 'Last 30 days'],
]

export const windowLabel = (h: number) => TIME_WINDOWS.find(([v]) => v === h)?.[1] ?? `Last ${h} hours`

const PALETTE = ['var(--accent-cyan)', 'var(--accent-green)', 'var(--accent-orange)', 'var(--accent-yellow)',
  '#c4a7f5', '#5fd4c6', 'var(--accent-red)', '#f3a6c8']
export const color = (i: number) => PALETTE[i % PALETTE.length]

export function emptyWidget(): Widget {
  return { title: '', search_id: null, kind: 'logs', query: '', viz: 'count', field: 'log_type', limit: 10, hours: 24, chart: 'area' }
}

/** Widgets saved before the grid (width 1-3, no kind/query) get today's shape. */
export function normalize(raw: Partial<Widget>): Widget {
  const w = { ...emptyWidget(), ...raw } as Widget
  const spec = VIZ[w.viz] ?? VIZ.count
  return { ...w, w: w.w ?? (w.width ? w.width * 4 : spec.w), h: w.h ?? spec.h }
}

/** Place widgets with no position after the others, left to right. */
export function placeAll(ws: Widget[]): Widget[] {
  let x = 0
  let y = Math.max(0, ...ws.filter(w => w.y != null).map(w => (w.y ?? 0) + (w.h ?? 4)))
  let rowH = 0
  return ws.map(w => {
    if (w.x != null && w.y != null) return w
    const wd = w.w ?? 4
    if (x + wd > 12) { x = 0; y += rowH; rowH = 0 }
    const placed = { ...w, x, y }
    x += wd
    rowH = Math.max(rowH, w.h ?? 4)
    return placed
  })
}

export function apiError(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0] && typeof d[0].msg === 'string') return d[0].msg
  return fallback
}

const tz = (() => { try { return Intl.DateTimeFormat().resolvedOptions().timeZone } catch { return 'UTC' } })()

export function useWidgetData(w: Widget, scope: Scope, enabled = true) {
  const hours = scope.hours ?? w.hours
  const widget = { search_id: w.search_id || null, kind: w.kind, query: w.query, viz: w.viz, field: w.field, limit: w.limit }
  return useQuery<RunResult>({
    queryKey: ['widget-data', widget, hours, scope.query, scope.filters],
    queryFn: () => api.post('/api/dashboards/widget-data',
      { widget, hours, tz, query: scope.query, filters: scope.filters }).then(r => r.data),
    refetchInterval: scope.refreshMs,
    placeholderData: keepPreviousData,
    enabled,
    retry: false,
  })
}

type OnFilter = ((field: string, value: string, negate?: boolean) => void) | undefined

const axisTick = { fill: 'var(--text-muted)', fontSize: 11 }
const tooltipStyle = { background: 'var(--bg-card)', border: '1px solid var(--border-default)', fontSize: 12 }

function Empty() {
  return <p className="text-xs text-muted-foreground">No events match in this window.</p>
}

function BigNumber({ value, children }: { readonly value: number; readonly children?: ReactNode }) {
  return (
    <div className="h-full flex flex-col items-center justify-center text-center gap-1">
      <div className="text-4xl font-semibold tabular-nums leading-none">{value.toLocaleString()}</div>
      {children}
    </div>
  )
}

function ValueButton({ field, value, onFilter, children, className = '' }: {
  readonly field?: string; readonly value: string; readonly onFilter: OnFilter
  readonly children: ReactNode; readonly className?: string
}) {
  if (!onFilter || !field) return <span className={className}>{children}</span>
  return (
    <button type="button" className={`text-left hover:underline ${className}`} title={`Filter ${field}: ${value}`}
      onClick={e => onFilter(field, value, e.altKey)}>{children}</button>
  )
}

function TimeChart({ w, r, onFilter }: { readonly w: Widget; readonly r: RunResult; readonly onFilter: OnFilter }) {
  const keys = r.viz === 'split' ? (r.keys ?? []) : ['count']
  const data = (r.points ?? []).map(p => ({ time: new Date(p.t).getTime(), ...(r.viz === 'split' ? p.series : { count: p.count }) }))
  const long = r.hours > 48
  const common = { data, margin: { top: 6, right: 8, bottom: 0, left: 0 } }
  const axes = <>
    <CartesianGrid stroke="var(--border-default)" strokeOpacity={0.5} vertical={false} />
    <XAxis dataKey="time" type="number" scale="time" domain={['dataMin', 'dataMax']} tick={axisTick}
      tickFormatter={(t: number) => format(new Date(t), long ? 'dd MMM' : 'HH:mm')} minTickGap={24} />
    <YAxis allowDecimals={false} width={40} tick={axisTick} />
    <Tooltip labelFormatter={t => format(new Date(t as number), 'dd MMM HH:mm')} contentStyle={tooltipStyle} />
  </>
  const stack = r.viz === 'split' ? 'a' : undefined
  const chart = w.chart === 'bar' ? (
    <BarChart {...common}>{axes}{keys.map((k, i) => <Bar key={k} dataKey={k} stackId={stack} fill={color(i)} isAnimationActive={false} />)}</BarChart>
  ) : w.chart === 'line' ? (
    <LineChart {...common}>{axes}{keys.map((k, i) => <Line key={k} dataKey={k} type="monotone" dot={false} stroke={color(i)} strokeWidth={2} isAnimationActive={false} />)}</LineChart>
  ) : (
    <AreaChart {...common}>{axes}{keys.map((k, i) => <Area key={k} dataKey={k} type="monotone" stackId={stack} stroke={color(i)} fill={color(i)} fillOpacity={0.25} isAnimationActive={false} />)}</AreaChart>
  )
  return (
    <div className="h-full flex flex-col min-h-0">
      <div className="flex-1 min-h-0"><ResponsiveContainer width="100%" height="100%">{chart}</ResponsiveContainer></div>
      {r.viz === 'split' && keys.length > 0 && (
        <ul className="flex flex-wrap gap-x-3 gap-y-1 pt-1 text-xs">
          {keys.map((k, i) => (
            <li key={k} className="flex items-center gap-1 min-w-0">
              <span className="inline-block w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: color(i) }} />
              <ValueButton field={r.field} value={k} onFilter={onFilter} className="font-mono truncate max-w-[16ch]">{k}</ValueButton>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function Bars({ r, onFilter }: { readonly r: RunResult; readonly onFilter: OnFilter }) {
  const values = r.values ?? []
  const max = Math.max(1, ...values.map(v => v.count))
  return (
    <ul className="space-y-1 text-xs">
      {values.map((v, i) => (
        <li key={v.value} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 items-center">
          <div className="relative h-6 rounded bg-muted overflow-hidden">
            <div className="absolute inset-y-0 left-0" style={{ width: `${(v.count / max) * 100}%`, background: color(r.viz === 'rare' ? 2 : 0), opacity: 0.35 }} />
            <ValueButton field={r.field} value={v.value} onFilter={onFilter} className="relative px-1.5 font-mono truncate block leading-6 w-full">
              {i + 1}. {v.value}
            </ValueButton>
          </div>
          <span className="tabular-nums">{v.count.toLocaleString()}</span>
        </li>
      ))}
    </ul>
  )
}

function Donut({ r, onFilter }: { readonly r: RunResult; readonly onFilter: OnFilter }) {
  const values = r.values ?? []
  const data = [...values.map(v => ({ name: v.value, value: v.count })), ...(r.other ? [{ name: 'Other', value: r.other }] : [])]
  const sum = data.reduce((a, b) => a + b.value, 0) || 1
  return (
    <div className="h-full grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-2 min-h-0">
      <div className="min-h-[140px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius="55%" outerRadius="90%" isAnimationActive={false}
              onClick={(d: { name?: string }) => { if (onFilter && r.field && d.name && d.name !== 'Other') onFilter(r.field, d.name) }}>
              {data.map((d, i) => <Cell key={d.name} fill={d.name === 'Other' ? 'var(--border-default)' : color(i)} stroke="var(--bg-card)" cursor={onFilter ? 'pointer' : undefined} />)}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <ul className="text-xs space-y-1 overflow-auto min-w-0 self-center">
        {data.map((d, i) => (
          <li key={d.name} className="flex items-center gap-1.5 min-w-0">
            <span className="inline-block w-2.5 h-2.5 rounded-sm shrink-0" style={{ background: d.name === 'Other' ? 'var(--border-default)' : color(i) }} />
            {d.name === 'Other' ? <span className="text-muted-foreground">Other</span>
              : <ValueButton field={r.field} value={d.name} onFilter={onFilter} className="font-mono truncate min-w-0">{d.name}</ValueButton>}
            <span className="ml-auto tabular-nums text-muted-foreground">{Math.round((d.value / sum) * 100)}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function DataTable({ r, onFilter }: { readonly r: RunResult; readonly onFilter: OnFilter }) {
  const values = r.values ?? []
  const sum = values.reduce((a, b) => a + b.count, 0) + (r.other ?? 0) || 1
  return (
    <table className="text-xs w-full">
      <thead><tr className="text-left text-muted-foreground border-b border-border">
        <th className="py-1 pr-2 font-medium">{r.field}</th><th className="py-1 pr-2 font-medium text-right">Count</th><th className="py-1 font-medium text-right">Share</th>
      </tr></thead>
      <tbody>
        {values.map(v => (
          <tr key={v.value} className="border-b border-border last:border-0">
            <td className="py-1 pr-2 font-mono break-all"><ValueButton field={r.field} value={v.value} onFilter={onFilter}>{v.value}</ValueButton></td>
            <td className="py-1 pr-2 text-right tabular-nums">{v.count.toLocaleString()}</td>
            <td className="py-1 text-right tabular-nums text-muted-foreground">{((v.count / sum) * 100).toFixed(1)}%</td>
          </tr>
        ))}
        {!!r.other && <tr><td className="py-1 pr-2 text-muted-foreground">Other</td><td className="py-1 pr-2 text-right tabular-nums">{r.other.toLocaleString()}</td>
          <td className="py-1 text-right tabular-nums text-muted-foreground">{((r.other / sum) * 100).toFixed(1)}%</td></tr>}
      </tbody>
    </table>
  )
}

function TagCloud({ r, onFilter }: { readonly r: RunResult; readonly onFilter: OnFilter }) {
  const values = r.values ?? []
  const max = Math.max(...values.map(v => v.count))
  const min = Math.min(...values.map(v => v.count))
  const size = (c: number) => 12 + (max === min ? 8 : ((Math.log(c) - Math.log(min)) / (Math.log(max) - Math.log(min))) * 22)
  return (
    <div className="h-full flex flex-wrap items-center justify-center content-center gap-x-3 gap-y-1">
      {[...values].sort((a, b) => a.value.localeCompare(b.value)).map(v => (
        <ValueButton key={v.value} field={r.field} value={v.value} onFilter={onFilter} className="font-medium leading-tight break-all">
          <span style={{ fontSize: size(v.count), color: color(values.indexOf(v)) }} title={`${v.count.toLocaleString()} events`}>{v.value}</span>
        </ValueButton>
      ))}
    </div>
  )
}

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function Heatmap({ r }: { readonly r: RunResult }) {
  const grid = r.grid ?? []
  const max = Math.max(1, ...grid.flat())
  return (
    <div className="overflow-x-auto h-full">
      <div className="grid gap-[2px] min-w-[420px] text-[10px] text-muted-foreground" style={{ gridTemplateColumns: '28px repeat(24, minmax(0, 1fr))' }}>
        <span />
        {Array.from({ length: 24 }, (_, h) => <span key={h} className="text-center">{h % 3 === 0 ? h : ''}</span>)}
        {grid.map((row, d) => [
          <span key={`d${d}`} className="leading-5">{DAYS[d]}</span>,
          ...row.map((c, h) => (
            <span key={`${d}-${h}`} className="h-5 rounded-sm" title={`${DAYS[d]} ${String(h).padStart(2, '0')}:00 · ${c.toLocaleString()} events`}
              style={{ background: c ? `color-mix(in srgb, var(--accent-orange) ${Math.round(15 + (c / max) * 85)}%, transparent)` : 'var(--bg-panel, transparent)' }} />
          )),
        ])}
      </div>
      <p className="text-[10px] text-muted-foreground pt-1">Hours in {r.tz}</p>
    </div>
  )
}

function LatestRows({ r }: { readonly r: RunResult }) {
  return (
    <table className="text-xs w-full">
      <tbody>{(r.rows ?? []).map(row => (
        <tr key={row.id} className="align-top border-b border-border last:border-0">
          <td className="py-1 pr-2 whitespace-nowrap text-muted-foreground">{format(new Date(row.created_at), 'dd MMM HH:mm:ss')}</td>
          <td className="py-1 pr-2 whitespace-nowrap">{row.hostname ?? ''}</td>
          <td className="py-1 pr-2 whitespace-nowrap text-muted-foreground">{row.log_type ?? ''}</td>
          <td className="py-1 font-mono break-all">{row.message}</td>
        </tr>
      ))}</tbody>
    </table>
  )
}

export function VizBody({ w, r, onFilter }: { readonly w: Widget; readonly r: RunResult; readonly onFilter?: OnFilter }) {
  switch (r.viz) {
    case 'count': return <BigNumber value={r.total}><span className="text-xs text-muted-foreground">events</span></BigNumber>
    case 'trend': {
      const up = (r.change_pct ?? 0) > 0
      return (
        <BigNumber value={r.total}>
          {r.change_pct == null ? <span className="text-xs text-muted-foreground">nothing in the window before</span> : (
            <span className="text-xs flex items-center gap-1" style={{ color: up ? 'var(--accent-orange)' : 'var(--accent-green)' }}>
              {up ? <ArrowUp size={12} /> : <ArrowDown size={12} />}{Math.abs(r.change_pct)}%
              <span className="text-muted-foreground">vs {(r.previous ?? 0).toLocaleString()} before</span>
            </span>
          )}
        </BigNumber>
      )
    }
    case 'unique': return <BigNumber value={r.unique ?? 0}><span className="text-xs text-muted-foreground">distinct <code>{r.field}</code></span></BigNumber>
    case 'timeline':
    case 'split': return r.total ? <TimeChart w={w} r={r} onFilter={onFilter} /> : <Empty />
    case 'heatmap': return r.total ? <Heatmap r={r} /> : <Empty />
    case 'table': return r.rows?.length ? <LatestRows r={r} /> : <Empty />
    default:
      if (!r.values?.length) return <Empty />
      if (r.viz === 'donut') return <Donut r={r} onFilter={onFilter} />
      if (r.viz === 'datatable') return <DataTable r={r} onFilter={onFilter} />
      if (r.viz === 'tagcloud') return <TagCloud r={r} onFilter={onFilter} />
      return <Bars r={r} onFilter={onFilter} />
  }
}
