import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { ArrowDown, ArrowUp, LayoutGrid, Loader2, Pencil, Plus, Trash2, X } from 'lucide-react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '@/api/client'
import { useSavedSearches } from '@/components/SavedSearchBar'

// Dashboards built from saved searches (server-api/app/api/routes/dashboards.py).

type Viz = 'count' | 'timeline' | 'top' | 'table'

interface Widget {
  id?: string
  title: string
  search_id: string
  viz: Viz
  hours: number
  field: string
  width: 1 | 2 | 3
}

interface Dashboard {
  id: string
  name: string
  description: string | null
  widgets: Widget[]
  shared: boolean
  mine: boolean
  editable: boolean
}

interface RunResult {
  search: { id: string; name: string; kind: 'logs' | 'events' }
  total: number
  points?: { t: string; count: number }[]
  values?: { value: string; count: number }[]
  rows?: { id: string; created_at: string; log_type: string | null; hostname: string | null; message: string }[]
}

const VIZ: Record<Viz, string> = { count: 'Count', timeline: 'Timeline', top: 'Top values', table: 'Latest rows' }
const TOP_FIELDS = ['log_type', 'event_action', 'event_category', 'source_ip', 'user_name', 'agent_id']
const WINDOWS: [number, string][] = [[1, '1 hour'], [6, '6 hours'], [24, '24 hours'], [72, '3 days'], [168, '7 days'], [720, '30 days']]
const SPAN: Record<1 | 2 | 3, string> = { 1: 'md:col-span-1', 2: 'md:col-span-2', 3: 'md:col-span-3' }

function apiError(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

function WidgetView({ w }: { readonly w: Widget }) {
  const q = useQuery<RunResult>({
    queryKey: ['widget', w.search_id, w.viz, w.hours, w.field],
    queryFn: () => api.get(`/api/saved-searches/${w.search_id}/run`,
      { params: { viz: w.viz, hours: w.hours, field: w.field, limit: 10 } }).then(r => r.data),
    refetchInterval: 60_000,
  })
  const label = WINDOWS.find(([h]) => h === w.hours)?.[1] ?? `${w.hours} h`
  return (
    <section className={`panel col-span-1 ${SPAN[w.width]} min-w-0`}>
      <div className="panel__body space-y-2">
        <div className="flex items-baseline justify-between gap-2">
          <h3 className="text-sm font-semibold truncate">{w.title || q.data?.search.name || 'Widget'}</h3>
          <span className="text-xs text-muted-foreground whitespace-nowrap">last {label}</span>
        </div>
        {q.isLoading ? <Loader2 size={16} className="animate-spin" />
          : q.isError ? <p className="text-xs text-destructive">{apiError(q.error, 'Could not run the saved search.')}</p>
          : q.data && <WidgetBody w={w} r={q.data} />}
        {q.data && (
          <Link className="text-xs underline text-muted-foreground"
            to={`/${q.data.search.kind}`} title="Open the search page (load it from Saved searches)">
            {q.data.search.name} · {q.data.total.toLocaleString()} matching
          </Link>
        )}
      </div>
    </section>
  )
}

function WidgetBody({ w, r }: { readonly w: Widget; readonly r: RunResult }) {
  if (w.viz === 'count') return <div className="text-4xl font-semibold tabular-nums">{r.total.toLocaleString()}</div>
  if (w.viz === 'timeline') {
    const data = (r.points ?? []).map(p => ({ time: new Date(p.t).getTime(), count: p.count }))
    return (
      <ResponsiveContainer width="100%" height={160}>
        <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid stroke="var(--border-default)" strokeOpacity={0.5} vertical={false} />
          <XAxis dataKey="time" type="number" scale="time" domain={['dataMin', 'dataMax']}
            tickFormatter={(t: number) => format(new Date(t), w.hours > 48 ? 'dd MMM' : 'HH:mm')}
            tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
          <YAxis allowDecimals={false} width={36} tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
          <Tooltip labelFormatter={t => format(new Date(t as number), 'dd MMM HH:mm')}
            contentStyle={{ background: 'var(--surface-raised, #111)', border: '1px solid var(--border-default)' }} />
          <Area type="monotone" dataKey="count" stroke="var(--accent-cyan)" fill="var(--accent-cyan)" fillOpacity={0.2} />
        </AreaChart>
      </ResponsiveContainer>
    )
  }
  if (w.viz === 'top') {
    const values = r.values ?? []
    const max = Math.max(1, ...values.map(v => v.count))
    if (!values.length) return <p className="text-xs text-muted-foreground">Nothing in this window.</p>
    return (
      <ul className="space-y-1 text-xs">
        {values.map(v => (
          <li key={v.value} className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 items-center">
            <div className="relative h-5 rounded bg-muted overflow-hidden">
              <div className="absolute inset-y-0 left-0 bg-primary/30" style={{ width: `${(v.count / max) * 100}%` }} />
              <span className="relative px-1.5 font-mono truncate block leading-5">{v.value}</span>
            </div>
            <span className="tabular-nums">{v.count.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    )
  }
  const rows = r.rows ?? []
  if (!rows.length) return <p className="text-xs text-muted-foreground">Nothing in this window.</p>
  return (
    <div className="overflow-x-auto">
      <table className="text-xs w-full">
        <tbody>{rows.map(row => (
          <tr key={row.id} className="align-top border-b border-border last:border-0">
            <td className="py-1 pr-2 whitespace-nowrap text-muted-foreground">{format(new Date(row.created_at), 'dd MMM HH:mm')}</td>
            <td className="py-1 pr-2 whitespace-nowrap">{row.hostname ?? row.log_type ?? ''}</td>
            <td className="py-1 font-mono break-all">{row.message}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  )
}

function Editor({ initial, onDone }: { readonly initial: Dashboard | null; readonly onDone: (id?: string) => void }) {
  const qc = useQueryClient()
  const searches = useSavedSearches()
  const [name, setName] = useState(initial?.name ?? '')
  const [shared, setShared] = useState(initial?.shared ?? false)
  const [widgets, setWidgets] = useState<Widget[]>(initial?.widgets ?? [])
  const [draft, setDraft] = useState<Widget>({ title: '', search_id: '', viz: 'count', hours: 24, field: 'log_type', width: 1 })
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), shared, widgets }
      return (initial ? api.put(`/api/dashboards/${initial.id}`, body) : api.post('/api/dashboards', body))
        .then(r => r.data as Dashboard)
    },
    onSuccess: d => { void qc.invalidateQueries({ queryKey: ['dashboards'] }); onDone(d.id) },
  })
  const move = (i: number, by: number) => setWidgets(ws => {
    const next = [...ws]
    const [w] = next.splice(i, 1)
    next.splice(Math.max(0, Math.min(next.length, i + by)), 0, w)
    return next
  })
  const nameOf = (id: string) => searches.data?.find(s => s.id === id)?.name ?? 'saved search'

  return (
    <section className="panel">
      <div className="panel__body space-y-4">
        <div className="control-cluster flex-wrap items-end">
          <label className="field"><span>Name</span>
            <input className="ui-input w-72 max-w-full" value={name} onChange={e => setName(e.target.value)} maxLength={120}
              placeholder="SOC wall, Web servers, VIP accounts…" /></label>
          <label className="flex items-center gap-1.5 text-sm cursor-pointer pb-2">
            <input type="checkbox" checked={shared} onChange={e => setShared(e.target.checked)} /> Share with my team
          </label>
        </div>

        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Widgets</h3>
          {!widgets.length && <p className="text-xs text-muted-foreground">No widgets yet. Add one below.</p>}
          <ul className="space-y-1">
            {widgets.map((w, i) => (
              <li key={w.id ?? i} className="flex flex-wrap items-center gap-2 text-sm rounded border border-border px-2 py-1">
                <span className="font-medium min-w-0 flex-1 truncate">{w.title || nameOf(w.search_id)}</span>
                <span className="text-xs text-muted-foreground">{VIZ[w.viz]}{w.viz === 'top' ? ` · ${w.field}` : ''} · {w.hours} h · width {w.width}</span>
                <button type="button" className="ui-icon-button" aria-label="Move up" disabled={i === 0} onClick={() => move(i, -1)}><ArrowUp size={14} /></button>
                <button type="button" className="ui-icon-button" aria-label="Move down" disabled={i === widgets.length - 1} onClick={() => move(i, 1)}><ArrowDown size={14} /></button>
                <button type="button" className="ui-icon-button" aria-label="Remove widget" onClick={() => setWidgets(ws => ws.filter((_, j) => j !== i))}><X size={14} /></button>
              </li>
            ))}
          </ul>
        </div>

        <fieldset className="rounded border border-border p-3 space-y-2">
          <legend className="text-sm font-medium px-1">Add a widget</legend>
          {searches.data && !searches.data.length ? (
            <p className="text-xs text-muted-foreground">Save a search first on <Link className="underline" to="/logs">Log search</Link> or <Link className="underline" to="/events">Events</Link>.</p>
          ) : (
            <div className="control-cluster flex-wrap items-end">
              <label className="field"><span>Saved search</span>
                <select className="ui-input" value={draft.search_id} onChange={e => setDraft({ ...draft, search_id: e.target.value })}>
                  <option value="">Choose…</option>
                  {(searches.data ?? []).map(s => <option key={s.id} value={s.id}>{s.name}{s.shared ? ' (team)' : ''}</option>)}
                </select></label>
              <label className="field"><span>Show as</span>
                <select className="ui-input" value={draft.viz} onChange={e => setDraft({ ...draft, viz: e.target.value as Viz })}>
                  {(Object.keys(VIZ) as Viz[]).map(v => <option key={v} value={v}>{VIZ[v]}</option>)}
                </select></label>
              {draft.viz === 'top' && (
                <label className="field"><span>Field</span>
                  <select className="ui-input" value={draft.field} onChange={e => setDraft({ ...draft, field: e.target.value })}>
                    {TOP_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}
                  </select></label>
              )}
              <label className="field"><span>Window</span>
                <select className="ui-input" value={draft.hours} onChange={e => setDraft({ ...draft, hours: Number(e.target.value) })}>
                  {WINDOWS.map(([h, l]) => <option key={h} value={h}>{l}</option>)}
                </select></label>
              <label className="field"><span>Width</span>
                <select className="ui-input" value={draft.width} onChange={e => setDraft({ ...draft, width: Number(e.target.value) as 1 | 2 | 3 })}>
                  <option value={1}>1/3</option><option value={2}>2/3</option><option value={3}>Full</option>
                </select></label>
              <label className="field"><span>Title (optional)</span>
                <input className="ui-input w-48" value={draft.title} maxLength={120} onChange={e => setDraft({ ...draft, title: e.target.value })} /></label>
              <button type="button" className="ui-button" disabled={!draft.search_id || widgets.length >= 24}
                onClick={() => { setWidgets(ws => [...ws, draft]); setDraft({ ...draft, title: '' }) }}><Plus size={14} /> Add</button>
            </div>
          )}
        </fieldset>

        {save.isError && <p role="alert" className="text-xs text-destructive">{apiError(save.error, 'Could not save the dashboard.')}</p>}
        <div className="control-cluster">
          <button type="button" className="ui-button ui-button--primary" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? 'Saving…' : 'Save dashboard'}</button>
          <button type="button" className="ui-button ui-button--quiet" onClick={() => onDone(initial?.id)}>Cancel</button>
        </div>
      </div>
    </section>
  )
}

export default function CustomDashboardsPage() {
  const qc = useQueryClient()
  const list = useQuery<Dashboard[]>({ queryKey: ['dashboards'], queryFn: () => api.get('/api/dashboards').then(r => r.data) })
  const [selected, setSelected] = useState<string>('')
  const [editing, setEditing] = useState<'new' | 'current' | null>(null)
  useEffect(() => {
    if (!selected && list.data?.length) setSelected(list.data[0].id)
  }, [list.data, selected])
  const current = list.data?.find(d => d.id === selected) ?? null
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/dashboards/${id}`),
    onSuccess: () => { setSelected(''); void qc.invalidateQueries({ queryKey: ['dashboards'] }) },
  })

  return (
    <div className="workspace space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <LayoutGrid size={18} aria-hidden="true" />
        <h1 className="text-xl font-bold">Dashboards</h1>
        <select className="ui-input w-auto" aria-label="Dashboard" value={selected} onChange={e => { setSelected(e.target.value); setEditing(null) }}>
          {!list.data?.length && <option value="">No dashboards yet</option>}
          {(list.data ?? []).map(d => <option key={d.id} value={d.id}>{d.name}{d.shared ? ' (team)' : ''}</option>)}
        </select>
        <div className="flex-1" />
        {current?.editable && !editing && <>
          <button className="ui-button" onClick={() => setEditing('current')}><Pencil size={14} /> Edit</button>
          <button className="ui-button ui-button--quiet" disabled={remove.isPending} onClick={() => remove.mutate(current.id)}>
            <Trash2 size={14} /> Delete</button>
        </>}
        {!editing && <button className="ui-button ui-button--primary" onClick={() => setEditing('new')}><Plus size={14} /> New dashboard</button>}
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        Each widget runs a saved search from Log search or Events in your group, as a count, a timeline, top values or the latest rows, and refreshes every minute.
      </p>

      {editing ? (
        <Editor initial={editing === 'current' ? current : null}
          onDone={id => { setEditing(null); if (id) setSelected(id) }} />
      ) : list.isLoading ? <Loader2 size={16} className="animate-spin" />
        : list.isError ? <p className="text-sm text-destructive">Could not load dashboards.</p>
        : !current ? <p className="text-sm text-muted-foreground">Create a dashboard from your saved searches.</p>
        : !current.widgets.length ? <p className="text-sm text-muted-foreground">This dashboard has no widgets yet.</p>
        : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {current.widgets.map((w, i) => <WidgetView key={w.id ?? i} w={w} />)}
          </div>
        )}
    </div>
  )
}
