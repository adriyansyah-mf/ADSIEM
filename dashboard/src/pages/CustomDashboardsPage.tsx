import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { GripVertical, LayoutGrid, Loader2, Pencil, Plus, RefreshCw, Search, Trash2, X } from 'lucide-react'
import { ResponsiveGridLayout, useContainerWidth, verticalCompactor } from 'react-grid-layout'
import type { Layout, LayoutItem, ResponsiveLayouts } from 'react-grid-layout'
import 'react-grid-layout/css/styles.css'
import 'react-resizable/css/styles.css'
import '@/components/dashboards/dashboards.css'
import { api } from '@/api/client'
import {
  DECODED_FIELDS, INDEX_FIELDS, TIME_WINDOWS, VIZ, VizBody, apiError, normalize, placeAll, useWidgetData, windowLabel,
} from '@/components/dashboards/viz'
import type { Pin, Scope, Widget } from '@/components/dashboards/viz'
import VizEditor from '@/components/dashboards/VizEditor'

// Custom dashboards, Wazuh / OpenSearch Dashboards style: a grid of
// visualizations sharing one time range, query bar and filter pills
// (server-api/app/api/routes/dashboards.py).

interface Dashboard {
  id: string
  name: string
  description: string | null
  widgets: Widget[]
  shared: boolean
  mine: boolean
  editable: boolean
}

interface Draft { id?: string; name: string; shared: boolean; widgets: Widget[] }

function DashGrid({ className, layout, editing, onLayout, children }: {
  className: string
  layout: LayoutItem[]
  editing: boolean
  onLayout: (layout: Layout) => void
  children: ReactNode
}) {
  const { width, containerRef, mounted } = useContainerWidth()
  return (
    <div ref={containerRef}>
      {mounted && (
        <ResponsiveGridLayout className={className} width={width} layouts={{ lg: layout }}
          breakpoints={{ lg: 768, xs: 0 }} cols={{ lg: 12, xs: 1 }} rowHeight={44} margin={[12, 12]} containerPadding={[0, 0]}
          dragConfig={{ enabled: editing, handle: '.viz-panel__drag' }} resizeConfig={{ enabled: editing }}
          compactor={verticalCompactor}
          onLayoutChange={(_: Layout, all: ResponsiveLayouts) => { if (all.lg) onLayout(all.lg) }}>
          {children}
        </ResponsiveGridLayout>
      )}
    </div>
  )
}
const REFRESH: [number | false, string][] = [[false, 'Off'], [30_000, '30 s'], [60_000, '1 min'], [300_000, '5 min']]
const newId = () => Math.random().toString(36).slice(2, 14)

function prepare(ws: Widget[]): Widget[] {
  return placeAll(ws.map(w => ({ ...normalize(w), id: w.id || newId() })))
}

function Panel({ w, scope, editing, onFilter, onEdit, onRemove }: {
  readonly w: Widget
  readonly scope: Scope
  readonly editing: boolean
  readonly onFilter: (field: string, value: string, negate?: boolean) => void
  readonly onEdit: () => void
  readonly onRemove: () => void
}) {
  const q = useWidgetData(w, scope)
  const Icon = VIZ[w.viz]?.icon ?? LayoutGrid
  const source = q.data?.search.name ?? (w.query ? w.query : `all ${w.kind}`)
  return (
    <section className="panel viz-panel" aria-label={w.title}>
      <header className="viz-panel__head">
        {editing && <span className="viz-panel__drag" title="Drag to move"><GripVertical size={14} aria-hidden="true" /></span>}
        <Icon size={13} className="text-muted-foreground shrink-0" aria-hidden="true" />
        <h3 className="text-sm font-semibold truncate min-w-0 flex-1" title={w.title}>{w.title}</h3>
        {q.isFetching && <Loader2 size={12} className="animate-spin text-muted-foreground" aria-label="Loading" />}
        {editing && <>
          <button type="button" className="ui-icon-button !w-7 !min-h-7" aria-label={`Edit ${w.title}`} onClick={onEdit}><Pencil size={13} /></button>
          <button type="button" className="ui-icon-button !w-7 !min-h-7" aria-label={`Remove ${w.title}`} onClick={onRemove}><X size={13} /></button>
        </>}
      </header>
      <div className="viz-panel__body">
        {q.isError ? <p className="text-xs text-destructive">{apiError(q.error, 'This panel could not run.')}</p>
          : q.data ? <VizBody w={w} r={q.data} onFilter={editing ? undefined : onFilter} />
          : <Loader2 size={16} className="animate-spin" />}
      </div>
      <footer className="viz-panel__foot" title={source}>
        {q.data ? `${q.data.total.toLocaleString()} events · ` : ''}{scope.hours == null ? `${windowLabel(w.hours)} · ` : ''}{source}
      </footer>
    </section>
  )
}

function FilterBar({ filters, setFilters }: { readonly filters: Pin[]; readonly setFilters: (f: Pin[]) => void }) {
  const [adding, setAdding] = useState(false)
  const [field, setField] = useState('host.name')
  const [value, setValue] = useState('')
  const [negate, setNegate] = useState(false)
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      {filters.map((p, i) => (
        <span key={`${p.field}=${p.value}`} className={`dash-pill ${p.negate ? 'dash-pill--not' : ''}`}>
          <button type="button" title={p.negate ? 'Include these again' : 'Exclude these instead'}
            onClick={() => setFilters(filters.map((x, j) => j === i ? { ...x, negate: !x.negate } : x))}>
            {p.negate && <b className="mr-1">NOT</b>}<span className="text-muted-foreground">{p.field}:</span>
            <span className="font-mono ml-1 truncate max-w-[24ch]">{p.value}</span>
          </button>
          <button type="button" aria-label={`Remove filter ${p.field}: ${p.value}`} onClick={() => setFilters(filters.filter((_, j) => j !== i))}><X size={12} /></button>
        </span>
      ))}
      {adding ? (
        <form className="flex flex-wrap items-center gap-1.5" onSubmit={e => {
          e.preventDefault()
          if (!value.trim()) return
          setFilters([...filters.filter(p => !(p.field === field && p.value === value.trim())), { field, value: value.trim(), negate }])
          setValue(''); setAdding(false)
        }}>
          <select className="ui-input w-auto !min-h-8 text-xs" aria-label="Filter field" value={field} onChange={e => setField(e.target.value)}>
            <optgroup label="Index fields">{INDEX_FIELDS.map(f => <option key={f}>{f}</option>)}</optgroup>
            <optgroup label="Decoded fields">{DECODED_FIELDS.map(f => <option key={f}>{f}</option>)}</optgroup>
          </select>
          <select className="ui-input w-auto !min-h-8 text-xs" aria-label="Operator" value={negate ? 'not' : 'is'} onChange={e => setNegate(e.target.value === 'not')}>
            <option value="is">is</option><option value="not">is not</option>
          </select>
          <input className="ui-input w-44 !min-h-8 text-xs font-mono" aria-label="Filter value" autoFocus value={value} maxLength={512}
            onChange={e => setValue(e.target.value)} placeholder="exact value" />
          <button className="ui-button !min-h-8 text-xs" disabled={!value.trim()}>Add</button>
          <button type="button" className="ui-button ui-button--quiet !min-h-8 text-xs" onClick={() => setAdding(false)}>Cancel</button>
        </form>
      ) : (
        <button type="button" className="ui-button ui-button--quiet !min-h-8 text-xs" onClick={() => setAdding(true)}><Plus size={12} /> Add filter</button>
      )}
      {filters.length > 0 && !adding && (
        <button type="button" className="text-xs underline text-muted-foreground" onClick={() => setFilters([])}>Clear all</button>
      )}
      {!filters.length && !adding && <span className="text-muted-foreground">Tip: click a value in a chart to filter every panel by it (Alt+click to exclude it).</span>}
    </div>
  )
}

export default function CustomDashboardsPage() {
  const qc = useQueryClient()
  const [params, setParams] = useSearchParams()
  const list = useQuery<Dashboard[]>({ queryKey: ['dashboards'], queryFn: () => api.get('/api/dashboards').then(r => r.data) })
  const selected = params.get('d') ?? ''
  const select = (id: string) => setParams(p => { const n = new URLSearchParams(p); if (id) n.set('d', id); else n.delete('d'); return n }, { replace: true })
  useEffect(() => {
    if (!selected && list.data?.length) select(list.data[0].id)
  }, [list.data, selected])
  const current = list.data?.find(d => d.id === selected) ?? null

  // toolbar, shared by every panel
  const [hours, setHours] = useState<number | null>(24)
  const [queryText, setQueryText] = useState('')
  const [query, setQuery] = useState('')
  const [filters, setFilters] = useState<Pin[]>([])
  const [refreshMs, setRefreshMs] = useState<number | false>(60_000)
  const scope: Scope = useMemo(() => ({ hours, query, filters, refreshMs }), [hours, query, filters, refreshMs])
  const addFilter = (field: string, value: string, negate = false) =>
    setFilters(fs => [...fs.filter(p => !(p.field === field && p.value === value)), { field, value, negate }])

  // edit mode works on a copy, saved in one go like Wazuh's Save dashboard
  const [draft, setDraft] = useState<Draft | null>(null)
  const [editor, setEditor] = useState<{ index: number | null } | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const editing = draft !== null
  const widgets = useMemo(() => prepare(editing ? draft.widgets : current?.widgets ?? []), [editing, draft, current])

  const save = useMutation({
    mutationFn: (d: Draft) => {
      const body = { name: d.name.trim(), shared: d.shared, widgets: d.widgets }
      return (d.id ? api.put(`/api/dashboards/${d.id}`, body) : api.post('/api/dashboards', body)).then(r => r.data as Dashboard)
    },
    onSuccess: d => { void qc.invalidateQueries({ queryKey: ['dashboards'] }); setDraft(null); select(d.id) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/dashboards/${id}`),
    onSuccess: () => { setConfirmDelete(false); select(''); void qc.invalidateQueries({ queryKey: ['dashboards'] }) },
  })
  const startEdit = (d: Dashboard | null) => {
    save.reset()
    setDraft(d ? { id: d.id, name: d.name, shared: d.shared, widgets: prepare(d.widgets) } : { name: '', shared: false, widgets: [] })
  }
  const setWidgets = (fn: (ws: Widget[]) => Widget[]) => setDraft(d => d && { ...d, widgets: fn(prepare(d.widgets)) })
  const onLayout = (layout: Layout) => {
    if (!editing) return
    const at = new Map(layout.map(l => [l.i, l]))
    setWidgets(ws => {
      const next = ws.map(w => { const l = at.get(w.id!); return l ? { ...w, x: l.x, y: l.y, w: l.w, h: l.h } : w })
      return next.every((w, i) => w.x === ws[i].x && w.y === ws[i].y && w.w === ws[i].w && w.h === ws[i].h) ? ws : next
    })
  }
  const layout: LayoutItem[] = widgets.map(w => ({ i: w.id!, x: w.x ?? 0, y: w.y ?? 0, w: w.w ?? 4, h: w.h ?? 4, minW: 2, minH: 2 }))

  return (
    <div className="workspace space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <LayoutGrid size={18} aria-hidden="true" />
        <h1 className="text-xl font-bold">Dashboards</h1>
        {editing ? (
          <>
            <input className="ui-input w-64 max-w-full" aria-label="Dashboard name" placeholder="Dashboard name, e.g. SOC wall"
              value={draft.name} maxLength={120} onChange={e => setDraft({ ...draft, name: e.target.value })} />
            <label className="flex items-center gap-1.5 text-sm cursor-pointer">
              <input type="checkbox" checked={draft.shared} onChange={e => setDraft({ ...draft, shared: e.target.checked })} /> Share with my team
            </label>
            <div className="flex-1" />
            <button className="ui-button" onClick={() => setEditor({ index: null })} disabled={draft.widgets.length >= 24}>
              <Plus size={14} /> Add visualization</button>
            <button className="ui-button ui-button--quiet" onClick={() => setDraft(null)}>Cancel</button>
            <button className="ui-button ui-button--primary" disabled={!draft.name.trim() || save.isPending} onClick={() => save.mutate(draft)}>
              {save.isPending ? 'Saving…' : 'Save dashboard'}</button>
          </>
        ) : (
          <>
            <select className="ui-input w-auto" aria-label="Dashboard" value={selected} onChange={e => { select(e.target.value); setConfirmDelete(false) }}>
              {!list.data?.length && <option value="">No dashboards yet</option>}
              {(list.data ?? []).map(d => <option key={d.id} value={d.id}>{d.name}{d.shared ? ' (team)' : ''}</option>)}
            </select>
            <div className="flex-1" />
            {current?.editable && (confirmDelete ? (
              <span className="control-cluster text-sm">
                Delete “{current.name}”?
                <button className="ui-button" disabled={remove.isPending} onClick={() => remove.mutate(current.id)}><Trash2 size={14} /> Delete</button>
                <button className="ui-button ui-button--quiet" onClick={() => setConfirmDelete(false)}>Keep</button>
              </span>
            ) : <>
              <button className="ui-button" onClick={() => startEdit(current)}><Pencil size={14} /> Edit</button>
              <button className="ui-button ui-button--quiet" onClick={() => setConfirmDelete(true)}><Trash2 size={14} /> Delete</button>
            </>)}
            <button className="ui-button ui-button--primary" onClick={() => startEdit(null)}><Plus size={14} /> New dashboard</button>
          </>
        )}
      </div>

      <section className="panel"><div className="panel__body space-y-2 !py-3">
        <form className="flex flex-wrap items-center gap-2" onSubmit={e => { e.preventDefault(); setQuery(queryText.trim()) }}>
          <div className="relative flex-1 min-w-[220px]">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <input className="ui-input w-full pl-8 font-mono text-xs" aria-label="Search every panel (Lucene)" value={queryText} maxLength={512}
              onChange={e => setQueryText(e.target.value)} placeholder='Search every panel, e.g. host.name:web-01 AND NOT user.name:svc_*' />
          </div>
          <select className="ui-input w-auto" aria-label="Time range" value={hours ?? 'own'}
            onChange={e => setHours(e.target.value === 'own' ? null : Number(e.target.value))}>
            {TIME_WINDOWS.map(([h, l]) => <option key={h} value={h}>{l}</option>)}
            <option value="own">Each panel's own</option>
          </select>
          <select className="ui-input w-auto" aria-label="Auto refresh" value={String(refreshMs)}
            onChange={e => setRefreshMs(e.target.value === 'false' ? false : Number(e.target.value))}>
            {REFRESH.map(([ms, l]) => <option key={l} value={String(ms)}>Refresh: {l}</option>)}
          </select>
          <button className="ui-button ui-button--primary" title="Apply the query and refresh every panel"
            onClick={() => { void qc.invalidateQueries({ queryKey: ['widget-data'] }) }}><RefreshCw size={14} /> Update</button>
        </form>
        <FilterBar filters={filters} setFilters={setFilters} />
      </div></section>

      {save.isError && <p role="alert" className="text-xs text-destructive">{apiError(save.error, 'Could not save the dashboard.')}</p>}
      {editing && widgets.length > 0 && (
        <p className="text-xs text-muted-foreground">Drag a panel by its grip, resize it from the bottom-right corner, then Save dashboard.</p>
      )}

      {list.isLoading ? <Loader2 size={16} className="animate-spin" />
        : list.isError ? <p className="text-sm text-destructive">Could not load dashboards.</p>
        : !editing && !current ? (
          <section className="panel"><div className="panel__body space-y-3">
            <p className="font-medium">No dashboard yet</p>
            <p className="text-sm text-muted-foreground max-w-2xl">
              A dashboard is a grid of visualizations: metrics, charts over time, pies, tables, tag clouds and heat maps
              over your logs and events. The time range, search bar and filters above narrow every panel at once.
            </p>
            <button className="ui-button ui-button--primary" onClick={() => startEdit(null)}><Plus size={14} /> Create dashboard</button>
          </div></section>
        ) : !widgets.length ? (
          <button type="button" disabled={!editing && !current?.editable}
            onClick={() => editing ? setEditor({ index: null }) : startEdit(current)}
            className="panel w-full min-h-[180px] flex flex-col items-center justify-center gap-2 border-dashed text-muted-foreground hover:text-foreground">
            <Plus size={22} aria-hidden="true" />
            <span className="text-sm font-medium">{editing || current?.editable ? 'Add your first visualization' : 'This dashboard has no panels yet'}</span>
          </button>
        ) : (
          <DashGrid className={`dash-grid ${editing ? 'dash-grid--editing' : ''}`} layout={layout}
            editing={editing} onLayout={onLayout}>
            {widgets.map((w, i) => (
              <div key={w.id}>
                <Panel w={w} scope={scope} editing={editing} onFilter={addFilter}
                  onEdit={() => setEditor({ index: i })}
                  onRemove={() => setWidgets(ws => ws.filter(x => x.id !== w.id))} />
              </div>
            ))}
          </DashGrid>
        )}

      {editor && editing && (
        <VizEditor initial={editor.index == null ? null : widgets[editor.index]} scope={scope} onClose={() => setEditor(null)}
          onSave={w => {
            setWidgets(ws => editor.index == null
              ? [...ws, { ...w, id: newId(), x: undefined, y: undefined }]
              : ws.map((x, j) => j === editor.index ? { ...x, ...w } : x))
            setEditor(null)
          }} />
      )}
    </div>
  )
}
