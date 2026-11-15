import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { useSavedSearches } from '@/components/SavedSearchBar'
import {
  DECODED_FIELDS, INDEX_FIELDS, TIME_WINDOWS, VIZ, VizBody, apiError, normalize, useWidgetData,
} from './viz'
import type { Chart, Scope, Viz, Widget } from './viz'

// Create or change one visualization, with a live preview under the dashboard's
// current time range, query bar and filters (like Wazuh's visualization editor).

function useDebounced<T>(value: T, ms = 400): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

const EXAMPLES: Record<'logs' | 'events', string> = {
  logs: 'e.g. "Failed password" AND log_type:linux_auth',
  events: 'e.g. event.outcome:failure AND user.name:admin*',
}

export default function VizEditor({ initial, scope, onSave, onClose }: {
  readonly initial: Widget | null
  readonly scope: Scope
  readonly onSave: (w: Widget) => void
  readonly onClose: () => void
}) {
  const searches = useSavedSearches()
  const [w, setW] = useState<Widget>(() => normalize(initial ?? {}))
  const [source, setSource] = useState<'query' | 'search'>(initial?.search_id ? 'search' : 'query')
  const set = (patch: Partial<Widget>) => setW(prev => ({ ...prev, ...patch }))
  const spec = VIZ[w.viz]

  const live = useDebounced({ ...w, search_id: source === 'search' ? w.search_id : null })
  const ready = source === 'query' || !!live.search_id
  const preview = useWidgetData(live, scope, ready)
  const searchName = searches.data?.find(s => s.id === w.search_id)?.name

  const pickViz = (viz: Viz) => {
    const next = VIZ[viz]
    // a resize only when the type changes size class, so a placed panel keeps its spot
    set({ viz, w: initial?.viz === viz ? w.w : next.w, h: initial?.viz === viz ? w.h : next.h,
      limit: viz === 'split' ? Math.min(w.limit, 8) : w.limit })
  }

  const save = () => {
    const out: Widget = { ...w, search_id: source === 'search' ? w.search_id : null }
    if (source === 'search') { out.query = ''; out.kind = 'logs' }
    if (!out.title.trim()) out.title = defaultTitle(out, searchName)
    onSave(out)
  }

  return (
    <WorkspaceDialog title={initial ? 'Edit visualization' : 'New visualization'} wide onClose={onClose}
      description="Pick a type, say which events it counts, and check the preview.">
      <div className="viz-editor">
        <div className="space-y-4 min-w-0">
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Type</legend>
            <div className="viz-types" role="radiogroup" aria-label="Visualization type">
              {(Object.keys(VIZ) as Viz[]).map(v => {
                const { icon: Icon, label, hint } = VIZ[v]
                return (
                  <button key={v} type="button" role="radio" aria-checked={w.viz === v} title={hint}
                    className={`viz-type ${w.viz === v ? 'viz-type--on' : ''}`} onClick={() => pickViz(v)}>
                    <Icon size={18} aria-hidden="true" /><span>{label}</span>
                  </button>
                )
              })}
            </div>
            <p className="text-xs text-muted-foreground">{spec.hint}.</p>
          </fieldset>

          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Data</legend>
            <div className="control-cluster text-sm">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="radio" name="viz-source" checked={source === 'query'} onChange={() => setSource('query')} /> A query
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="radio" name="viz-source" checked={source === 'search'} onChange={() => setSource('search')} /> A saved search
              </label>
            </div>
            {source === 'query' ? (
              <div className="grid grid-cols-[auto_minmax(0,1fr)] gap-2">
                <select className="ui-input w-auto" aria-label="Index" value={w.kind} onChange={e => set({ kind: e.target.value as 'logs' | 'events' })}>
                  <option value="logs">Logs</option><option value="events">Events</option>
                </select>
                <input className="ui-input font-mono text-xs" aria-label="Query (Lucene)" value={w.query} maxLength={512}
                  placeholder={EXAMPLES[w.kind]} onChange={e => set({ query: e.target.value })} />
                <p className="col-span-2 text-xs text-muted-foreground">Lucene, like Log search. Leave it empty to count every event.</p>
              </div>
            ) : searches.data && !searches.data.length ? (
              <p className="text-xs text-muted-foreground">No saved searches yet: save one from Log search or Events, or use a query.</p>
            ) : (
              <select className="ui-input" aria-label="Saved search" value={w.search_id ?? ''} onChange={e => set({ search_id: e.target.value || null })}>
                <option value="">Choose a saved search…</option>
                {(searches.data ?? []).map(s => <option key={s.id} value={s.id}>{s.name}{s.shared ? ' (team)' : ''}</option>)}
              </select>
            )}
          </fieldset>

          <fieldset className="grid grid-cols-2 gap-3">
            <legend className="text-sm font-medium mb-2">Options</legend>
            {spec.field && (
              <label className="field col-span-2 sm:col-span-1"><span>Field</span>
                <select className="ui-input" value={w.field} onChange={e => set({ field: e.target.value })}>
                  <optgroup label="Index fields">{INDEX_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}</optgroup>
                  <optgroup label="Decoded fields">{DECODED_FIELDS.map(f => <option key={f} value={f}>{f}</option>)}</optgroup>
                </select></label>
            )}
            {spec.size && (
              <label className="field"><span>{w.viz === 'split' ? 'Series' : 'Values'}</span>
                <select className="ui-input" value={w.limit} onChange={e => set({ limit: Number(e.target.value) })}>
                  {(w.viz === 'split' ? [3, 5, 8] : [5, 10, 15, 20, 30, 50]).map(n => <option key={n} value={n}>{n}</option>)}
                </select></label>
            )}
            {(w.viz === 'timeline' || w.viz === 'split') && (
              <label className="field"><span>Chart</span>
                <select className="ui-input" value={w.chart} onChange={e => set({ chart: e.target.value as Chart })}>
                  <option value="area">Area</option><option value="line">Line</option><option value="bar">Bar</option>
                </select></label>
            )}
            <label className="field"><span>Own time range</span>
              <select className="ui-input" value={w.hours} onChange={e => set({ hours: Number(e.target.value) })}>
                {TIME_WINDOWS.map(([h, l]) => <option key={h} value={h}>{l}</option>)}
              </select></label>
            <label className="field col-span-2"><span>Title</span>
              <input className="ui-input" value={w.title} maxLength={120} placeholder={defaultTitle(w, searchName)}
                onChange={e => set({ title: e.target.value })} /></label>
            <p className="col-span-2 text-xs text-muted-foreground">
              The own time range applies when the dashboard's time picker is set to "Each panel's own".
            </p>
          </fieldset>
        </div>

        <div className="viz-preview min-w-0">
          <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>Preview{preview.data ? ` · ${preview.data.total.toLocaleString()} events` : ''}</span>
            {preview.isFetching && <Loader2 size={12} className="animate-spin" />}
          </div>
          <div className="viz-preview__body">
            {!ready ? <p className="text-xs text-muted-foreground">Choose a saved search to see a preview.</p>
              : preview.isError ? <p className="text-xs text-destructive">{apiError(preview.error, 'This visualization could not run.')}</p>
              : preview.data ? <VizBody w={live} r={preview.data} />
              : <Loader2 size={16} className="animate-spin" />}
          </div>
        </div>
      </div>
      <div className="control-cluster justify-end pt-4">
        <button type="button" className="ui-button ui-button--quiet" onClick={onClose}>Cancel</button>
        <button type="button" className="ui-button ui-button--primary" disabled={source === 'search' && !w.search_id} onClick={save}>
          {initial ? 'Update panel' : 'Add to dashboard'}
        </button>
      </div>
    </WorkspaceDialog>
  )
}

export function defaultTitle(w: Widget, searchName?: string): string {
  const what = searchName ?? (w.query.trim() ? w.query.trim().slice(0, 40) : w.kind === 'events' ? 'All events' : 'All logs')
  const spec = VIZ[w.viz]
  return spec.field ? `${spec.label}: ${w.field} · ${what}` : `${spec.label} · ${what}`
}
