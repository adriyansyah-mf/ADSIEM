import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bookmark, Save, X } from 'lucide-react'
import { api } from '@/api/client'

// Load and save Log search / Events queries (server-api/app/api/routes/saved_searches.py).

export interface SavedSearch {
  id: string
  name: string
  kind: 'logs' | 'events'
  query: string
  filter_tree: Record<string, unknown> | null
  log_type: string | null
  shared: boolean
  mine: boolean
  editable: boolean
}

export function useSavedSearches(kind?: 'logs' | 'events') {
  return useQuery<SavedSearch[]>({
    queryKey: ['saved-searches', kind ?? 'all'],
    queryFn: () => api.get('/api/saved-searches', { params: { kind } }).then(r => r.data),
  })
}

function apiError(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

export default function SavedSearchBar({ kind, query, filterTree, onLoad }: {
  readonly kind: 'logs' | 'events'
  readonly query: string
  readonly filterTree?: string
  readonly onLoad: (s: SavedSearch) => void
}) {
  const qc = useQueryClient()
  const saved = useSavedSearches(kind)
  const [saving, setSaving] = useState(false)
  const [name, setName] = useState('')
  const [shared, setShared] = useState(false)
  const [justSaved, setJustSaved] = useState('')
  const save = useMutation({
    mutationFn: () => api.post('/api/saved-searches', {
      name: name.trim(), kind, query, shared, filter_tree: filterTree ? JSON.parse(filterTree) : null,
    }),
    onSuccess: () => { setJustSaved(name.trim()); setSaving(false); setName(''); setShared(false); void qc.invalidateQueries({ queryKey: ['saved-searches'] }) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/saved-searches/${id}`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['saved-searches'] }) },
  })
  const [selected, setSelected] = useState('')
  const current = (saved.data ?? []).find(s => s.id === selected)
  const empty = !query.trim() && !filterTree

  return (
    <div className="control-cluster flex-wrap">
      <label className="flex items-center gap-1.5 text-sm">
        <Bookmark size={14} aria-hidden="true" />
        <span className="sr-only">Saved searches</span>
        <select className="ui-input w-auto" aria-label="Saved searches" value={selected}
          onChange={e => {
            setSelected(e.target.value)
            const s = (saved.data ?? []).find(x => x.id === e.target.value)
            if (s) onLoad(s)
          }}>
          <option value="">{saved.data?.length ? 'Saved searches…' : 'No saved searches yet'}</option>
          {(saved.data ?? []).map(s => (
            <option key={s.id} value={s.id}>{s.name}{s.shared ? ' (team)' : ''}</option>
          ))}
        </select>
      </label>
      {current?.editable && (
        <button type="button" className="ui-button ui-button--quiet" disabled={remove.isPending}
          onClick={() => { remove.mutate(current.id); setSelected('') }} aria-label={`Delete saved search ${current.name}`}>
          <X size={14} /> Delete
        </button>
      )}
      {!saving ? (
        <button type="button" className="ui-button" disabled={empty} title={empty ? 'Type a query or apply filters first' : undefined}
          onClick={() => { setSaving(true); setJustSaved('') }}><Save size={14} /> Save search</button>
      ) : (
        <form className="control-cluster flex-wrap" onSubmit={e => { e.preventDefault(); if (name.trim()) save.mutate() }}>
          <input className="ui-input w-56" autoFocus placeholder="Name, e.g. SSH failures on web servers" value={name}
            onChange={e => setName(e.target.value)} aria-label="Saved search name" maxLength={120} />
          <label className="flex items-center gap-1.5 text-sm cursor-pointer">
            <input type="checkbox" checked={shared} onChange={e => setShared(e.target.checked)} /> Share with my team
          </label>
          <button className="ui-button ui-button--primary" disabled={!name.trim() || save.isPending}>Save</button>
          <button type="button" className="ui-button ui-button--quiet" onClick={() => setSaving(false)}>Cancel</button>
        </form>
      )}
      {justSaved && !saving && (
        <span className="text-xs">
          Saved “{justSaved}”. <Link className="underline" to="/dashboards">Add it to a dashboard →</Link>
        </span>
      )}
      {(save.isError || remove.isError) && (
        <span role="alert" className="text-destructive text-xs">
          {apiError(save.error ?? remove.error, 'Could not save the search.')}
        </span>
      )}
    </div>
  )
}
