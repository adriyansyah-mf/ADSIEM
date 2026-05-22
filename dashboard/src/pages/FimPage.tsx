import { useState } from 'react'
import { format } from 'date-fns'
import { ShieldAlert, FilePlus, FilePen, FileX, RefreshCw, Plus, Trash2, ToggleLeft, ToggleRight } from 'lucide-react'
import { useFimEvents, useFimPaths, useAddFimPath, useToggleFimPath, useDeleteFimPath } from '@/hooks/useFim'
import type { FimEvent, FimWatchPath } from '@/types'

const TYPE_META = {
  CREATE: { label: 'CREATE', color: 'text-emerald-400', bg: 'bg-emerald-900/30 border-emerald-700' },
  MODIFY: { label: 'MODIFY', color: 'text-yellow-400', bg: 'bg-yellow-900/30 border-yellow-700' },
  DELETE: { label: 'DELETE', color: 'text-red-400',    bg: 'bg-red-900/30 border-red-700' },
  RENAME: { label: 'RENAME', color: 'text-blue-400',   bg: 'bg-blue-900/30 border-blue-700' },
} as const

function TypeBadge({ type }: { type: string }) {
  const m = TYPE_META[type as keyof typeof TYPE_META] ?? { label: type, color: 'text-muted-foreground', bg: 'bg-muted/30 border-border' }
  return (
    <span className={`inline-block text-xs font-mono px-2 py-0.5 rounded border ${m.bg} ${m.color}`}>
      {m.label}
    </span>
  )
}

function WatchPathsPanel() {
  const { data: paths = [] } = useFimPaths()
  const addPath = useAddFimPath()
  const togglePath = useToggleFimPath()
  const deletePath = useDeleteFimPath()
  const [newPath, setNewPath] = useState('')

  const handleAdd = () => {
    const p = newPath.trim()
    if (!p) return
    addPath.mutate(p, { onSuccess: () => setNewPath('') })
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">Watch Paths</h2>
        <span className="text-xs text-muted-foreground">Agents update on next heartbeat (~30s)</span>
      </div>

      <div className="flex gap-2">
        <input
          value={newPath}
          onChange={e => setNewPath(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
          placeholder="/path/to/watch"
          className="flex-1 bg-muted border border-border rounded px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
        />
        <button
          onClick={handleAdd}
          disabled={addPath.isPending || !newPath.trim()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-xs font-medium disabled:opacity-50"
        >
          <Plus size={12} /> Add
        </button>
      </div>

      <div className="space-y-1">
        {paths.map(p => <WatchPathRow key={p.id} path={p} onToggle={() => togglePath.mutate(p.id)} onDelete={() => deletePath.mutate(p.id)} />)}
        {paths.length === 0 && <p className="text-xs text-muted-foreground py-2">No paths configured.</p>}
      </div>
    </div>
  )
}

function WatchPathRow({ path, onToggle, onDelete }: { path: FimWatchPath; onToggle: () => void; onDelete: () => void }) {
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded border text-sm ${path.is_enabled ? 'border-border bg-muted/20' : 'border-border/40 bg-muted/5 opacity-60'}`}>
      <span className="flex-1 font-mono text-xs">{path.path}</span>
      <button onClick={onToggle} className="text-muted-foreground hover:text-foreground transition-colors" title={path.is_enabled ? 'Disable' : 'Enable'}>
        {path.is_enabled ? <ToggleRight size={16} className="text-emerald-400" /> : <ToggleLeft size={16} />}
      </button>
      <button onClick={onDelete} className="text-muted-foreground hover:text-destructive transition-colors" title="Remove">
        <Trash2 size={14} />
      </button>
    </div>
  )
}

export default function FimPage() {
  const [filterType, setFilterType] = useState<string>('')
  const [search, setSearch] = useState('')

  const { data = [], isLoading, refetch, isFetching } = useFimEvents(
    filterType ? { event_type: filterType } : undefined
  )

  const filtered = search
    ? data.filter(e => e.path.toLowerCase().includes(search.toLowerCase()))
    : data

  const counts = data.reduce<Record<string, number>>((acc, e) => {
    acc[e.event_type] = (acc[e.event_type] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold flex items-center gap-2">
          <ShieldAlert size={20} />
          File Integrity Monitoring
        </h1>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-muted hover:bg-muted/80 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      <WatchPathsPanel />

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {(['CREATE', 'MODIFY', 'DELETE', 'RENAME'] as const).map(t => {
          const m = TYPE_META[t]
          const icons = { CREATE: FilePlus, MODIFY: FilePen, DELETE: FileX, RENAME: RefreshCw }
          const Icon = icons[t]
          return (
            <button
              key={t}
              onClick={() => setFilterType(filterType === t ? '' : t)}
              className={`rounded-lg border p-4 text-left transition-all ${filterType === t ? m.bg + ' ' + m.color : 'bg-card border-border hover:bg-muted/50'}`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium">{t}</span>
                <Icon size={14} />
              </div>
              <div className="text-2xl font-bold">{counts[t] ?? 0}</div>
            </button>
          )
        })}
      </div>

      {/* Search */}
      <div className="flex gap-3">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by path…"
          className="flex-1 bg-muted border border-border rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
        />
        {filterType && (
          <button onClick={() => setFilterType('')} className="text-xs px-3 py-1.5 rounded bg-muted hover:bg-muted/80 border border-border">
            Clear: {filterType}
          </button>
        )}
      </div>

      {/* Event table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 text-xs text-muted-foreground uppercase">
            <tr>
              <th className="px-4 py-2 text-left">Time</th>
              <th className="px-4 py-2 text-left">Type</th>
              <th className="px-4 py-2 text-left">Path</th>
              <th className="px-4 py-2 text-left">SHA-256</th>
              <th className="px-4 py-2 text-right">Size</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">Loading…</td></tr>}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">No FIM events yet.</td></tr>
            )}
            {filtered.map(ev => <FimRow key={ev.id} ev={ev} />)}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-muted-foreground">
        Showing {filtered.length} events · Refreshes every 15s
      </p>
    </div>
  )
}

function FimRow({ ev }: { ev: FimEvent }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <>
      <tr className="border-t border-border hover:bg-muted/30 cursor-pointer transition-colors" onClick={() => setExpanded(x => !x)}>
        <td className="px-4 py-2 font-mono text-xs text-muted-foreground whitespace-nowrap">
          {format(new Date(ev.detected_at), 'MM-dd HH:mm:ss')}
        </td>
        <td className="px-4 py-2"><TypeBadge type={ev.event_type} /></td>
        <td className="px-4 py-2 font-mono text-xs max-w-sm truncate">{ev.path}</td>
        <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
          {ev.sha256 ? ev.sha256.slice(0, 16) + '…' : '—'}
        </td>
        <td className="px-4 py-2 text-right text-xs text-muted-foreground">
          {ev.size_bytes != null ? formatBytes(ev.size_bytes) : '—'}
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-border bg-muted/20">
          <td colSpan={5} className="px-6 py-3">
            <div className="grid grid-cols-2 gap-4 text-xs">
              <div><span className="text-muted-foreground">Full path: </span><span className="font-mono">{ev.path}</span></div>
              {ev.sha256 && <div><span className="text-muted-foreground">SHA-256: </span><span className="font-mono break-all">{ev.sha256}</span></div>}
              <div><span className="text-muted-foreground">Agent ID: </span><span className="font-mono">{ev.agent_id}</span></div>
              <div><span className="text-muted-foreground">Detected: </span><span>{format(new Date(ev.detected_at), 'yyyy-MM-dd HH:mm:ss')}</span></div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}
