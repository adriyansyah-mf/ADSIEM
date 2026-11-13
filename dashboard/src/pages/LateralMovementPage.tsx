import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { api } from '@/api/client'
import DataTable, { type Column } from '@/components/DataTable'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'

interface GraphNode { id: string; agent: boolean; status: string | null; out: number; in: number }
interface GraphEdge {
  group_id: string; src: string; dst: string; protocol: string; users: string[]; count: number
  new: boolean; first_seen: string; last_seen: string
}
interface Graph { hours: number; truncated: boolean; nodes: GraphNode[]; edges: GraphEdge[] }
type EdgeRow = GraphEdge & { readonly id: string }

const PROTOCOL_COLOR: Record<string, string> = {
  ssh: '#0ea5e9', rdp: '#a855f7', smb: '#f59e0b', winrm: '#10b981', rpc: '#64748b', logon: '#6366f1',
}
const NEW_COLOR = '#ef4444'
const SIZE = 640

function layout(nodes: GraphNode[]): Map<string, { x: number; y: number }> {
  // busiest hosts first around the circle, so hubs sit apart and labels stay readable
  const sorted = [...nodes].sort((a, b) => (b.in + b.out) - (a.in + a.out) || a.id.localeCompare(b.id))
  const r = SIZE / 2 - 70
  const out = new Map<string, { x: number; y: number }>()
  sorted.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / Math.max(sorted.length, 1) - Math.PI / 2
    out.set(n.id, { x: SIZE / 2 + r * Math.cos(angle), y: SIZE / 2 + r * Math.sin(angle) })
  })
  return out
}

function GraphView({ graph, focus, onFocus }: { readonly graph: Graph; readonly focus: string; readonly onFocus: (h: string) => void }) {
  const pos = useMemo(() => layout(graph.nodes), [graph.nodes])
  if (!graph.nodes.length) return <p className="text-sm text-muted-foreground">No lateral paths seen in this window.</p>
  return <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full max-w-[720px] mx-auto" role="img"
    aria-label="Lateral movement graph: hosts as circles, paths as arrows">
    <defs>{[...Object.entries(PROTOCOL_COLOR), ['new', NEW_COLOR]].map(([k, c]) =>
      <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX="18" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" fill={c} /></marker>)}</defs>
    {graph.edges.map(e => {
      const a = pos.get(e.src), b = pos.get(e.dst)
      if (!a || !b) return null
      const dim = focus && e.src !== focus && e.dst !== focus
      const color = e.new ? NEW_COLOR : PROTOCOL_COLOR[e.protocol] ?? '#94a3b8'
      return <line key={`${e.group_id}|${e.src}|${e.dst}|${e.protocol}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
        stroke={color} strokeWidth={e.new ? 2.5 : 1.5} strokeDasharray={e.new ? '6 3' : undefined}
        opacity={dim ? 0.12 : 0.85} markerEnd={`url(#arrow-${e.new ? 'new' : e.protocol in PROTOCOL_COLOR ? e.protocol : 'rpc'})`}>
        <title>{`${e.src} → ${e.dst} · ${e.protocol}${e.users.length ? ` · ${e.users.join(', ')}` : ''} · ${e.count}×${e.new ? ' · NEW' : ''}`}</title>
      </line>
    })}
    {graph.nodes.map(n => {
      const p = pos.get(n.id)!
      const radius = 6 + Math.min(10, Math.sqrt(n.in + n.out) * 2)
      const dim = focus && focus !== n.id && !graph.edges.some(e => (e.src === focus && e.dst === n.id) || (e.dst === focus && e.src === n.id))
      return <g key={n.id} opacity={dim ? 0.25 : 1} className="cursor-pointer" onClick={() => onFocus(focus === n.id ? '' : n.id)}>
        <circle cx={p.x} cy={p.y} r={radius} fill={n.agent ? 'var(--accent-cyan, #06b6d4)' : 'var(--muted, #cbd5e1)'}
          stroke={focus === n.id ? NEW_COLOR : 'var(--border-default, #475569)'} strokeWidth={focus === n.id ? 3 : 1} />
        <text x={p.x} y={p.y + radius + 12} textAnchor="middle" fontSize="11" fill="currentColor">{n.id}</text>
        <title>{`${n.id}${n.agent ? ' (agent)' : ' (address, no agent)'} · ${n.out} out · ${n.in} in`}</title>
      </g>
    })}
  </svg>
}

export default function LateralMovementPage() {
  const [hours, setHours] = useState(24)
  const [newOnly, setNewOnly] = useState(false)
  const [focus, setFocus] = useState('')
  const query = useQuery<Graph>({
    queryKey: ['lateral', hours, newOnly],
    queryFn: () => api.get('/api/lateral/graph', { params: { hours, new_only: newOnly } }).then(r => r.data),
    refetchInterval: 60_000,
  })
  const rows: EdgeRow[] = (query.data?.edges ?? [])
    .filter(e => !focus || e.src === focus || e.dst === focus)
    .map(e => ({ ...e, id: `${e.group_id}|${e.src}|${e.dst}|${e.protocol}` }))
  const columns: readonly Column<EdgeRow>[] = [
    { key: 'path', header: 'Path', render: r => <span className="font-mono text-xs">{r.src} → {r.dst}</span>, exportValue: r => `${r.src} -> ${r.dst}` },
    { key: 'protocol', header: 'How', render: r => <span className="uppercase text-xs font-medium" style={{ color: PROTOCOL_COLOR[r.protocol] }}>{r.protocol}</span> },
    { key: 'users', header: 'Users', render: r => <span className="text-xs">{r.users.join(', ') || '—'}</span>, exportValue: r => r.users.join(' ') },
    { key: 'new', header: 'New', render: r => r.new ? <span className="text-xs font-semibold" style={{ color: NEW_COLOR }}>new</span> : '', exportValue: r => String(r.new) },
    { key: 'count', header: 'Seen', render: r => <span className="tabular-nums">{r.count}</span> },
    { key: 'first_seen', header: 'First seen', render: r => <span className="text-xs whitespace-nowrap">{formatDistanceToNow(new Date(r.first_seen), { addSuffix: true })}</span> },
    { key: 'last_seen', header: 'Last seen', render: r => <span className="text-xs whitespace-nowrap">{formatDistanceToNow(new Date(r.last_seen), { addSuffix: true })}</span> },
    { key: 'group_id', header: 'Group', hiddenByDefault: true, render: r => r.group_id },
  ]
  return <div className="workspace">
    <PageHeader eyebrow="Behavior intelligence" title="Lateral movement"
      description="Which host reaches which, how and as whom: remote logins (SSH, Windows network logon, RDP) and connections to remote-administration ports. Paths first seen in the window are red."
      actions={<button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh</button>} />
    <section className="panel" aria-label="Filters"><div className="ueba-filters">
      <label className="field"><span>Window</span><select className="ui-input" value={hours} onChange={e => setHours(Number(e.target.value))}>
        <option value={1}>Last hour</option><option value={24}>Last 24 hours</option><option value={168}>Last 7 days</option><option value={720}>Last 30 days</option></select></label>
      <label className="field"><span>Paths</span><select className="ui-input" value={newOnly ? 'new' : 'all'} onChange={e => setNewOnly(e.target.value === 'new')}>
        <option value="all">All paths</option><option value="new">New paths only</option></select></label>
      {focus && <button className="ui-button self-end" onClick={() => setFocus('')}>Clear focus: {focus}</button>}
    </div>
    <div className="filter-footer"><span>Click a host to focus on its paths ·{' '}
      {Object.entries(PROTOCOL_COLOR).map(([p, c]) => <span key={p} className="mr-2 uppercase" style={{ color: c }}>{p}</span>)}
      <span style={{ color: NEW_COLOR }}>NEW</span>{query.data?.truncated && ' · showing the 1000 most recent paths'}</span></div></section>
    {query.isPending ? <section className="panel"><QueryState kind="loading" title="Loading the graph…" /></section>
      : query.isError ? <section className="panel"><QueryState kind="error" title="Could not load lateral movement" onRetry={() => { void query.refetch() }} /></section>
        : <>
          <section aria-label="Graph"><Panel title="Graph" description={`${query.data.nodes.length} hosts · ${query.data.edges.length} paths`}>
            <GraphView graph={query.data} focus={focus} onFocus={setFocus} /></Panel></section>
          <DataTable columns={columns} data={rows} total={rows.length} page={1} pageSize={rows.length || 1} onPageChange={() => {}}
            showPagination={false} exportFilename="lateral-paths.csv" emptyTitle="No paths" emptyDescription="Remote logins and remote-administration connections between hosts appear here." />
        </>}
  </div>
}
