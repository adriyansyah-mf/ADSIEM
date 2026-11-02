import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import {
  AlertTriangle, Ban, Check, Copy, FileText, Globe, Loader2, Lock, Network, ShieldOff, ShieldX, Skull, Star,
} from 'lucide-react'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

interface TreeEvent {
  id: string
  kind: 'file' | 'network' | 'dns' | 'malware'
  time: string
  path?: string
  action?: string
  destination?: string
  port?: string
  direction?: string
  query?: string
  answers?: string
  label?: string
  sha256?: string
}

interface ProcessNode {
  id: string
  pid: string
  ppid: string
  image: string
  command_line: string
  parent_image: string
  user: string
  integrity: string
  sha256: string
  start: string | null
  parent_id: string | null
  depth: number
  anchor?: boolean
  synthetic?: boolean
  exited?: string
  exit_code?: string
  events?: TreeEvent[]
  counts?: Partial<Record<'file' | 'network' | 'dns' | 'malware', number>>
}

interface TreeAgent {
  id: string
  hostname: string
  status: string
  is_isolated: boolean
  version: string | null
}

interface Tree {
  anchor: string | null
  nodes: ProcessNode[]
  notes: string[]
  agent: TreeAgent | null
}

const base = (p: string) => p.split(/[\\/]/).pop() || p

function when(t?: string | null) {
  if (!t) return ''
  try { return format(new Date(t), 'MMM d HH:mm:ss') } catch { return t }
}

function apiError(e: unknown): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : 'Request failed'
}

/** A button that asks once more before it acts. */
function ConfirmButton({ icon, label, confirm, danger, disabled, onConfirm }: {
  icon: React.ReactNode; label: string; confirm: string; danger?: boolean; disabled?: boolean; onConfirm: () => void
}) {
  const [armed, setArmed] = useState(false)
  if (armed) {
    return (
      <div className="rounded border border-amber-700 bg-amber-900/20 p-2 text-xs space-y-2 w-full">
        <div className="flex gap-1.5"><AlertTriangle size={13} className="shrink-0 text-amber-400" /> {confirm}</div>
        <div className="flex gap-2 justify-end">
          <button onClick={() => setArmed(false)} className="px-2 py-1 rounded border border-border hover:bg-muted">Cancel</button>
          <button onClick={() => { setArmed(false); onConfirm() }}
            className={`px-2 py-1 rounded font-semibold ${danger ? 'bg-red-700 text-white' : 'bg-primary text-primary-foreground'}`}>
            {label}
          </button>
        </div>
      </div>
    )
  }
  return (
    <button onClick={() => setArmed(true)} disabled={disabled}
      className="flex items-center gap-1.5 rounded border border-border px-2.5 py-1.5 text-xs hover:bg-muted disabled:opacity-40">
      {icon} {label}
    </button>
  )
}

function Row({ n, selected, onSelect, indent, last }: {
  n: ProcessNode; selected: boolean; onSelect: () => void; indent: number; last: boolean
}) {
  const c = n.counts ?? {}
  return (
    <button onClick={onSelect}
      className={`flex w-full items-center gap-1.5 rounded px-2 py-1 text-left text-xs ${selected ? 'bg-primary/15 ring-1 ring-primary' : 'hover:bg-muted'}`}
      style={{ paddingLeft: 8 + indent * 18 }}>
      {indent > 0 && <span className="text-muted-foreground font-mono">{last ? '└' : '├'}</span>}
      {n.anchor ? <Star size={12} className="shrink-0 fill-amber-400 text-amber-400" />
        : <span className={`h-2 w-2 shrink-0 rounded-full ${n.synthetic ? 'border border-muted-foreground' : 'bg-muted-foreground'}`} />}
      <span className={`truncate font-medium ${n.synthetic ? 'text-muted-foreground' : ''}`}>{n.image ? base(n.image) : 'unknown'}</span>
      <span className="text-muted-foreground font-mono">{n.pid}</span>
      <span className="ml-auto flex shrink-0 items-center gap-1.5 text-muted-foreground">
        {!!c.malware && <span className="flex items-center gap-0.5 text-red-400"><ShieldX size={11} />{c.malware}</span>}
        {!!c.file && <span className="flex items-center gap-0.5"><FileText size={11} />{c.file}</span>}
        {!!c.network && <span className="flex items-center gap-0.5"><Network size={11} />{c.network}</span>}
        {!!c.dns && <span className="flex items-center gap-0.5"><Globe size={11} />{c.dns}</span>}
        {n.exited && <span title={`exited ${when(n.exited)}`}>✕</span>}
      </span>
    </button>
  )
}

function EventLine({ e }: { e: TreeEvent }) {
  const icon = e.kind === 'file' ? <FileText size={11} /> : e.kind === 'dns' ? <Globe size={11} />
    : e.kind === 'malware' ? <ShieldX size={11} className="text-red-400" /> : <Network size={11} />
  const text = e.kind === 'file' ? `${e.action || 'file'} ${e.path}`
    : e.kind === 'dns' ? `${e.query}${e.answers ? ` → ${e.answers}` : ''}`
      : e.kind === 'malware' ? `known malware ${e.label} (${e.action}) ${e.path ?? ''}`
        : `${e.direction === 'inbound' ? '←' : '→'} ${e.destination}${e.port ? `:${e.port}` : ''}`
  return (
    <div className="flex gap-2 text-xs">
      <span className="shrink-0 text-muted-foreground font-mono">{when(e.time).split(' ').pop()}</span>
      <span className="shrink-0 pt-0.5">{icon}</span>
      <span className="break-all font-mono">{text}</span>
    </div>
  )
}

function Details({ n, agent }: { n: ProcessNode; agent: TreeAgent | null }) {
  const qc = useQueryClient()
  const [copied, setCopied] = useState(false)
  const task = useMutation({
    mutationFn: (body: { task_type: string; params: Record<string, unknown> }) =>
      api.post('/api/tasks', { agent_id: agent!.id, ...body }).then(r => r.data),
    onSuccess: (_, v) => emitToast(`${v.task_type.replace('_', ' ')} sent to ${agent!.hostname}`, 'success'),
    onError: e => emitToast(apiError(e), 'error'),
  })
  const addHash = useMutation({
    mutationFn: () => api.post('/api/malware-hashes', { hashes: [n.sha256], label: base(n.image), reference: `${agent?.hostname ?? ''}:${n.image}` }),
    onSuccess: () => emitToast('Hash added: every agent now checks it', 'success'),
    onError: e => emitToast(apiError(e), 'error'),
  })
  const isolate = useMutation({
    mutationFn: () => api.post(`/api/agents/${agent!.id}/isolate`),
    onSuccess: () => { emitToast(`Isolation requested for ${agent!.hostname}`, 'success'); qc.invalidateQueries({ queryKey: ['process-tree'] }) },
    onError: e => emitToast(apiError(e), 'error'),
  })
  const real = !n.synthetic && !!n.pid
  const busy = task.isPending || addHash.isPending || isolate.isPending

  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-center gap-1.5 font-semibold break-all">
          {n.anchor && <Star size={13} className="shrink-0 fill-amber-400 text-amber-400" />}{n.image || 'unknown image'}
        </div>
        {n.command_line && <pre className="mt-1 whitespace-pre-wrap break-all rounded bg-muted p-2 text-xs">{n.command_line}</pre>}
      </div>
      <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 text-xs">
        <dt className="text-muted-foreground">PID</dt><dd className="font-mono">{n.pid || '?'}{n.ppid ? ` (parent ${n.ppid})` : ''}</dd>
        {n.user && <><dt className="text-muted-foreground">User</dt><dd className="font-mono">{n.user}{n.integrity ? ` · ${n.integrity}` : ''}</dd></>}
        {n.start && <><dt className="text-muted-foreground">Started</dt><dd>{when(n.start)}</dd></>}
        {n.exited && <><dt className="text-muted-foreground">Exited</dt><dd>{when(n.exited)}{n.exit_code ? ` (code ${n.exit_code})` : ''}</dd></>}
        {n.sha256 && <>
          <dt className="text-muted-foreground">SHA-256</dt>
          <dd><button onClick={() => { navigator.clipboard?.writeText(n.sha256); setCopied(true); setTimeout(() => setCopied(false), 1200) }}
            className="inline-flex items-center gap-1 font-mono break-all text-left hover:underline">{n.sha256}
            {copied ? <Check size={11} className="text-primary" /> : <Copy size={11} className="opacity-50" />}</button></dd>
        </>}
      </dl>
      {n.synthetic && (
        <p className="text-xs text-muted-foreground">No process start was recorded for this one; it is shown from what its child or the alert says.</p>
      )}

      {agent && (
        <div className="space-y-2 border-t border-border pt-3">
          <div className="text-xs font-semibold text-muted-foreground">Respond on {agent.hostname}</div>
          <div className="flex flex-wrap gap-2">
            <ConfirmButton icon={<Skull size={13} />} label="Kill process" danger disabled={!real || !!n.exited || busy}
              confirm={`Kill PID ${n.pid} on ${agent.hostname}? The agent kills whatever process has this PID now; if ${base(n.image)} already exited, the PID may belong to something else.`}
              onConfirm={() => task.mutate({ task_type: 'kill_process', params: { pid: Number(n.pid) } })} />
            <ConfirmButton icon={<Lock size={13} />} label="Quarantine file" disabled={!n.image || busy}
              confirm={`Lock ${n.image} on ${agent.hostname} so it cannot be read or run? Restore it from the agent's tasks with restore_file.`}
              onConfirm={() => task.mutate({ task_type: 'quarantine_file', params: { path: n.image } })} />
            <ConfirmButton icon={<Ban size={13} />} label="Known malware" disabled={!n.sha256 || busy}
              confirm="Add this SHA-256 to Malware hashes? Every agent then detects it, or blocks it if the action is block."
              onConfirm={() => addHash.mutate()} />
            {agent.is_isolated ? (
              <span className="flex items-center gap-1.5 rounded border border-red-800 px-2.5 py-1.5 text-xs text-red-300"><ShieldOff size={13} /> Host isolated</span>
            ) : (
              <ConfirmButton icon={<ShieldOff size={13} />} label="Isolate host" danger disabled={busy}
                confirm={`Cut ${agent.hostname} off the network except the SIEM server? Users and services on it lose connectivity until you lift isolation on the Agents page.`}
                onConfirm={() => isolate.mutate()} />
            )}
          </div>
          {!n.sha256 && <p className="text-xs text-muted-foreground">No SHA-256 for this process (only Sysmon and known-malware events carry one).</p>}
        </div>
      )}

      {(n.events?.length ?? 0) > 0 && (
        <div className="space-y-1 border-t border-border pt-3">
          <div className="text-xs font-semibold text-muted-foreground">Activity</div>
          {n.events!.map(e => <EventLine key={e.id} e={e} />)}
        </div>
      )}
    </div>
  )
}

export default function ProcessTree({ alertId }: { alertId: string }) {
  const { data, isLoading, error } = useQuery<Tree>({
    queryKey: ['process-tree', alertId],
    queryFn: () => api.get(`/api/alerts/${alertId}/process-tree`).then(r => r.data),
  })
  const [selected, setSelected] = useState<string | null>(null)

  const rows = useMemo(() => {
    if (!data) return []
    const kids = new Map<string | null, ProcessNode[]>()
    for (const n of data.nodes) {
      const list = kids.get(n.parent_id) ?? []
      list.push(n)
      kids.set(n.parent_id, list)
    }
    const out: { n: ProcessNode; indent: number; last: boolean }[] = []
    const walk = (n: ProcessNode, indent: number, last: boolean) => {
      out.push({ n, indent, last })
      const cs = kids.get(n.id) ?? []
      cs.forEach((c, i) => walk(c, indent + 1, i === cs.length - 1))
    }
    const roots = kids.get(null) ?? []
    roots.forEach((r, i) => walk(r, 0, i === roots.length - 1))
    return out
  }, [data])

  if (isLoading) return <div className="p-4"><Loader2 size={16} className="animate-spin" /></div>
  if (error || !data) return <p className="p-4 text-sm text-destructive">Could not load the process tree.</p>
  if (data.nodes.length === 0) {
    return <p className="p-4 text-sm text-muted-foreground">{data.notes[0] ?? 'No process to show.'}</p>
  }
  const current = data.nodes.find(n => n.id === (selected ?? data.anchor)) ?? data.nodes[0]

  return (
    <div className="space-y-3 p-4">
      {data.notes.map(t => <p key={t} className="text-xs text-muted-foreground">{t}</p>)}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="space-y-0.5 rounded-lg border border-border p-2">
          {rows.map(({ n, indent, last }) => (
            <Row key={n.id} n={n} indent={indent} last={last} selected={n.id === current.id} onSelect={() => setSelected(n.id)} />
          ))}
        </div>
        <div className="rounded-lg border border-border p-3">
          <Details key={current.id} n={current} agent={data.agent} />
        </div>
      </div>
    </div>
  )
}
