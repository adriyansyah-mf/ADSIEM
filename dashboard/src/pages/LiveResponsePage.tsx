import { useEffect, useMemo, useState } from 'react'
import { format, formatDistanceStrict } from 'date-fns'
import {
  Terminal, Play, Loader2, CheckCircle, XCircle, Clock, Ban, Download, FileCode, Plus, Pencil, Trash2,
  ChevronDown, ChevronRight, Filter,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import YamlEditor from '@/components/YamlEditor'
import LegacyTasks from '@/components/LegacyTasks'
import {
  useFlowArtifacts, useSaveFlowArtifact, useDeleteFlowArtifact, useFlows, useFlow, useFlowResults,
  useFlowLogs, useCreateFlow, useCancelFlow, downloadFlowResults,
} from '@/hooks/useFlows'
import type { Agent, Flow, FlowArtifact, FlowStatus } from '@/types'

type Tab = 'collect' | 'artifacts' | 'legacy'

const ACTIVE: FlowStatus[] = ['scheduled', 'running']

const NEW_ARTIFACT_TEMPLATE = `name: Custom.Linux.Example
description: Describe what this collects and why.
parameters:
  - name: PathPrefix
    default: /tmp/
sources:
  - name: Processes
    plugin: pslist          # info, pslist, netstat, users, glob, hash, read_file, persistence, dmesg, open_files, yara
    detection:              # optional Sigma filter applied to the rows on the server
      selection:
        Exe|startswith: "{{PathPrefix}}"
      condition: selection
    fields: [Pid, Name, Exe, CommandLine, Username]   # optional column projection
resources:
  timeout: 600
  max_rows: 10000
`

function StatusPill({ status }: { status: FlowStatus }) {
  const styles: Record<FlowStatus, string> = {
    scheduled: 'text-muted-foreground border-border',
    running: 'text-blue-400 border-blue-400/40',
    finished: 'text-emerald-400 border-emerald-400/40',
    error: 'text-red-400 border-red-400/40',
    cancelled: 'text-yellow-400 border-yellow-400/40',
  }
  const icon = {
    scheduled: <Clock size={11} />,
    running: <Loader2 size={11} className="animate-spin" />,
    finished: <CheckCircle size={11} />,
    error: <XCircle size={11} />,
    cancelled: <Ban size={11} />,
  }[status]
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${styles[status]}`}>
      {icon}{status}
    </span>
  )
}

function duration(f: Flow): string {
  if (!f.started_at) return '—'
  const end = f.completed_at ? new Date(f.completed_at) : new Date()
  return formatDistanceStrict(end, new Date(f.started_at))
}

function Cell({ value }: { value: unknown }) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">—</span>
  if (typeof value === 'object') {
    const text = JSON.stringify(value)
    return <span title={text}>{text.length > 120 ? text.slice(0, 120) + '…' : text}</span>
  }
  const text = String(value)
  return <span title={text.length > 120 ? text : undefined}>{text.length > 120 ? text.slice(0, 120) + '…' : text}</span>
}

function saveBase64(name: string, data: string) {
  const bin = atob(data)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const url = URL.createObjectURL(new Blob([bytes]))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}

// ─── Flow detail ─────────────────────────────────────────────────

function FlowResultsView({ flowId, sources, active }: { flowId: string; sources: Array<{ name: string; rows: number }>; active: boolean }) {
  const [source, setSource] = useState<string | undefined>(sources[0]?.name)
  const [offset, setOffset] = useState(0)
  useEffect(() => { setSource(sources[0]?.name); setOffset(0) }, [flowId]) // eslint-disable-line react-hooks/exhaustive-deps
  const { data, isLoading } = useFlowResults(flowId, source, offset, active)
  const columns = data?.columns ?? []
  const hasFileData = columns.includes('Data') && columns.includes('Encoding')

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {sources.map(s => (
          <button key={s.name} onClick={() => { setSource(s.name); setOffset(0) }}
            className={`rounded border px-2 py-1 text-xs font-mono ${s.name === source ? 'border-primary text-primary' : 'border-border text-muted-foreground hover:text-foreground'}`}>
            {s.name} <span className="opacity-70">({s.rows})</span>
          </button>
        ))}
        {source && (
          <div className="ml-auto flex gap-2">
            {(['csv', 'json'] as const).map(fmt => (
              <button key={fmt} onClick={() => downloadFlowResults(flowId, source, fmt)}
                className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs hover:border-primary hover:text-primary">
                <Download size={11} /> {fmt.toUpperCase()}
              </button>
            ))}
          </div>
        )}
      </div>

      {isLoading && <p className="text-xs text-muted-foreground">Loading…</p>}
      {data && data.total === 0 && (
        <p className="py-6 text-center text-sm text-muted-foreground">
          {active ? 'Waiting for rows…' : 'No rows (nothing collected, or every row was filtered out by the artifact).'}
        </p>
      )}
      {data && data.total > 0 && (
        <>
          <div className="max-h-[480px] overflow-auto rounded border border-border">
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-card">
                <tr className="border-b border-border text-muted-foreground">
                  {columns.map(c => <th key={c} className="whitespace-nowrap px-2 py-1.5 text-left font-semibold">{c}</th>)}
                  {hasFileData && <th className="px-2 py-1.5" />}
                </tr>
              </thead>
              <tbody>
                {data.rows.map((row, i) => (
                  <tr key={offset + i} className="border-b border-border/40 align-top hover:bg-muted/20">
                    {columns.map(c => (
                      <td key={c} className="max-w-[420px] break-all px-2 py-1"><Cell value={c === 'Data' ? `${String(row[c] ?? '').length} base64 chars` : row[c]} /></td>
                    ))}
                    {hasFileData && (
                      <td className="px-2 py-1">
                        <button className="flex items-center gap-1 text-primary hover:underline"
                          onClick={() => saveBase64(String(row.Path ?? 'file').split('/').pop() || 'file', String(row.Data ?? ''))}>
                          <Download size={11} /> file
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Rows {offset + 1}–{offset + data.rows.length} of {data.total}</span>
            <div className="flex gap-2">
              <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 500))}
                className="rounded border border-border px-2 py-0.5 disabled:opacity-40">Prev</button>
              <button disabled={offset + 500 >= data.total} onClick={() => setOffset(offset + 500)}
                className="rounded border border-border px-2 py-0.5 disabled:opacity-40">Next</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function FlowDetailPanel({ flowId, agentName }: { flowId: string; agentName: string }) {
  const { data: flow } = useFlow(flowId)
  const [tab, setTab] = useState<'results' | 'logs' | 'request'>('results')
  const active = !!flow && ACTIVE.includes(flow.status)
  const { data: logs = [] } = useFlowLogs(flowId, active)
  const cancel = useCancelFlow()
  if (!flow) return <div className="rounded-lg border border-border bg-card p-4 text-sm text-muted-foreground">Loading flow…</div>

  return (
    <div className="space-y-3 rounded-lg border border-border bg-card p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-mono text-sm font-bold">{flow.artifact}</span>
        <StatusPill status={flow.status} />
        <span className="text-xs text-muted-foreground">on {agentName} · {flow.total_rows} rows · {duration(flow)}</span>
        {active && (
          <button onClick={() => cancel.mutate(flow.id)} disabled={cancel.isPending}
            className="ml-auto flex items-center gap-1 rounded border border-red-400/40 px-2 py-1 text-xs text-red-400 hover:bg-red-400/10 disabled:opacity-50">
            <Ban size={12} /> Cancel
          </button>
        )}
      </div>
      {flow.error && <p className="rounded bg-destructive/10 px-2 py-1 text-xs text-destructive">{flow.error}</p>}

      <div className="flex gap-1 border-b border-border">
        {(['results', 'logs', 'request'] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 py-1.5 text-xs font-medium capitalize ${tab === t ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
            {t}{t === 'logs' && logs.length ? ` (${logs.length})` : ''}
          </button>
        ))}
      </div>

      {tab === 'results' && <FlowResultsView flowId={flow.id} sources={flow.sources} active={active} />}
      {tab === 'logs' && (
        <div className="max-h-[420px] space-y-0.5 overflow-auto font-mono text-xs">
          {logs.map((l, i) => (
            <div key={i} className="flex gap-3">
              <span className="shrink-0 text-muted-foreground">{format(new Date(l.ts), 'HH:mm:ss')}</span>
              <span className={`w-10 shrink-0 uppercase ${l.level === 'error' ? 'text-red-400' : l.level === 'warn' ? 'text-yellow-400' : 'text-muted-foreground'}`}>{l.level}</span>
              <span className="break-all">{l.message}</span>
            </div>
          ))}
        </div>
      )}
      {tab === 'request' && (
        <div className="grid gap-3 lg:grid-cols-2">
          <div>
            <p className="mb-1 text-xs uppercase text-muted-foreground">Sent to agent</p>
            <pre className="max-h-[420px] overflow-auto rounded bg-muted/20 p-2 text-xs">{JSON.stringify(flow.request, null, 2)}</pre>
          </div>
          <div>
            <p className="mb-1 text-xs uppercase text-muted-foreground">Artifact (as run) · params {JSON.stringify(flow.params)}</p>
            <pre className="max-h-[420px] overflow-auto rounded bg-muted/20 p-2 text-xs">{flow.artifact_content}</pre>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Collect tab ─────────────────────────────────────────────────

function CollectTab({ agents, artifacts }: { agents: Agent[]; artifacts: FlowArtifact[] }) {
  const [agentId, setAgentId] = useState('')
  const [artifactName, setArtifactName] = useState('')
  const [params, setParams] = useState<Record<string, string | boolean>>({})
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [timeout, setTimeoutValue] = useState('')
  const [maxRows, setMaxRows] = useState('')
  // ?flow=<id> opens that flow (linked from AI investigations)
  const [selected, setSelected] = useState<string | null>(() => new URLSearchParams(window.location.search).get('flow'))
  const { data: flows = [] } = useFlows(agentId || undefined)
  const createFlow = useCreateFlow()

  const runnable = artifacts.filter(a => !a.error)
  const artifact = runnable.find(a => a.name === artifactName)
  const agentNames = useMemo(() => Object.fromEntries(agents.map(a => [a.id, a.hostname])), [agents])
  const sortedAgents = [...agents].sort((a, b) => Number(b.status === 'online') - Number(a.status === 'online') || a.hostname.localeCompare(b.hostname))

  useEffect(() => {
    setParams(Object.fromEntries((artifact?.parameters ?? []).map(p => [p.name, p.type === 'bool' ? Boolean(p.default) : String(p.default ?? '')])))
  }, [artifactName]) // eslint-disable-line react-hooks/exhaustive-deps

  const collect = () => {
    if (!agentId || !artifact) return
    createFlow.mutate(
      {
        agent_id: agentId,
        artifact: artifact.name,
        params,
        timeout: timeout ? Number(timeout) : undefined,
        max_rows: maxRows ? Number(maxRows) : undefined,
      },
      { onSuccess: f => setSelected(f.id) },
    )
  }

  const input = 'w-full rounded border border-border bg-muted px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-primary'

  return (
    <div className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
      <div className="h-fit space-y-3 rounded-lg border border-border bg-card p-4">
        <p className="text-xs font-semibold uppercase text-muted-foreground">New collection</p>
        <label className="block space-y-1">
          <span className="text-xs text-muted-foreground">Endpoint</span>
          <select value={agentId} onChange={e => setAgentId(e.target.value)} className={input}>
            <option value="">Select an agent…</option>
            {sortedAgents.map(a => (
              <option key={a.id} value={a.id} disabled={!a.flow_poll_at}>
                {a.hostname} ({a.status}{a.version ? `, v${a.version}` : ''}){a.flow_poll_at ? '' : ' — no flow runner, update agent'}
              </option>
            ))}
          </select>
        </label>
        <label className="block space-y-1">
          <span className="text-xs text-muted-foreground">Artifact</span>
          <select value={artifactName} onChange={e => setArtifactName(e.target.value)} className={input}>
            <option value="">Select an artifact…</option>
            {runnable.map(a => <option key={a.name} value={a.name}>{a.name}</option>)}
          </select>
        </label>
        {artifact && (
          <div className="space-y-3">
            <p className="whitespace-pre-line text-xs text-muted-foreground">{artifact.description}</p>
            <div className="flex flex-wrap gap-1">
              {artifact.sources.map(s => (
                <span key={s.name} className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                  {s.name} · {s.plugin}{s.filtered && <Filter size={10} className="text-primary" />}
                </span>
              ))}
            </div>
            {artifact.parameters.map(p => (
              <label key={p.name} className="block space-y-1">
                <span className="font-mono text-xs">{p.name} <span className="text-muted-foreground">({p.type})</span></span>
                {p.type === 'bool' ? (
                  <input type="checkbox" checked={Boolean(params[p.name])}
                    onChange={e => setParams(v => ({ ...v, [p.name]: e.target.checked }))} className="block" />
                ) : (
                  <input value={String(params[p.name] ?? '')} inputMode={p.type === 'int' ? 'numeric' : undefined}
                    onChange={e => setParams(v => ({ ...v, [p.name]: e.target.value }))} className={`${input} font-mono`} />
                )}
                {p.description && <span className="block text-[11px] text-muted-foreground">{p.description}</span>}
              </label>
            ))}
            <button onClick={() => setShowAdvanced(x => !x)} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              {showAdvanced ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Resource limits
            </button>
            {showAdvanced && (
              <div className="grid grid-cols-2 gap-2">
                <label className="space-y-1">
                  <span className="text-[11px] text-muted-foreground">Timeout (s)</span>
                  <input value={timeout} onChange={e => setTimeoutValue(e.target.value)} placeholder={String(artifact.timeout ?? 600)} className={input} />
                </label>
                <label className="space-y-1">
                  <span className="text-[11px] text-muted-foreground">Max rows</span>
                  <input value={maxRows} onChange={e => setMaxRows(e.target.value)} placeholder={String(artifact.max_rows ?? 10000)} className={input} />
                </label>
              </div>
            )}
          </div>
        )}
        <button onClick={collect} disabled={!agentId || !artifact || createFlow.isPending}
          className="flex w-full items-center justify-center gap-1.5 rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50">
          {createFlow.isPending ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} Collect
        </button>
        {agentId && agents.find(a => a.id === agentId)?.status !== 'online' && (
          <p className="text-[11px] text-yellow-400">This agent is offline — the collection will wait until it reconnects (up to 24h).</p>
        )}
      </div>

      <div className="min-w-0 space-y-4">
        <div className="overflow-hidden rounded-lg border border-border bg-card">
          <div className="max-h-[320px] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card">
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="px-3 py-2 text-left font-semibold">Artifact</th>
                  <th className="px-3 py-2 text-left font-semibold">Endpoint</th>
                  <th className="px-3 py-2 text-left font-semibold">Status</th>
                  <th className="px-3 py-2 text-right font-semibold">Rows</th>
                  <th className="px-3 py-2 text-left font-semibold">Started</th>
                  <th className="px-3 py-2 text-left font-semibold">Duration</th>
                </tr>
              </thead>
              <tbody>
                {flows.length === 0 && (
                  <tr><td colSpan={6} className="py-8 text-center text-sm text-muted-foreground">No collections yet. Pick an endpoint and an artifact.</td></tr>
                )}
                {flows.map(f => (
                  <tr key={f.id} onClick={() => setSelected(f.id)}
                    className={`cursor-pointer border-b border-border/40 hover:bg-muted/20 ${selected === f.id ? 'bg-muted/30' : ''}`}>
                    <td className="px-3 py-1.5 font-mono text-xs">{f.artifact}</td>
                    <td className="px-3 py-1.5 text-xs">{agentNames[f.agent_id] ?? f.agent_id.slice(0, 8)}</td>
                    <td className="px-3 py-1.5"><StatusPill status={f.status} /></td>
                    <td className="px-3 py-1.5 text-right font-mono text-xs">{f.total_rows}</td>
                    <td className="px-3 py-1.5 text-xs text-muted-foreground">{format(new Date(f.created_at), 'MM-dd HH:mm:ss')}</td>
                    <td className="px-3 py-1.5 text-xs text-muted-foreground">{duration(f)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
        {selected && (
          <FlowDetailPanel flowId={selected}
            agentName={agentNames[flows.find(f => f.id === selected)?.agent_id ?? ''] ?? 'agent'} />
        )}
      </div>
    </div>
  )
}

// ─── Artifacts tab ───────────────────────────────────────────────

function ArtifactsTab({ artifacts }: { artifacts: FlowArtifact[] }) {
  const [editing, setEditing] = useState<{ name?: string; content: string } | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const save = useSaveFlowArtifact()
  const del = useDeleteFlowArtifact()

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Artifacts compile to plugin calls on the agent; each source can filter its rows with a Sigma <code>detection</code> block on the server.
        </p>
        <button onClick={() => setEditing({ content: NEW_ARTIFACT_TEMPLATE })}
          className="flex shrink-0 items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground">
          <Plus size={14} /> New artifact
        </button>
      </div>
      <div className="divide-y divide-border rounded-lg border border-border bg-card">
        {artifacts.map(a => (
          <div key={a.name} className="p-3">
            <div className="flex items-center gap-2">
              <button onClick={() => setOpen(open === a.name ? null : a.name)} className="flex min-w-0 items-center gap-2 text-left">
                {open === a.name ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                <FileCode size={14} className="shrink-0 text-muted-foreground" />
                <span className="truncate font-mono text-sm font-semibold">{a.name}</span>
              </button>
              {a.builtin
                ? <span className="rounded border border-border px-1.5 text-[10px] uppercase text-muted-foreground">built-in</span>
                : <span className="rounded border border-primary/40 px-1.5 text-[10px] uppercase text-primary">custom</span>}
              {a.error && <span className="text-xs text-destructive">invalid: {a.error}</span>}
              <span className="ml-auto hidden text-xs text-muted-foreground md:inline">
                {a.sources.map(s => s.plugin).join(', ')}
              </span>
              {!a.builtin && (
                <>
                  <button title="Edit" onClick={() => setEditing({ name: a.name, content: a.content })} className="text-muted-foreground hover:text-primary"><Pencil size={14} /></button>
                  <button title="Delete" onClick={() => { if (window.confirm(`Delete artifact ${a.name}?`)) del.mutate(a.name) }}
                    className="text-muted-foreground hover:text-destructive"><Trash2 size={14} /></button>
                </>
              )}
            </div>
            <p className="ml-11 mt-1 whitespace-pre-line text-xs text-muted-foreground">{a.description}</p>
            {open === a.name && (
              <div className="ml-11 mt-2 space-y-2">
                <pre className="max-h-80 overflow-auto rounded bg-muted/20 p-2 text-xs">{a.content}</pre>
                {a.builtin && (
                  <button onClick={() => setEditing({ content: a.content.replace(/^name:\s*(\S+)/m, 'name: Custom.$1') })}
                    className="text-xs text-primary hover:underline">Copy as custom artifact</button>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
      {editing && (
        <YamlEditor
          title={editing.name ? `Edit ${editing.name}` : 'New artifact'}
          value={editing.content}
          onChange={content => setEditing(e => (e ? { ...e, content } : e))}
          onSave={() => save.mutate({ name: editing.name, content: editing.content }, { onSuccess: () => setEditing(null) })}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────

export default function LiveResponsePage() {
  const [tab, setTab] = useState<Tab>('collect')
  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents-all'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data.items),
  })
  const { data: artifacts = [] } = useFlowArtifacts()

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <Terminal size={18} />
        <h1 className="text-xl font-bold">Live Response</h1>
        <div className="ml-auto flex gap-1 rounded-lg border border-border bg-card p-1">
          {([['collect', 'Collect'], ['artifacts', 'Artifacts'], ['legacy', 'Legacy tasks']] as const).map(([key, label]) => (
            <button key={key} onClick={() => setTab(key)}
              className={`rounded px-3 py-1 text-sm ${tab === key ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:text-foreground'}`}>
              {label}
            </button>
          ))}
        </div>
      </div>
      {tab === 'collect' && <CollectTab agents={agents} artifacts={artifacts} />}
      {tab === 'artifacts' && <ArtifactsTab artifacts={artifacts} />}
      {tab === 'legacy' && <LegacyTasks />}
    </div>
  )
}
