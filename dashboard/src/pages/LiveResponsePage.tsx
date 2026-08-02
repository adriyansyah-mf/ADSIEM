import { useState } from 'react'
import { format } from 'date-fns'
import { Terminal, Play, Users, Download, ChevronDown, ChevronRight, CheckCircle, XCircle, Loader2, Clock } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useTasks, useCreateTask, useFleetHunts, useCreateFleetHunt } from '@/hooks/useTasks'
import { useBuiltinArtifacts } from '@/hooks/useArtifacts'
import type { Agent, AgentTask } from '@/types'

const TASK_ICONS: Record<string, string> = {
  process_list: '⚙️', netstat: '🌐', persistence_check: '🔩',
  users_list: '👤', dmesg_tail: '📟', open_files: '📂',
  file_list: '🗂️', file_get: '💾', yara_scan: '🔍',
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'done') return <CheckCircle size={13} className="text-emerald-400" />
  if (status === 'failed') return <XCircle size={13} className="text-red-400" />
  if (status === 'dispatched' || status === 'running') return <Loader2 size={13} className="text-blue-400 animate-spin" />
  return <Clock size={13} className="text-muted-foreground" />
}

function TaskResult({ task }: { task: AgentTask }) {
  if (task.status === 'failed') return <p className="text-xs text-destructive">{task.error}</p>
  if (!task.result) return null
  const result = task.result as Record<string, unknown>

  if (task.task_type === 'process_list') {
    const procs = result as unknown as Array<{ pid: number; name: string; cmdline: string; state: string; uid: string; vmrss_kb: string }>
    return (
      <div className="overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <thead><tr className="border-b border-border text-muted-foreground">
            <th className="text-left py-1 pr-3">PID</th><th className="text-left py-1 pr-3">NAME</th>
            <th className="text-left py-1 pr-3">STATE</th><th className="text-left py-1 pr-3">UID</th>
            <th className="text-left py-1 pr-3">MEM(KB)</th><th className="text-left py-1">CMDLINE</th>
          </tr></thead>
          <tbody>{(Array.isArray(result) ? result : []).map((p: typeof procs[0], i: number) => (
            <tr key={i} className="border-b border-border/40 hover:bg-muted/20">
              <td className="py-0.5 pr-3 text-accent-cyan">{p.pid}</td>
              <td className="py-0.5 pr-3 font-bold">{p.name}</td>
              <td className="py-0.5 pr-3">{p.state}</td>
              <td className="py-0.5 pr-3">{p.uid}</td>
              <td className="py-0.5 pr-3">{p.vmrss_kb}</td>
              <td className="py-0.5 text-muted-foreground truncate max-w-[300px]">{p.cmdline}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    )
  }

  if (task.task_type === 'users_list') {
    const users = result as unknown as Array<{ username: string; uid: string; gid: string; home_dir: string; shell: string }>
    return (
      <table className="w-full text-xs font-mono">
        <thead><tr className="border-b border-border text-muted-foreground">
          <th className="text-left py-1 pr-3">USERNAME</th><th className="text-left py-1 pr-3">UID</th>
          <th className="text-left py-1 pr-3">GID</th><th className="text-left py-1 pr-3">HOME</th><th className="text-left py-1">SHELL</th>
        </tr></thead>
        <tbody>{(Array.isArray(result) ? result : []).map((u: typeof users[0], i: number) => (
          <tr key={i} className="border-b border-border/40">
            <td className="py-0.5 pr-3 font-bold text-accent-cyan">{u.username}</td>
            <td className="py-0.5 pr-3">{u.uid}</td><td className="py-0.5 pr-3">{u.gid}</td>
            <td className="py-0.5 pr-3">{u.home_dir}</td><td className="py-0.5">{u.shell}</td>
          </tr>
        ))}</tbody>
      </table>
    )
  }

  if (task.task_type === 'file_list') {
    const files = result as unknown as Array<{ name: string; path: string; size: number; mode: string; mod_time: string; is_dir: boolean }>
    return (
      <div className="max-h-80 overflow-y-auto">
        <table className="w-full text-xs font-mono">
          <thead><tr className="border-b border-border text-muted-foreground">
            <th className="text-left py-1 pr-3">MODE</th><th className="text-left py-1 pr-3">SIZE</th>
            <th className="text-left py-1 pr-3">MODIFIED</th><th className="text-left py-1">PATH</th>
          </tr></thead>
          <tbody>{(Array.isArray(result) ? result : []).map((f: typeof files[0], i: number) => (
            <tr key={i} className="border-b border-border/40 hover:bg-muted/20">
              <td className="py-0.5 pr-3 text-muted-foreground">{f.mode}</td>
              <td className="py-0.5 pr-3">{f.size}</td>
              <td className="py-0.5 pr-3">{f.mod_time?.slice(0, 16)}</td>
              <td className={`py-0.5 ${f.is_dir ? 'text-blue-400 font-bold' : 'text-accent-cyan'}`}>{f.path}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    )
  }

  if (task.task_type === 'file_get') {
    const fc = result as { path: string; size_bytes: number; encoding: string; content: string; truncated: boolean }
    const decoded = fc.content ? atob(fc.content) : ''
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span>{fc.path}</span><span>{fc.size_bytes} bytes</span>
          {fc.truncated && <span className="text-yellow-400">TRUNCATED</span>}
          <button onClick={() => {
            const blob = new Blob([decoded], { type: 'text/plain' })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url; a.download = fc.path.split('/').pop() || 'file'; a.click()
          }} className="flex items-center gap-1 text-primary hover:underline ml-auto">
            <Download size={11} /> Download
          </button>
        </div>
        <pre className="text-xs bg-muted/20 rounded p-2 max-h-60 overflow-auto font-mono whitespace-pre-wrap break-all">{decoded.slice(0, 50000)}</pre>
      </div>
    )
  }

  if (task.task_type === 'persistence_check') {
    const items = result as unknown as Array<{ category: string; path: string; content: string; exists: boolean }>
    const cats = Array.isArray(result) ? [...new Set((result as typeof items).map(i => i.category))] : []
    return (
      <div className="space-y-3">
        {cats.map(cat => (
          <div key={cat}>
            <p className="text-xs font-bold uppercase text-muted-foreground mb-1">{cat.replace(/_/g, ' ')}</p>
            {(Array.isArray(result) ? result as typeof items : []).filter(i => i.category === cat).map((item, i) => (
              <details key={i} className="mb-1">
                <summary className="text-xs font-mono cursor-pointer text-accent-cyan hover:underline">{item.path}</summary>
                <pre className="text-xs bg-muted/20 p-2 mt-1 rounded max-h-40 overflow-auto whitespace-pre-wrap">{item.content || '(empty)'}</pre>
              </details>
            ))}
          </div>
        ))}
      </div>
    )
  }

  if (task.task_type === 'dmesg_tail') {
    const lines = (result as { lines?: string[] }).lines ?? []
    return <pre className="text-xs font-mono bg-muted/20 p-2 rounded max-h-60 overflow-auto whitespace-pre-wrap">{lines.join('\n')}</pre>
  }

  if (task.task_type === 'netstat') {
    const raw = (result as { raw?: string }).raw ?? ''
    const conns = (result as { connections?: Array<{ local: string; remote: string; state: string }> }).connections ?? []
    return (
      <div className="space-y-3">
        <pre className="text-xs font-mono bg-muted/20 p-2 rounded max-h-40 overflow-auto whitespace-pre-wrap">{raw}</pre>
        {conns.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground uppercase mb-1">Established Connections ({conns.length})</p>
            <div className="max-h-40 overflow-auto space-y-0.5">
              {conns.map((c, i) => (
                <div key={i} className="flex gap-3 text-xs font-mono">
                  <span className="text-accent-cyan">{c.local}</span>
                  <span className="text-muted-foreground">→</span>
                  <span>{c.remote}</span>
                  <span className="text-muted-foreground">{c.state}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  // generic JSON fallback (also covers yara_scan)
  return <pre className="text-xs font-mono bg-muted/20 p-2 rounded max-h-60 overflow-auto">{JSON.stringify(result, null, 2)}</pre>
}

function TaskCard({ task }: { task: AgentTask }) {
  const [open, setOpen] = useState(task.status === 'done' || task.status === 'failed')
  return (
    <div className="rounded border border-border bg-card overflow-hidden">
      <button className="w-full flex items-center gap-2 px-3 py-2 hover:bg-muted/20 text-left" onClick={() => setOpen(x => !x)}>
        <StatusIcon status={task.status} />
        <span className="text-xs font-mono font-bold">{task.task_type}</span>
        <span className="text-xs text-muted-foreground ml-auto">{format(new Date(task.created_at), 'HH:mm:ss')}</span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>
      {open && (
        <div className="border-t border-border p-3">
          {(task.status === 'pending' || task.status === 'dispatched') && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 size={12} className="animate-spin" /> Waiting for agent…
            </div>
          )}
          {task.status === 'done' || task.status === 'failed' ? <TaskResult task={task} /> : null}
        </div>
      )}
    </div>
  )
}

export default function LiveResponsePage() {
  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents-all'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data.items),
  })
  const { data: builtins = [] } = useBuiltinArtifacts()
  const [selectedAgent, setSelectedAgent] = useState<string>('')
  const [paramOverrides, setParamOverrides] = useState<Record<string, Record<string, string>>>({})
  const { data: tasks = [] } = useTasks(selectedAgent || undefined)
  const createTask = useCreateTask()
  const { data: fleetHunts = [] } = useFleetHunts()
  const createFleet = useCreateFleetHunt()
  const [fleetName, setFleetName] = useState('')
  const [fleetType, setFleetType] = useState('')
  const [justRan, setJustRan] = useState<string | null>(null)

  const onlineAgents = agents.filter(a => a.status === 'online')
  const agentTasks = tasks.filter(t => !selectedAgent || t.agent_id === selectedAgent)

  const dispatch = (art: typeof builtins[0]) => {
    const targets = selectedAgent ? [selectedAgent] : onlineAgents.map(a => a.id)
    if (targets.length === 0) return
    const overrides = paramOverrides[art.task_type] ?? {}
    const params = { ...art.default_params, ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== '')) }
    targets.forEach(agent_id => createTask.mutate({ agent_id, task_type: art.task_type, params }))
    setJustRan(art.task_type)
    setTimeout(() => setJustRan(null), 2000)
  }

  const handleFleetHunt = () => {
    if (!fleetType || !fleetName) return
    createFleet.mutate({ name: fleetName, task_type: fleetType, params: {} })
    setFleetName('')
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <Terminal size={18} />
        <h1 className="text-xl font-bold">Live Response</h1>
      </div>

      {/* Target selector — one specific agent, or every online agent */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <p className="text-xs text-muted-foreground uppercase font-semibold">Target</p>
        <select value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)}
          className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary sm:max-w-xs">
          <option value="">All online agents ({onlineAgents.length})</option>
          {agents.map(a => (
            <option key={a.id} value={a.id}>{a.hostname} ({a.status})</option>
          ))}
        </select>
      </div>

      {/* Collections */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <p className="text-xs text-muted-foreground uppercase font-semibold">Collections</p>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {builtins.map(art => (
            <div key={art.task_type} className="space-y-1">
              {/* param inputs for tasks that need them */}
              {(art.task_type === 'file_list' || art.task_type === 'file_get') && (
                <input
                  placeholder={art.task_type === 'file_get' ? '/etc/passwd' : '/tmp'}
                  value={paramOverrides[art.task_type]?.path ?? ''}
                  onChange={e => setParamOverrides(p => ({ ...p, [art.task_type]: { ...p[art.task_type], path: e.target.value } }))}
                  className="w-full text-xs bg-muted border border-border rounded px-2 py-1 font-mono focus:outline-none"
                />
              )}
              <button
                onClick={() => dispatch(art)}
                disabled={createTask.isPending}
                title={art.description}
                className="w-full flex items-center gap-1.5 px-3 py-2 rounded border border-border hover:border-primary hover:text-primary transition-colors text-sm disabled:opacity-50"
              >
                <span>{TASK_ICONS[art.task_type] ?? '📋'}</span>
                <span className="truncate">{art.name}</span>
                {justRan === art.task_type && <CheckCircle size={12} className="text-emerald-400 ml-auto shrink-0" />}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Fleet Hunt — named, tracked runs across all online agents */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Users size={14} />
          <p className="text-xs text-muted-foreground uppercase font-semibold">Fleet Hunt — Tracked Run on All Online Agents</p>
        </div>
        <div className="flex gap-3 flex-wrap">
          <input value={fleetName} onChange={e => setFleetName(e.target.value)} placeholder="Hunt name…"
            className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary min-w-[160px]" />
          <select value={fleetType} onChange={e => setFleetType(e.target.value)}
            className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary">
            <option value="">Select artifact…</option>
            {builtins.map(a => <option key={a.task_type} value={a.task_type}>{a.name}</option>)}
          </select>
          <button onClick={handleFleetHunt} disabled={!fleetName || !fleetType || createFleet.isPending}
            className="flex items-center gap-1.5 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
            {createFleet.isPending ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            Launch Fleet Hunt
          </button>
        </div>

        {fleetHunts.length > 0 && (
          <div className="space-y-2 mt-2">
            {fleetHunts.map(fh => (
              <div key={fh.id} className="flex items-center gap-3 text-sm rounded border border-border px-3 py-2">
                <span className={`w-2 h-2 rounded-full ${fh.status === 'done' ? 'bg-emerald-400' : fh.status === 'running' ? 'bg-blue-400 animate-pulse' : 'bg-muted-foreground'}`} />
                <span className="font-medium">{fh.name}</span>
                <span className="text-muted-foreground text-xs font-mono">{fh.task_type}</span>
                <span className="text-xs text-muted-foreground ml-auto">
                  {fh.completed_agents}/{fh.total_agents} agents · {format(new Date(fh.created_at), 'MM-dd HH:mm')}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Task results */}
      <div className="space-y-2">
        {agentTasks.length === 0 && (
          <div className="text-sm text-muted-foreground text-center py-8">
            No tasks yet. Dispatch a collection above.
          </div>
        )}
        {agentTasks.map(t => <TaskCard key={t.id} task={t} />)}
      </div>
    </div>
  )
}
