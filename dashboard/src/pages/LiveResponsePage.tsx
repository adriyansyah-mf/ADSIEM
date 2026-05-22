import { useState } from 'react'
import { format } from 'date-fns'
import { Terminal, Play, RefreshCw, Download, ChevronDown, ChevronRight, CheckCircle, XCircle, Loader2, Clock } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useTasks, useCreateTask } from '@/hooks/useTasks'
import type { Agent, AgentTask } from '@/types'

const TASK_TYPES = [
  { type: 'process_list', label: 'Process List', icon: '⚙️', params: {} },
  { type: 'netstat', label: 'Network Connections', icon: '🌐', params: {} },
  { type: 'persistence_check', label: 'Persistence Check', icon: '🔩', params: {} },
  { type: 'users_list', label: 'User Accounts', icon: '👤', params: {} },
  { type: 'open_files', label: 'Open Files', icon: '📂', params: { limit: 100 } },
  { type: 'dmesg_tail', label: 'Kernel Log', icon: '📟', params: { lines: 100 } },
  { type: 'file_list', label: 'File List', icon: '🗂️', params: { path: '/tmp', max_depth: 2 } },
  { type: 'file_get', label: 'File Acquisition', icon: '💾', params: { path: '' } },
]

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

  // generic JSON fallback
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
  const [selectedAgent, setSelectedAgent] = useState<string>('')
  const [paramOverrides, setParamOverrides] = useState<Record<string, Record<string, string>>>({})
  const { data: tasks = [] } = useTasks(selectedAgent || undefined)
  const createTask = useCreateTask()

  const agentTasks = tasks.filter(t => !selectedAgent || t.agent_id === selectedAgent)

  const dispatch = (tt: typeof TASK_TYPES[0]) => {
    if (!selectedAgent) return
    const overrides = paramOverrides[tt.type] ?? {}
    const params = { ...tt.params, ...Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== '')) }
    createTask.mutate({ agent_id: selectedAgent, task_type: tt.type, params })
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <Terminal size={18} />
        <h1 className="text-xl font-bold">Live Response</h1>
      </div>

      {/* Agent selector */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <p className="text-xs text-muted-foreground uppercase font-semibold">Target Agent</p>
        <select value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)}
          className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary">
          <option value="">— Select agent —</option>
          {agents.map(a => (
            <option key={a.id} value={a.id}>{a.hostname} ({a.status})</option>
          ))}
        </select>
      </div>

      {/* Collection buttons */}
      {selectedAgent && (
        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <p className="text-xs text-muted-foreground uppercase font-semibold">Collections</p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {TASK_TYPES.map(tt => (
              <div key={tt.type} className="space-y-1">
                {/* param inputs for tasks that need them */}
                {(tt.type === 'file_list' || tt.type === 'file_get') && (
                  <input
                    placeholder={tt.type === 'file_get' ? '/etc/passwd' : '/tmp'}
                    value={paramOverrides[tt.type]?.path ?? ''}
                    onChange={e => setParamOverrides(p => ({ ...p, [tt.type]: { ...p[tt.type], path: e.target.value } }))}
                    className="w-full text-xs bg-muted border border-border rounded px-2 py-1 font-mono focus:outline-none"
                  />
                )}
                <button
                  onClick={() => dispatch(tt)}
                  disabled={createTask.isPending}
                  className="w-full flex items-center gap-1.5 px-3 py-2 rounded border border-border hover:border-primary hover:text-primary transition-colors text-sm disabled:opacity-50"
                >
                  <span>{tt.icon}</span>
                  <span className="truncate">{tt.label}</span>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Task results */}
      <div className="space-y-2">
        {agentTasks.length === 0 && selectedAgent && (
          <div className="text-sm text-muted-foreground text-center py-8">
            No tasks yet. Dispatch a collection above.
          </div>
        )}
        {agentTasks.map(t => <TaskCard key={t.id} task={t} />)}
      </div>
    </div>
  )
}
