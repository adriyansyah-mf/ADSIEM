import { useState } from 'react'
import { format } from 'date-fns'
import { Package, Play, Users, Loader2, CheckCircle } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useBuiltinArtifacts, useRunArtifact } from '@/hooks/useArtifacts'
import { useFleetHunts, useCreateFleetHunt } from '@/hooks/useTasks'
import type { Agent } from '@/types'

const TASK_ICONS: Record<string, string> = {
  process_list: '⚙️', netstat: '🌐', persistence_check: '🔩',
  users_list: '👤', dmesg_tail: '📟', open_files: '📂',
  file_list: '🗂️', file_get: '💾', yara_scan: '🔍',
}

export default function ArtifactsPage() {
  const { data: builtins = [] } = useBuiltinArtifacts()
  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents-all'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data.items),
  })
  const { data: fleetHunts = [] } = useFleetHunts()
  const runArtifact = useRunArtifact()
  const createFleet = useCreateFleetHunt()

  const [selectedAgent, setSelectedAgent] = useState<string>('')
  const [fleetName, setFleetName] = useState('')
  const [fleetType, setFleetType] = useState('')
  const [justRan, setJustRan] = useState<string | null>(null)

  const onlineAgents = agents.filter(a => a.status === 'online')

  const handleRun = async (artifact: typeof builtins[0]) => {
    if (!selectedAgent && onlineAgents.length === 0) return
    const agentIds = selectedAgent ? [selectedAgent] : undefined

    // use artifact builtins endpoint by matching task_type
    const allArtifacts = await api.get('/api/artifacts').then(r => r.data)
    const match = allArtifacts.find((a: { task_type: string; id: string }) => a.task_type === artifact.task_type)
    if (match) {
      await runArtifact.mutateAsync({ id: match.id, agentIds })
    } else {
      // create on the fly via tasks
      const agents2 = agentIds ? agents.filter(a => agentIds.includes(a.id)) : onlineAgents
      for (const ag of agents2) {
        await api.post('/api/tasks', { agent_id: ag.id, task_type: artifact.task_type, params: artifact.default_params })
      }
    }
    setJustRan(artifact.task_type)
    setTimeout(() => setJustRan(null), 3000)
  }

  const handleFleetHunt = () => {
    if (!fleetType || !fleetName) return
    createFleet.mutate({ name: fleetName, task_type: fleetType, params: {} })
    setFleetName('')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Package size={18} />
        <h1 className="text-xl font-bold">Artifacts</h1>
      </div>

      {/* Agent selector */}
      <div className="rounded-lg border border-border bg-card p-4">
        <p className="text-xs text-muted-foreground uppercase font-semibold mb-2">Target</p>
        <select value={selectedAgent} onChange={e => setSelectedAgent(e.target.value)}
          className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary min-w-[220px]">
          <option value="">All online agents ({onlineAgents.length})</option>
          {agents.map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
        </select>
      </div>

      {/* Built-in artifact catalog */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <p className="text-xs text-muted-foreground uppercase font-semibold">Built-in Collections</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {builtins.map(art => (
            <div key={art.task_type} className="rounded border border-border p-3 space-y-2 hover:border-primary/50 transition-colors">
              <div className="flex items-center gap-2">
                <span className="text-lg">{TASK_ICONS[art.task_type] ?? '📋'}</span>
                <div>
                  <p className="text-sm font-semibold">{art.name}</p>
                  <p className="text-xs text-muted-foreground line-clamp-2">{art.description}</p>
                </div>
              </div>
              <button
                onClick={() => handleRun(art)}
                disabled={runArtifact.isPending}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded bg-primary/10 border border-primary/30 hover:bg-primary/20 text-primary text-xs font-medium transition-colors"
              >
                {justRan === art.task_type
                  ? <><CheckCircle size={12} /> Dispatched!</>
                  : runArtifact.isPending
                    ? <><Loader2 size={12} className="animate-spin" /> Running…</>
                    : <><Play size={12} /> Run</>
                }
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Fleet Hunt */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Users size={14} />
          <p className="text-xs text-muted-foreground uppercase font-semibold">Fleet Hunt — Run on All Online Agents</p>
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
            {createFleet.isPending ? <Loader2 size={14} className="animate-spin" /> : <Users size={14} />}
            Launch Fleet Hunt
          </button>
        </div>

        {/* Fleet hunt history */}
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
    </div>
  )
}
