import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useLogSources, useAddLogSource, useUpdateLogSource, useDeleteLogSource } from '@/hooks/useAgents'
import StatusBadge from '@/components/StatusBadge'
import { Trash2, Plus } from 'lucide-react'
import type { LogSource } from '@/types'

export default function LogSourcesPage() {
  const { id } = useParams<{ id: string }>()
  const { data: sources, isLoading } = useLogSources(id!)
  const addSource = useAddLogSource(id!)
  const updateSource = useUpdateLogSource(id!)
  const deleteSource = useDeleteLogSource(id!)
  const [path, setPath] = useState('')
  const [logType, setLogType] = useState('')

  const handleAdd = () => {
    if (!path || !logType) return
    addSource.mutate({ path, log_type: logType, is_enabled: true })
    setPath('')
    setLogType('')
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Log Sources for Agent</h1>
      <div className="mb-4 flex gap-2">
        <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/var/log/auth.log"
          className="flex-1 px-3 py-2 rounded border border-border bg-background text-sm" />
        <input value={logType} onChange={(e) => setLogType(e.target.value)} placeholder="linux_auth"
          className="w-40 px-3 py-2 rounded border border-border bg-background text-sm" />
        <button onClick={handleAdd} className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-1">
          <Plus size={14} /> Add
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <div className="space-y-2">
          {(sources ?? []).map((s: LogSource) => (
            <div key={s.id} className="flex items-center justify-between px-4 py-3 rounded border border-border bg-card">
              <div>
                <div className="font-mono text-sm">{s.path}</div>
                <div className="text-xs text-muted-foreground">{s.log_type}</div>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={() => updateSource.mutate({ sourceId: s.id, data: { ...s, is_enabled: !s.is_enabled } })}
                  className="text-xs underline text-muted-foreground hover:text-foreground">
                  {s.is_enabled ? 'Disable' : 'Enable'}
                </button>
                <StatusBadge status={s.is_enabled ? 'online' : 'offline'} />
                <button onClick={() => deleteSource.mutate(s.id)} className="text-destructive hover:opacity-70">
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
