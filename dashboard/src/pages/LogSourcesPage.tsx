import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useAgent, useLogSources, useAddLogSource, useUpdateLogSource, useDeleteLogSource } from '@/hooks/useAgents'
import StatusBadge from '@/components/StatusBadge'
import { Trash2, Plus, ArrowLeft, ToggleLeft, ToggleRight } from 'lucide-react'
import type { LogSource } from '@/types'

const LOG_TYPES = [
  { value: 'linux_auth', label: 'linux_auth — SSH / PAM / sudo' },
  { value: 'syslog', label: 'syslog — General system log' },
  { value: 'nginx_access', label: 'nginx_access — Nginx access log' },
  { value: 'nginx_error', label: 'nginx_error — Nginx error log' },
  { value: 'apache_access', label: 'apache_access — Apache access log' },
  { value: 'apache_error', label: 'apache_error — Apache error log' },
  { value: 'windows_event', label: 'windows_event — Windows Event Log' },
  { value: 'custom', label: 'custom — Other / raw' },
]

export default function LogSourcesPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: agent } = useAgent(id!)
  const { data: sources, isLoading } = useLogSources(id!)
  const addSource = useAddLogSource(id!)
  const updateSource = useUpdateLogSource(id!)
  const deleteSource = useDeleteLogSource(id!)

  const [path, setPath] = useState('')
  const [logType, setLogType] = useState('')
  const [customType, setCustomType] = useState('')
  const [error, setError] = useState('')

  const resolvedType = logType === 'custom' ? customType : logType

  const handleAdd = () => {
    if (!path.trim()) { setError('Path is required'); return }
    if (!resolvedType.trim()) { setError('Log type is required'); return }
    setError('')
    addSource.mutate(
      { path: path.trim(), log_type: resolvedType.trim(), is_enabled: true },
      { onSuccess: () => { setPath(''); setLogType(''); setCustomType('') } },
    )
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleAdd()
  }

  return (
    <div className="max-w-3xl">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button onClick={() => navigate('/agents')}
          className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground">
          <ArrowLeft size={18} />
        </button>
        <div>
          <h1 className="text-xl font-bold">Log Sources</h1>
          {agent && (
            <p className="text-sm text-muted-foreground">
              {agent.name} &middot; <span className="font-mono">{agent.hostname}</span>
              <span className="ml-2"><StatusBadge status={agent.status} /></span>
            </p>
          )}
        </div>
      </div>

      {/* Add form */}
      <div className="rounded-lg border border-border bg-card p-4 mb-6">
        <h2 className="text-sm font-semibold mb-3">Add Log Source</h2>
        <div className="flex flex-col gap-2">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="/var/log/nginx/access.log"
            className="w-full px-3 py-2 rounded border border-border bg-background text-sm font-mono"
          />
          <div className="flex gap-2">
            <select
              value={logType}
              onChange={(e) => setLogType(e.target.value)}
              className="flex-1 px-3 py-2 rounded border border-border bg-background text-sm"
            >
              <option value="">— Select log type —</option>
              {LOG_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            {logType === 'custom' && (
              <input
                value={customType}
                onChange={(e) => setCustomType(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="my_log_type"
                className="w-40 px-3 py-2 rounded border border-border bg-background text-sm"
              />
            )}
            <button
              onClick={handleAdd}
              disabled={addSource.isPending}
              className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-1.5 disabled:opacity-50"
            >
              <Plus size={14} />
              {addSource.isPending ? 'Adding…' : 'Add'}
            </button>
          </div>
          {error && <p className="text-xs text-destructive">{error}</p>}
          {addSource.isError && (
            <p className="text-xs text-destructive">Failed to add source. Check path and try again.</p>
          )}
        </div>
      </div>

      {/* Sources list */}
      <div>
        <h2 className="text-sm font-semibold mb-2 text-muted-foreground uppercase tracking-wide">
          Active Sources ({(sources ?? []).length})
        </h2>
        {isLoading ? (
          <div className="text-muted-foreground text-sm">Loading…</div>
        ) : (sources ?? []).length === 0 ? (
          <div className="text-muted-foreground text-sm py-8 text-center border border-dashed border-border rounded-lg">
            No log sources configured. Add one above.
          </div>
        ) : (
          <div className="space-y-2">
            {(sources ?? []).map((s: LogSource) => (
              <div key={s.id}
                className="flex items-center justify-between px-4 py-3 rounded-lg border border-border bg-card">
                <div>
                  <div className="font-mono text-sm">{s.path}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{s.log_type}</div>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => updateSource.mutate({ sourceId: s.id, data: { ...s, is_enabled: !s.is_enabled } })}
                    className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
                    title={s.is_enabled ? 'Disable' : 'Enable'}
                  >
                    {s.is_enabled
                      ? <ToggleRight size={18} className="text-green-500" />
                      : <ToggleLeft size={18} />}
                  </button>
                  <StatusBadge status={s.is_enabled ? 'online' : 'offline'} />
                  <button
                    onClick={() => { if (confirm(`Remove ${s.path}?`)) deleteSource.mutate(s.id) }}
                    className="text-destructive hover:opacity-70 ml-1"
                    title="Remove"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="mt-6 text-xs text-muted-foreground">
        Changes are picked up by the agent on the next heartbeat (default every 30 s).
      </p>
    </div>
  )
}
