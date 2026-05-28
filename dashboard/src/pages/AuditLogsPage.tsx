import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ClipboardList } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '@/api/client'

interface AuditLog {
  id: string
  actor_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  detail: Record<string, unknown>
  created_at: string
}

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-green-500/20 text-green-400',
  update: 'bg-blue-500/20 text-blue-400',
  delete: 'bg-red-500/20 text-red-400',
  login:  'bg-purple-500/20 text-purple-400',
}

function actionColor(action: string) {
  const key = Object.keys(ACTION_COLORS).find(k => action.toLowerCase().includes(k))
  return key ? ACTION_COLORS[key] : 'bg-muted text-muted-foreground'
}

export default function AuditLogsPage() {
  const [actionFilter, setActionFilter] = useState('')

  const { data: logs = [], isLoading } = useQuery<AuditLog[]>(
    ['audit-logs', actionFilter],
    () => api.get('/api/audit-logs', { params: { limit: 200, action: actionFilter || undefined } }).then(r => r.data),
    { refetchInterval: 30000 }
  )

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ClipboardList size={20} />
          <h1 className="text-xl font-semibold">Audit Log</h1>
        </div>
        <input
          placeholder="Filter by action..."
          className="px-2 py-1 text-sm bg-background border border-border rounded w-48"
          value={actionFilter}
          onChange={e => setActionFilter(e.target.value)}
        />
      </div>

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading...</div>
      ) : logs.length === 0 ? (
        <div className="text-sm text-muted-foreground">No audit log entries found.</div>
      ) : (
        <div className="border border-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">Time</th>
                <th className="text-left px-3 py-2">Action</th>
                <th className="text-left px-3 py-2">Resource</th>
                <th className="text-left px-3 py-2">Actor</th>
                <th className="text-left px-3 py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log: AuditLog) => (
                <tr key={log.id} className="border-t border-border hover:bg-muted/30">
                  <td className="px-3 py-2 text-muted-foreground whitespace-nowrap">
                    {format(new Date(log.created_at), 'yyyy-MM-dd HH:mm:ss')}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${actionColor(log.action)}`}>
                      {log.action}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {log.resource_type}
                    {log.resource_id && <span className="ml-1 opacity-60 text-xs">#{log.resource_id.slice(0, 8)}</span>}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground text-xs font-mono">
                    {log.actor_id ? log.actor_id.slice(0, 8) : '—'}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground text-xs max-w-xs truncate">
                    {Object.keys(log.detail).length > 0 ? JSON.stringify(log.detail) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
