import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ClipboardList, ShieldCheck, ShieldAlert } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '@/api/client'
import { PageHeader } from '@/components/ui/PageHeader'

interface AuditLog {
  id: string
  actor_type: string
  actor_id: string | null
  group_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  detail: Record<string, unknown>
  created_at: string
}

interface AuditChainVerification {
  group_id: string
  verified: boolean
  verified_count: number
  total_count: number
  head_hash_prefix: string | null
  broken_at_id: string | null
  broken_at_timestamp: string | null
}

function ChainStatusPanel() {
  const { data, isLoading, isError } = useQuery<AuditChainVerification>({
    queryKey: ['audit-chain-verify'],
    queryFn: () => api.get('/api/audit-logs/verify').then(r => r.data),
    retry: false,
  })

  if (isLoading) {
    return <div className="text-xs text-muted-foreground">Checking audit chain integrity...</div>
  }
  if (isError) {
    // 403 for callers without audit:verify, or the endpoint being unavailable — not a broken chain.
    return null
  }
  if (!data) return null

  const verified = data.verified
  return (
    <div
      className={`enterprise-panel rounded border p-3 flex items-center gap-3 text-sm ${
        verified ? 'border-emerald-500/30 bg-emerald-500/5' : 'border-red-500/40 bg-red-500/10'
      }`}
    >
      {verified ? (
        <ShieldCheck aria-hidden="true" size={18} className="text-emerald-400 shrink-0" />
      ) : (
        <ShieldAlert aria-hidden="true" size={18} className="text-red-400 shrink-0" />
      )}
      <div className="flex flex-col gap-0.5">
        <span className={verified ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
          Audit chain {verified ? 'VERIFIED' : 'BROKEN'}
          <span className="ml-2 font-normal text-muted-foreground">
            ({data.verified_count}/{data.total_count} entries verified{data.group_id ? `, tenant "${data.group_id}"` : ''})
          </span>
        </span>
        {data.head_hash_prefix && (
          <span className="text-xs text-muted-foreground font-mono">
            head: {data.head_hash_prefix}...
          </span>
        )}
        {!verified && data.broken_at_timestamp && (
          <span className="text-xs text-red-400/80">
            First discrepancy detected at entry from {format(new Date(data.broken_at_timestamp), 'yyyy-MM-dd HH:mm:ss')}.
            This view is read-only and cannot repair or rewrite history — escalate for investigation.
          </span>
        )}
      </div>
    </div>
  )
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

  const { data: logs = [], isLoading } = useQuery<AuditLog[]>({
    queryKey: ['audit-logs', actionFilter],
    queryFn: () => api.get('/api/audit-logs', { params: { limit: 200, action: actionFilter || undefined } }).then(r => r.data),
    refetchInterval: 30000,
  })

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <PageHeader title={<><ClipboardList aria-hidden="true" size={20} /> Audit Log</>} className="!mb-0" />
        <input
          placeholder="Filter by action..."
          className="px-2 py-1 text-sm bg-background border border-border rounded w-48"
          value={actionFilter}
          onChange={e => setActionFilter(e.target.value)}
        />
      </div>

      <ChainStatusPanel />

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading...</div>
      ) : logs.length === 0 ? (
        <div className="text-sm text-muted-foreground">No audit log entries found.</div>
      ) : (
        <div className="enterprise-panel rounded border border-border bg-card overflow-auto shadow-[0_0_0_1px_hsl(var(--primary)/0.06)]">
          <table className="w-full text-sm">
            <thead className="bg-muted text-muted-foreground">
              <tr>
                <th className="text-left px-4 py-2 font-semibold uppercase tracking-wider text-[11px] whitespace-nowrap">Time</th>
                <th className="text-left px-4 py-2 font-semibold uppercase tracking-wider text-[11px] whitespace-nowrap">Action</th>
                <th className="text-left px-4 py-2 font-semibold uppercase tracking-wider text-[11px] whitespace-nowrap">Resource</th>
                <th className="text-left px-4 py-2 font-semibold uppercase tracking-wider text-[11px] whitespace-nowrap">Actor</th>
                <th className="text-left px-4 py-2 font-semibold uppercase tracking-wider text-[11px] whitespace-nowrap">Detail</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log: AuditLog) => (
                <tr key={log.id} className="border-t border-border transition-colors hover:bg-white/[0.03]">
                  <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">
                    {format(new Date(log.created_at), 'yyyy-MM-dd HH:mm:ss')}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${actionColor(log.action)}`}>
                      {log.action}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">
                    {log.resource_type}
                    {log.resource_id && <span className="ml-1 opacity-60 text-xs">#{log.resource_id.slice(0, 8)}</span>}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground text-xs font-mono">
                    {log.actor_id ? log.actor_id.slice(0, 8) : `(${log.actor_type})`}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground text-xs max-w-xs truncate">
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
