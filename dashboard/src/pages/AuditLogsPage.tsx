import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { format } from 'date-fns'

interface AuditLog {
  id: string
  actor_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  detail: Record<string, unknown>
  created_at: string
}

interface Paginated { total: number; page: number; page_size: number; items: AuditLog[] }

export default function AuditLogsPage() {
  const [page, setPage] = useState(1)
  const [actionFilter, setActionFilter] = useState('')
  const [resourceFilter, setResourceFilter] = useState('')

  const { data, isLoading } = useQuery<Paginated>({
    queryKey: ['audit-logs', page, actionFilter, resourceFilter],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), page_size: '50' })
      if (actionFilter) params.set('action', actionFilter)
      if (resourceFilter) params.set('resource_type', resourceFilter)
      return api.get(`/api/audit-logs?${params}`).then(r => r.data)
    },
  })

  const totalPages = data ? Math.ceil(data.total / data.page_size) : 1

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Audit Log</h1>
        <span className="text-sm text-muted-foreground">{data?.total ?? 0} entries</span>
      </div>

      <div className="flex gap-3 mb-4">
        <input placeholder="Filter by action…" value={actionFilter}
          onChange={e => { setActionFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm w-52" />
        <input placeholder="Filter by resource type…" value={resourceFilter}
          onChange={e => { setResourceFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm w-52" />
      </div>

      {isLoading ? (
        <p className="text-muted-foreground text-sm">Loading…</p>
      ) : (
        <div className="rounded border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted text-muted-foreground text-xs uppercase">
              <tr>
                <th className="px-4 py-2 text-left">Time</th>
                <th className="px-4 py-2 text-left">Action</th>
                <th className="px-4 py-2 text-left">Resource</th>
                <th className="px-4 py-2 text-left">Resource ID</th>
                <th className="px-4 py-2 text-left">Detail</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map(log => (
                <tr key={log.id} className="border-t border-border hover:bg-muted/30">
                  <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">
                    {format(new Date(log.created_at), 'yyyy-MM-dd HH:mm:ss')}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">{log.action}</td>
                  <td className="px-4 py-2 text-muted-foreground">{log.resource_type ?? '—'}</td>
                  <td className="px-4 py-2 text-muted-foreground font-mono text-xs truncate max-w-[120px]">
                    {log.resource_id ? log.resource_id.slice(0, 8) + '…' : '—'}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground text-xs truncate max-w-[200px]">
                    {Object.keys(log.detail).length > 0 ? JSON.stringify(log.detail) : '—'}
                  </td>
                </tr>
              ))}
              {(data?.items ?? []).length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">No audit log entries.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-4">
          <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
            className="px-3 py-1 rounded border border-border text-sm disabled:opacity-40 hover:bg-muted">Prev</button>
          <span className="px-3 py-1 text-sm text-muted-foreground">{page} / {totalPages}</span>
          <button disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
            className="px-3 py-1 rounded border border-border text-sm disabled:opacity-40 hover:bg-muted">Next</button>
        </div>
      )}
    </div>
  )
}
