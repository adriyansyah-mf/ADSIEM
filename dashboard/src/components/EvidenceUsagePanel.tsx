import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Panel, QueryState } from '@/components/Workspace'

interface EvidenceUsage {
  readonly budget_bytes: number
  readonly groups: readonly {
    readonly group_id: string
    readonly payload_bytes: number
    readonly percent: number
    readonly full: boolean
    readonly top_hosts: readonly { readonly hostname: string; readonly payload_bytes: number }[]
  }[]
}

export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1 }
  return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`
}

export default function EvidenceUsagePanel() {
  const usage = useQuery<EvidenceUsage>({
    queryKey: ['evidence-usage'],
    queryFn: () => api.get('/api/evidence/usage').then(r => r.data),
    refetchInterval: 60_000,
  })
  return (
    <Panel title="Evidence storage per group">
      <p className="table-secondary evidence-usage__intro">
        When a group reaches its budget, agents keep sending alerts but new evidence files are rejected (HTTP 429).
        The budget is set by <code>EVIDENCE_GROUP_BUDGET_BYTES</code> on the server.
      </p>
      {usage.isPending ? <QueryState kind="loading" title="Loading evidence usage…" />
        : usage.isError ? <QueryState kind="error" title="Could not load evidence usage" onRetry={() => { void usage.refetch() }} />
        : usage.data.groups.length === 0 ? <QueryState kind="empty" title="No evidence stored yet" description="Usage appears once agents deliver evidence." />
        : <div className="evidence-usage">
          <table>
            <thead><tr><th>Group</th><th>Usage</th><th>Budget</th><th>Largest sources</th></tr></thead>
            <tbody>{usage.data.groups.map(group => (
              <tr key={group.group_id}>
                <td className="table-primary">{group.group_id}</td>
                <td>
                  <div className="evidence-usage__meter" role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={group.percent}
                    aria-label={`${group.group_id} evidence usage`}>
                    <span className="evidence-usage__track"><span className={`evidence-usage__fill ${group.percent >= 90 ? 'is-full' : group.percent >= 70 ? 'is-high' : ''}`}
                      style={{ width: `${group.percent}%` }} /></span>
                    <span className={group.full ? 'evidence-usage__full' : undefined}>
                      {formatBytes(group.payload_bytes)} · {group.percent}%{group.full ? ' · full, new evidence rejected' : ''}</span>
                  </div>
                </td>
                <td className="font-mono">{formatBytes(usage.data.budget_bytes)}</td>
                <td className="table-secondary">{group.top_hosts.length
                  ? group.top_hosts.map(host => `${host.hostname} (${formatBytes(host.payload_bytes)})`).join(', ') : '—'}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>}
    </Panel>
  )
}
