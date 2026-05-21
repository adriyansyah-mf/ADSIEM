import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useAgents } from '@/hooks/useAgents'
import { useAuthStore } from '@/stores/auth'
import { formatDistanceToNow } from 'date-fns'
import type { Agent } from '@/types'

export default function AgentsPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useAgents(page)
  const { hasRole } = useAuthStore()
  const navigate = useNavigate()

  const columns = [
    { key: 'name', header: 'Name', render: (r: Agent) => r.name },
    { key: 'hostname', header: 'Hostname', render: (r: Agent) => r.hostname },
    { key: 'group', header: 'Group', render: (r: Agent) => r.group_id },
    { key: 'status', header: 'Status', render: (r: Agent) => <StatusBadge status={r.status} /> },
    { key: 'version', header: 'Version', render: (r: Agent) => r.version ?? '—' },
    { key: 'last_seen', header: 'Last Seen', render: (r: Agent) =>
      r.last_seen_at ? formatDistanceToNow(new Date(r.last_seen_at), { addSuffix: true }) : 'Never'
    },
    { key: 'sources', header: 'Sources', render: (r: Agent) => r.log_sources.length },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Agents</h1>
      {isLoading ? (
        <div className="text-muted-foreground">Loading...</div>
      ) : (
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          total={data?.total ?? 0}
          page={page}
          pageSize={25}
          onPageChange={setPage}
          onRowClick={hasRole('admin') ? (r) => navigate(`/agents/${r.id}/sources`) : undefined}
        />
      )}
    </div>
  )
}
