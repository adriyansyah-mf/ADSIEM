import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, RefreshCw } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import DataTable from '@/components/DataTable'
import type { Column } from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { PageHeader, QueryState } from '@/components/Workspace'
import { AgentActions } from '@/components/AgentActions'
import DeployAgentModal from '@/components/DeployAgentModal'
import { EvidenceBadge, EvidenceHealthPanel } from '@/components/EvidenceHealth'
import { useAgents } from '@/hooks/useAgents'
import { useWorkspaceFilters } from '@/hooks/useWorkspaceFilters'
import { useAuthStore } from '@/stores/auth'
import type { Agent } from '@/types'

export default function AgentsPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [showInstall, setShowInstall] = useState(false)
  const filters = useWorkspaceFilters()
  const { params, update } = filters
  const search = params.get('search') ?? ''
  const status = params.get('status') ?? ''
  const query = useAgents(page, pageSize, search, status)
  const canManage = useAuthStore(state => state.hasRole('admin'))
  const navigate = useNavigate()
  useEffect(() => { setPage(1) }, [params])
  const columns: readonly Column<Agent>[] = [
    { key: 'name', header: 'Endpoint', render: row => <div className="table-primary">{row.name}<div className="table-secondary font-mono">{row.hostname}</div></div> },
    { key: 'group_id', header: 'Group', render: row => row.group_id },
    { key: 'status', header: 'State', render: row => <div className="control-cluster">
      <StatusBadge status={row.status} />{row.approved === false && <StatusBadge status="pending_approval" />}{row.is_isolated && <StatusBadge status="isolated" />}
    </div> },
    { key: 'evidence', header: 'Evidence delivery', render: row => <EvidenceBadge summary={row.evidence} />,
      exportValue: row => row.evidence?.status ?? 'not_reported' },
    { key: 'version', header: 'Version', render: row => <span className="font-mono">{row.version ?? '—'}</span> },
    { key: 'last_seen_at', header: 'Last seen', render: row => row.last_seen_at ? <time className="whitespace-nowrap" dateTime={row.last_seen_at} title={new Date(row.last_seen_at).toLocaleString()}>{formatDistanceToNow(new Date(row.last_seen_at), { addSuffix: true })}</time> : 'Never' },
    { key: 'sources', header: 'Log sources', render: row => row.log_sources.length, exportValue: row => row.log_sources.length },
  ]
  return <div className="workspace">
    <PageHeader eyebrow="Environment" title="Agents" description="Monitor endpoint connectivity, enrollment, and containment."
      actions={<><button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh</button>
        {canManage && <button className="ui-button ui-button--primary" onClick={() => setShowInstall(true)}><Plus size={16} /> Deploy agent</button>}</>} />
    <section className="panel" aria-label="Agent filters">
      <div className="filter-bar filter-bar--short">
        <label className="field"><span>Search endpoints</span><input className="ui-input" value={filters.searchInput} placeholder="Search name or hostname…" onChange={event => filters.setSearchInput(event.target.value)} /></label>
        <label className="field"><span>Connection status</span><select className="ui-input" value={status} onChange={event => update({ status: event.target.value })}>
          <option value="">All statuses</option><option value="online">Online</option><option value="offline">Offline</option>
        </select></label>
      </div>
      <div className="filter-footer"><span>{query.isFetching ? 'Updating endpoints…' : query.data ? `${query.data.total.toLocaleString()} matching agents · refreshes every 30 seconds` : 'Waiting for endpoint data'}
        {canManage && ' · Expand for response actions; open a row for log sources'}</span>{(search || status) && <button className="ui-button ui-button--quiet" onClick={filters.clear}>Clear filters</button>}</div>
    </section>
    {query.isPending ? <section className="panel"><QueryState kind="loading" title="Loading agents…" /></section>
      : query.isError ? <section className="panel"><QueryState kind="error" title="Could not load agents" description="Endpoint state is unavailable. Your filters are preserved." onRetry={() => { void query.refetch() }} /></section>
        : <DataTable columns={columns} data={query.data.items} total={query.data.total} page={page} pageSize={pageSize}
          onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1) }}
          onRowClick={canManage ? row => navigate(`/agents/${row.id}/sources`) : undefined}
          expandable={canManage} renderExpanded={row => <div className="space-y-4">
            <AgentActions agent={row} />
            <EvidenceHealthPanel agent={row} canManage={canManage} />
          </div>}
          exportFilename="agents-page.csv" emptyTitle="No agents match this view" emptyDescription={search || status ? 'Try a different hostname or clear the filters.' : canManage ? 'Deploy an agent to start collecting endpoint telemetry.' : 'An administrator can deploy agents for this group.'} />}
    {showInstall && <DeployAgentModal onClose={() => setShowInstall(false)} />}
  </div>
}
