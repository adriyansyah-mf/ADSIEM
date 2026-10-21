import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bot, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import DataTable from '@/components/DataTable'
import type { Column } from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import { PageHeader, QueryState } from '@/components/Workspace'
import { TimeRangeFilter } from '@/components/TimeRangeSelect'
import { useCases } from '@/hooks/useCases'
import { useWorkspaceFilters } from '@/hooks/useWorkspaceFilters'
import { useAuthStore } from '@/stores/auth'
import { CaseQuickActions } from '@/components/CaseQuickActions'
import type { Case } from '@/types'

export default function CasesPage() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const filters = useWorkspaceFilters()
  const { params, update } = filters
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  const userId = useAuthStore(state => state.user?.id)
  useEffect(() => { setPage(1) }, [params])
  const value = (key: string) => params.get(key) ?? ''
  const query = useCases(page, {
    status: value('status') || undefined, severity: value('severity') || undefined,
    hostname: value('hostname') || undefined, search: value('search') || undefined,
    start_time: value('start_time') || undefined, end_time: value('end_time') || undefined,
  })
  const columns: readonly Column<Case>[] = [
    { key: 'severity', header: 'Severity', render: row => <SeverityBadge severity={row.severity} /> },
    { key: 'title', header: 'Case', render: row => <div className="table-primary">{row.title}
      <div className="table-secondary line-clamp-2">{row.description || row.ai_reasoning || 'No summary provided'}</div>
      {row.created_by_ai && <span className="control-cluster table-secondary mt-1"><Bot size={12} /> AI-created case</span>}
    </div> },
    { key: 'status', header: 'Status', render: row => <StatusBadge status={row.status} /> },
    { key: 'assignee_id', header: 'Assigned to', render: row => row.assignee_id === userId ? 'You' : row.assignee_id ? <span className="font-mono text-xs break-all">{row.assignee_id}</span> : <span className="text-muted-foreground">Unassigned</span> },
    { key: 'created_at', header: 'Created', render: row => <time dateTime={row.created_at} className="whitespace-nowrap">{format(new Date(row.created_at), 'dd MMM, HH:mm')}</time> },
    { key: 'group_id', header: 'Group', hiddenByDefault: true, render: row => row.group_id },
    { key: 'alert_id', header: 'Alert ID', hiddenByDefault: true, render: row => row.alert_id ?? '—' },
  ]
  const active = ['search', 'hostname', 'status', 'severity', 'start_time', 'end_time'].some(key => value(key))
  return <div className="workspace">
    <PageHeader eyebrow="Investigations" title="Cases" description="Manage investigations, ownership, and response decisions."
      actions={<button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh</button>} />
    <section className="panel" aria-label="Case filters">
      <div className="filter-bar">
        <label className="field"><span>Search cases</span><input className="ui-input" value={filters.searchInput} placeholder="Search title or description…" onChange={event => filters.setSearchInput(event.target.value)} /></label>
        <label className="field"><span>Hostname</span><input className="ui-input" value={value('hostname')} placeholder="Any hostname" onChange={event => update({ hostname: event.target.value })} /></label>
        <label className="field"><span>Severity</span><select className="ui-input" value={value('severity')} onChange={event => update({ severity: event.target.value })}>
          <option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info'].map(item => <option key={item} value={item}>{item.charAt(0).toUpperCase() + item.slice(1)}</option>)}
        </select></label>
        <label className="field"><span>Status</span><select className="ui-input" value={value('status')} onChange={event => update({ status: event.target.value })}>
          <option value="">All statuses</option><option value="open">Open</option><option value="in_review">In review</option><option value="escalated">Escalated</option><option value="resolved">Resolved</option><option value="closed">Closed</option>
        </select></label>
        <div className="field"><span>Time window</span><TimeRangeFilter value={{ start_time: value('start_time') || undefined, end_time: value('end_time') || undefined }}
          onChange={range => update({ start_time: range.start_time ?? '', end_time: range.end_time ?? '' })} selectClassName="ui-input" inputClassName="ui-input" /></div>
      </div>
      <div className="filter-footer"><span>{query.isFetching ? 'Updating cases…' : query.data ? `${query.data.total.toLocaleString()} matching cases · refreshes every 15 seconds` : 'Waiting for case data'}
        {canManage && ' · Expand a row for quick actions'}</span>{active && <button className="ui-button ui-button--quiet" onClick={filters.clear}>Clear filters</button>}</div>
    </section>
    {query.isPending ? <section className="panel"><QueryState kind="loading" title="Loading cases…" /></section>
      : query.isError ? <section className="panel"><QueryState kind="error" title="Could not load cases" description="Your filters are preserved. Try again when the connection is available." onRetry={() => { void query.refetch() }} /></section>
      : <DataTable columns={columns} data={query.data.items} total={query.data.total} page={page} pageSize={25} onPageChange={setPage}
        onRowClick={row => navigate(`/cases/${row.id}`)} expandable={canManage} renderExpanded={row => <CaseQuickActions caseData={row} />}
        exportFilename="cases-page.csv" emptyTitle="No cases match this view" emptyDescription={active ? 'Widen the filters or clear them to see more investigations.' : 'Open an alert and create a case to start an investigation.'} />}
  </div>
}
