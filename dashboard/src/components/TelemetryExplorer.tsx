import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { RefreshCw, Search, SlidersHorizontal } from 'lucide-react'
import { format } from 'date-fns'
import DataTable from '@/components/DataTable'
import type { Column } from '@/components/DataTable'
import QueryBuilder, { EMPTY_GROUP, isEmptyTree, type Group } from '@/components/QueryBuilder'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'
import { TelemetryDetails, type TelemetryRecord } from '@/components/TelemetryDetails'
import { useCursorPagination } from '@/hooks/useCursorPagination'
import { useTelemetryRecords } from '@/hooks/useTelemetryRecords'

type Kind = 'logs' | 'events'
const FIELDS: Readonly<Record<Kind, string[]>> = {
  logs: ['log_type', 'raw_message', 'agent_id', 'created_at', 'decoded_fields.source.ip', 'decoded_fields.user.name'],
  events: ['event_category', 'event_action', 'source_ip', 'user_name', 'group_id', 'created_at', 'decoded_fields.source.ip', 'decoded_fields.user.name'],
}

export default function TelemetryExplorer({ kind }: { readonly kind: Kind }) {
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const [draft, setDraft] = useState(search)
  const [showBuilder, setShowBuilder] = useState(false)
  const [tree, setTree] = useState<Group>(EMPTY_GROUP)
  const [applied, setApplied] = useState<Group>(EMPTY_GROUP)
  const [preferredPageSize, setPreferredPageSize] = useState(25)
  useEffect(() => { setDraft(search) }, [search])
  const filterTree = isEmptyTree(applied) ? undefined : JSON.stringify(applied)
  const updateSearch = (value: string) => setParams(current => {
    const next = new URLSearchParams(current)
    if (value.trim()) next.set('q', value.trim())
    else next.delete('q')
    return next
  })
  const clearFilters = () => { setDraft(''); updateSearch(''); setTree(EMPTY_GROUP); setApplied(EMPTY_GROUP) }
  return <div className="workspace">
    <PageHeader eyebrow="Investigation workspace" title={kind === 'logs' ? 'Raw logs' : 'Events'}
      description={kind === 'logs' ? 'Search original endpoint messages and inspect the full evidence.' : 'Investigate decoded activity, source addresses, and user context.'} />
    <section className="panel" aria-label="Telemetry search">
      <div className="panel__body space-y-3">
        <form className="telemetry-search" onSubmit={event => { event.preventDefault(); updateSearch(draft) }}>
          <label className="field"><span>Lucene query</span><input className="ui-input font-mono" value={draft} onChange={event => setDraft(event.target.value)}
            aria-describedby="telemetry-query-help" placeholder={kind === 'logs' ? 'log_type:linux_auth AND raw_message:"Failed password"' : 'event_action:login_failed AND user_name:root'} /></label>
          <button className="ui-button ui-button--primary" type="submit"><Search size={14} /> Search</button>
          <button className="ui-button" type="button" aria-expanded={showBuilder} aria-controls="telemetry-advanced-filters" onClick={() => setShowBuilder(value => !value)}><SlidersHorizontal size={14} /> Advanced filters</button>
        </form>
        <div className="filter-footer p-0"><span id="telemetry-query-help">Lucene field:value, AND / OR, and quoted phrases are supported. Press Enter to search.</span>
          {(search || filterTree) && <button className="ui-button ui-button--quiet" onClick={clearFilters}>Clear filters</button>}</div>
        {filterTree && <p className="text-xs text-muted-foreground mb-0">Advanced filters applied</p>}
      </div>
    </section>
    {showBuilder && <div id="telemetry-advanced-filters"><Panel title="Advanced filters" description="Combine conditions with AND / OR. Changes take effect only when applied.">
      <QueryBuilder node={tree} onChange={setTree} fields={FIELDS[kind]} />
      <div className="control-cluster mt-4"><button className="ui-button ui-button--primary" onClick={() => setApplied(tree)}>Apply filters</button>
        <button className="ui-button" onClick={() => { setTree(EMPTY_GROUP); setApplied(EMPTY_GROUP) }}>Reset advanced filters</button></div>
    </Panel></div>}
    <TelemetryResults key={JSON.stringify([kind, search, filterTree])} kind={kind} search={search} filterTree={filterTree}
      initialPageSize={preferredPageSize} onPageSizeChange={setPreferredPageSize} />
  </div>
}

function columnsFor(kind: Kind): readonly Column<TelemetryRecord>[] {
  const timestamp: Column<TelemetryRecord> = { key: 'timestamp', header: kind === 'logs' ? 'Received' : 'Created',
    render: row => { const value = 'raw_message' in row ? row.received_at : row.created_at
      return <time className="whitespace-nowrap" dateTime={value} title={value}>{format(new Date(value), 'dd MMM, HH:mm:ss')}</time> },
    exportValue: row => 'raw_message' in row ? row.received_at : row.created_at }
  return kind === 'logs' ? [timestamp,
    { key: 'log_type', header: 'Log type', render: row => 'raw_message' in row ? row.log_type ?? 'Unknown' : '—' },
    { key: 'raw_message', header: 'Message', render: row => <div className="telemetry-message font-mono">{'raw_message' in row ? row.raw_message : '—'}</div> },
    { key: 'agent_id', header: 'Agent ID', render: row => <span className="font-mono text-xs break-all">{row.agent_id ?? '—'}</span> },
  ] : [timestamp,
    { key: 'event_action', header: 'Activity', render: row => 'decoded_fields' in row ? <div className="table-primary">{row.event_action ?? 'Unknown activity'}<div className="table-secondary">{row.event_category ?? 'Uncategorized'}</div></div> : '—' },
    { key: 'source_ip', header: 'Source IP', render: row => <span className="font-mono">{'decoded_fields' in row ? row.source_ip ?? '—' : '—'}</span> },
    { key: 'user_name', header: 'User', render: row => 'decoded_fields' in row ? row.user_name ?? '—' : '—' },
    { key: 'group_id', header: 'Group', render: row => 'decoded_fields' in row ? row.group_id : '—' },
    { key: 'agent_id', header: 'Agent ID', hiddenByDefault: true, render: row => row.agent_id ?? '—' },
    { key: 'event_category', header: 'Category', hiddenByDefault: true, render: row => 'decoded_fields' in row ? row.event_category ?? '—' : '—' },
  ]
}

/** A new query remounts this boundary so old search_after cursors cannot leak. */
function TelemetryResults({ kind, search, filterTree, initialPageSize, onPageSizeChange }: {
  readonly kind: Kind; readonly search: string; readonly filterTree?: string
  readonly initialPageSize: number; readonly onPageSizeChange: (size: number) => void
}) {
  const pagination = useCursorPagination(initialPageSize)
  const { page, pageSize, after, onPageData, goToPage, changePageSize } = pagination
  const [selected, setSelected] = useState<TelemetryRecord | null>(null)
  const query = useTelemetryRecords<TelemetryRecord>(kind, pageSize, after, search || undefined, filterTree)
  useEffect(() => { if (!query.isPlaceholderData) onPageData(query.data?.next_after) }, [query.data?.next_after, query.isPlaceholderData, onPageData])
  const loading = query.isPending || query.isPlaceholderData
  return <section className="space-y-3 min-w-0" aria-label={`${kind === 'logs' ? 'Log' : 'Event'} results`}>
    <div className="filter-footer px-0"><span>{query.isFetching ? 'Updating results…' : query.isError ? 'Results unavailable' : `Updated ${format(new Date(query.dataUpdatedAt), 'HH:mm:ss')} · refreshes every 15 seconds`} · Open a row to inspect evidence</span>
      <button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh</button></div>
    {query.isError ? <section className="panel"><QueryState kind="error" title={`Could not load ${kind}`} description="Your query is preserved. Check the query syntax or connection and try again." onRetry={() => { void query.refetch() }} /></section>
      : loading ? <section className="panel"><QueryState kind="loading" title={`Loading ${kind}…`} description={`Fetching page ${page}.`} /></section>
        : <DataTable columns={columnsFor(kind)} data={query.data.items} total={query.data.total} page={page} pageSize={pageSize} onPageChange={goToPage}
          showPagination={false} onRowClick={setSelected} exportFilename={`${kind}-page.csv`} emptyTitle={`No ${kind} match this query`}
          emptyDescription={search || filterTree ? 'Try a wider query or clear the filters above.' : 'Check endpoint connectivity and configured log sources.'} />}
    <div className="table-pagination">
      <span>{!loading && !query.isError && query.data ? `${query.data.items.length} records on this page · ${query.data.total.toLocaleString()} matching` : 'Waiting for results'}</span>
      <div className="control-cluster"><select className="ui-input w-auto" aria-label="Results per page" value={pageSize} disabled={query.isFetching} onChange={event => {
        const size = Number(event.target.value)
        changePageSize(size)
        onPageSizeChange(size)
      }}>
        {[25, 50, 100].map(size => <option key={size} value={size}>{size} / page</option>)}</select>
        <button className="ui-button" disabled={page <= 1 || query.isFetching} onClick={() => goToPage(page - 1)}>Previous</button>
        <span className="tabular-nums">Page {page}</span>
        <button className="ui-button" disabled={query.isFetching || query.isError || !query.data?.next_after} onClick={() => goToPage(page + 1)}>Next</button>
      </div>
    </div>
    {selected && <TelemetryDetails record={selected} onClose={() => setSelected(null)} />}
  </section>
}
