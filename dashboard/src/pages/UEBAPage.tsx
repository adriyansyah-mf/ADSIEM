import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import DataTable, { type Column } from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'
import { UebaRisk } from '@/components/UebaRisk'
import { UebaEntityDetails } from '@/components/UebaEntityDetails'
import { useUebaEntities, useUebaStatus } from '@/hooks/useUeba'
import type { UebaEntityScore } from '@/types'

type EntityRow = UebaEntityScore & { readonly id: string }

function ModelStatus() {
  const query = useUebaStatus()
  return <section aria-label="Detection model"><Panel title="Detection model" description="Model readiness and collected observations are separate from entity risk.">
    {query.isPending ? <QueryState kind="loading" title="Loading model status…" />
      : query.isError ? <QueryState kind="error" title="Could not load model status" description="Model readiness and snapshot counts are unavailable. This does not mean the model is still collecting data." onRetry={() => { void query.refetch() }} />
        : <div className="space-y-4">
          <div className="control-cluster"><StatusBadge status={query.data.status === 'ready' ? 'ready' : 'collecting_data'} />
            {query.data.trained_at && <span className="text-xs text-muted-foreground">Trained <time dateTime={query.data.trained_at}>{format(new Date(query.data.trained_at), 'dd MMM yyyy, HH:mm')}</time></span>}</div>
          {query.data.status === 'cold' && <p className="text-sm text-muted-foreground">Collecting baseline data</p>}
          <dl className="ueba-model-stats"><div><dt>User snapshots</dt><dd>{query.data.user_snapshot_count.toLocaleString()}</dd></div>
            <div><dt>IP snapshots</dt><dd>{query.data.ip_snapshot_count.toLocaleString()}</dd></div></dl>
          <p className="text-xs text-muted-foreground mb-0">Snapshots are collected observations, not elapsed hours or an estimated training completion time.</p>
        </div>}
  </Panel></section>
}

export default function UEBAPage() {
  const [entityType, setEntityType] = useState<'user' | 'ip'>('user')
  const [minRisk, setMinRisk] = useState(0)
  const [selected, setSelected] = useState<EntityRow | null>(null)
  const query = useUebaEntities(entityType, minRisk)
  const rows = query.data?.map(entity => ({ ...entity, id: JSON.stringify([entity.entity_type, entity.entity_value, entity.group_id]) })) ?? []
  const columns: readonly Column<EntityRow>[] = [
    { key: 'entity_value', header: 'Entity', render: row => <span className="table-primary block font-mono text-xs">{row.entity_value}</span> },
    { key: 'risk_score', header: 'Risk score', render: row => <UebaRisk score={row.risk_score} /> },
    { key: 'anomaly_count', header: 'Anomalies', render: row => <span className="tabular-nums">{row.anomaly_count}</span> },
    { key: 'last_seen_at', header: 'Last seen', render: row => row.last_seen_at ? <time className="whitespace-nowrap" dateTime={row.last_seen_at}>{format(new Date(row.last_seen_at), 'dd MMM, HH:mm')}</time> : 'Not recorded' },
    { key: 'group_id', header: 'Group', hiddenByDefault: true, render: row => row.group_id },
  ]
  return <div className="workspace">
    <PageHeader eyebrow="Behavior intelligence" title="Behavior analytics" description="Prioritize anomalous users and IP addresses, then examine the evidence behind each risk score."
      actions={<button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh entities</button>} />
    <ModelStatus />
    <section className="panel" aria-label="Entity filters"><div className="ueba-filters">
      <label className="field"><span>Entity type</span><select className="ui-input" value={entityType} onChange={event => {
        setEntityType(event.target.value === 'ip' ? 'ip' : 'user'); setSelected(null)
      }}><option value="user">Users</option><option value="ip">IP addresses</option></select></label>
      <label className="field"><span>Minimum risk</span><select className="ui-input" value={minRisk} onChange={event => { setMinRisk(Number(event.target.value)); setSelected(null) }}>
        <option value={0}>All risk scores</option><option value={40}>40 and above</option><option value={60}>60 and above</option><option value={80}>80 and above</option></select></label>
    </div><div className="filter-footer"><span>{query.isFetching ? 'Updating entities…' : query.isError ? 'Entity results unavailable' : `Showing ${rows.length} ${entityType === 'user' ? 'user' : 'IP'} ${rows.length === 1 ? 'entity' : 'entities'}`} · Up to 50 highest-risk matches · refreshes every 30 seconds · Open a row for evidence</span></div></section>
    {query.isPending ? <section className="panel"><QueryState kind="loading" title="Loading entities…" /></section>
      : query.isError ? <section className="panel"><QueryState kind="error" title="Could not load entities" description="Your entity and risk filters are preserved." onRetry={() => { void query.refetch() }} /></section>
        : <DataTable columns={columns} data={rows} total={rows.length} page={1} pageSize={50} onPageChange={() => {}} showPagination={false}
          onRowClick={setSelected} exportFilename={`ueba-${entityType}-entities.csv`} emptyTitle="No entities match this view" emptyDescription="Try a lower minimum risk, switch entity type, or wait for more endpoint observations." />}
    {selected && <UebaEntityDetails entityType={selected.entity_type} entityValue={selected.entity_value} onClose={() => setSelected(null)} />}
  </div>
}
