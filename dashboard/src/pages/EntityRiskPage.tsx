import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { api } from '@/api/client'
import DataTable, { type Column } from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import { PageHeader, QueryState } from '@/components/Workspace'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { UebaRisk } from '@/components/UebaRisk'

type EntityType = 'all' | 'host' | 'user'

interface RiskEntity {
  entity_type: 'host' | 'user'
  entity_value: string
  group_id: string
  risk_score: number
  peak_score: number
  alert_count: number
  tactics: string[]
  sources: Record<string, number>
  last_alert_at: string | null
  risk_alert_at: string | null
  top_alert?: string | null
}

interface Contribution { alert_id: string; title: string; severity: string; source: string; tactics: string[]; at: string; points: number }
type RiskDetail = RiskEntity & { recent: Contribution[] }
type Row = RiskEntity & { readonly id: string }

const SOURCE_LABEL: Record<string, string> = {
  sigma: 'Sigma', ioa: 'IOA', ioc: 'IoC', behavior: 'Behaviour', ueba: 'UEBA', yara: 'YARA', malware: 'Malware',
  agent_tamper: 'Tamper', network_ids: 'Network IDS', app_control: 'App Control',
}
const label = (t: string) => t.replace(/_/g, ' ')

function Tactics({ tactics }: { readonly tactics: string[] }) {
  if (!tactics.length) return <span className="text-xs text-muted-foreground">none in 24 h</span>
  return <div className="flex flex-wrap gap-1">{tactics.map(t =>
    <span key={t} className="rounded border border-border px-1.5 py-0.5 text-[11px] capitalize">{label(t)}</span>)}</div>
}

function Detail({ row, onClose }: { readonly row: Row; readonly onClose: () => void }) {
  const query = useQuery<RiskDetail>({
    queryKey: ['entity-risk', row.entity_type, row.entity_value, row.group_id],
    queryFn: () => api.get(`/api/entity-risk/${row.entity_type}/${encodeURIComponent(row.entity_value)}`,
      { params: { group_id: row.group_id } }).then(r => r.data),
  })
  return <WorkspaceDialog title={`${row.entity_type === 'host' ? 'Host' : 'User'} · ${row.entity_value}`}
    description="The alerts that built this risk score, newest first" onClose={onClose} wide>
    {query.isPending ? <QueryState kind="loading" title="Loading contributions…" />
      : query.isError ? <QueryState kind="error" title="Could not load this entity" onRetry={() => { void query.refetch() }} />
        : <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <UebaRisk score={query.data.risk_score} />
            <span className="text-muted-foreground">peak {query.data.peak_score.toFixed(0)} · {query.data.alert_count} alerts</span>
            <Tactics tactics={query.data.tactics} />
          </div>
          <div className="table-scroll"><table className="data-table">
            <thead><tr><th className="p-2 text-left">When</th><th className="p-2 text-left">Alert</th><th className="p-2 text-left">Source</th><th className="p-2 text-right">Risk added</th></tr></thead>
            <tbody>{query.data.recent.map(c => <tr key={`${c.alert_id}-${c.at}`}>
              <td className="p-2 whitespace-nowrap text-xs">{formatDistanceToNow(new Date(c.at), { addSuffix: true })}</td>
              <td className="p-2"><div className="flex items-center gap-2"><SeverityBadge severity={c.severity} />
                <Link to={`/alerts/${c.alert_id}`} className="underline">{c.title}</Link></div>
                {c.tactics.length > 0 && <div className="text-[11px] text-muted-foreground capitalize mt-0.5">{c.tactics.map(label).join(', ')}</div>}</td>
              <td className="p-2 text-xs">{SOURCE_LABEL[c.source] ?? c.source}</td>
              <td className="p-2 text-right tabular-nums">+{c.points}</td>
            </tr>)}</tbody>
          </table></div>
          <p className="text-xs text-muted-foreground">Each alert adds points by severity (low 5, medium 15, high 30, critical 50), plus 10 for a tactic new in the last 24 h. The score halves every 24 h without new alerts.</p>
        </div>}
  </WorkspaceDialog>
}

export default function EntityRiskPage() {
  const [entityType, setEntityType] = useState<EntityType>('all')
  const [minRisk, setMinRisk] = useState(1)
  const [selected, setSelected] = useState<Row | null>(null)
  const query = useQuery<{ items: RiskEntity[] }>({
    queryKey: ['entity-risk', entityType, minRisk],
    queryFn: () => api.get('/api/entity-risk', { params: { entity_type: entityType, min_risk: minRisk, limit: 100 } }).then(r => r.data),
    refetchInterval: 30_000,
  })
  const rows: Row[] = (query.data?.items ?? []).map(e => ({ ...e, id: `${e.entity_type}|${e.entity_value}|${e.group_id}` }))
  const columns: readonly Column<Row>[] = [
    { key: 'entity_value', header: 'Entity', render: r => <div className="table-primary">{r.entity_value}
      <div className="table-secondary">{r.entity_type === 'host' ? 'Host' : 'User'}</div></div> },
    { key: 'risk_score', header: 'Risk', render: r => <UebaRisk score={r.risk_score} />, exportValue: r => r.risk_score },
    { key: 'tactics', header: 'Tactics (24 h)', render: r => <Tactics tactics={r.tactics} />, exportValue: r => r.tactics.join(' ') },
    { key: 'sources', header: 'Sources', render: r => <span className="text-xs">{Object.entries(r.sources).map(([s, n]) => `${SOURCE_LABEL[s] ?? s} ${n}`).join(' · ')}</span>,
      exportValue: r => JSON.stringify(r.sources) },
    { key: 'top_alert', header: 'Latest alert', render: r => <span className="text-xs">{r.top_alert ?? '—'}</span> },
    { key: 'last_alert_at', header: 'Last alert', render: r => r.last_alert_at ? <time className="whitespace-nowrap text-xs" dateTime={r.last_alert_at}>{formatDistanceToNow(new Date(r.last_alert_at), { addSuffix: true })}</time> : '—' },
    { key: 'group_id', header: 'Group', hiddenByDefault: true, render: r => r.group_id },
  ]
  return <div className="workspace">
    <PageHeader eyebrow="Behavior intelligence" title="Entity risk"
      description="Hosts and users ranked by the alerts they collected across every detection source. A [Risk] alert is raised when one reaches the threshold across two or more tactics."
      actions={<button className="ui-button" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={14} /> Refresh</button>} />
    <section className="panel" aria-label="Filters"><div className="ueba-filters">
      <label className="field"><span>Entity type</span><select className="ui-input" value={entityType} onChange={e => { setEntityType(e.target.value as EntityType); setSelected(null) }}>
        <option value="all">Hosts and users</option><option value="host">Hosts</option><option value="user">Users</option></select></label>
      <label className="field"><span>Minimum risk</span><select className="ui-input" value={minRisk} onChange={e => { setMinRisk(Number(e.target.value)); setSelected(null) }}>
        <option value={1}>Any risk</option><option value={40}>40 and above</option><option value={70}>70 and above</option><option value={90}>90 and above</option></select></label>
    </div></section>
    {query.isPending ? <section className="panel"><QueryState kind="loading" title="Loading entities…" /></section>
      : query.isError ? <section className="panel"><QueryState kind="error" title="Could not load entity risk" onRetry={() => { void query.refetch() }} /></section>
        : <DataTable columns={columns} data={rows} total={rows.length} page={1} pageSize={100} onPageChange={() => {}} showPagination={false}
          onRowClick={setSelected} exportFilename="entity-risk.csv" emptyTitle="No entity carries risk right now"
          emptyDescription="Risk builds as alerts arrive and halves every 24 hours." />}
    {selected && <Detail row={selected} onClose={() => setSelected(null)} />}
  </div>
}
