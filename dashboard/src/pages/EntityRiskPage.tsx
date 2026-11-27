import { useMemo } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNowStrict } from 'date-fns'
import { api } from '@/api/client'
import { useUebaEntityDetail, useUebaRiskHistory } from '@/hooks/useUeba'
import { CanvasHeader, CanvasPage, Chip, Empty, Meter, SectionTitle, Seg, Spark, severityTone, type Tone } from '@/components/canvas/Canvas'

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

const SOURCE_LABEL: Record<string, string> = {
  sigma: 'Sigma', ioa: 'IOA', ioc: 'IoC', behavior: 'Behaviour', ueba: 'UEBA', yara: 'YARA', malware: 'Malware',
  agent_tamper: 'Tamper', network_ids: 'Network IDS', app_control: 'App Control',
}
const label = (text: string) => text.replace(/_/g, ' ')

function riskTone(score: number): Tone {
  return score >= 70 ? 'bad' : score >= 40 ? 'warn' : 'info'
}

function keyOf(entity: Pick<RiskEntity, 'entity_type' | 'entity_value' | 'group_id'>) {
  return `${entity.entity_type}|${entity.entity_value}|${entity.group_id}`
}

export default function EntityRiskPage() {
  const [params, setParams] = useSearchParams()
  const entityType = (['all', 'host', 'user'].includes(params.get('type') ?? '') ? params.get('type') : 'all') as EntityType
  const minRisk = Number(params.get('min') ?? 1) || 1
  const patch = (changes: Record<string, string | null>) => setParams(current => {
    const next = new URLSearchParams(current)
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value)
      else next.delete(key)
    }
    return next
  }, { replace: true })

  const query = useQuery<{ items: RiskEntity[] }>({
    queryKey: ['entity-risk', entityType, minRisk],
    queryFn: () => api.get('/api/entity-risk', { params: { entity_type: entityType, min_risk: minRisk, limit: 100 } }).then(r => r.data),
    refetchInterval: 30_000,
  })
  const lateral = useQuery<number>({
    queryKey: ['lateral', 'count'],
    queryFn: () => api.get('/api/lateral/graph', { params: { hours: 24 } }).then(r => Array.isArray(r.data?.edges) ? r.data.edges.length : 0),
    retry: false,
    staleTime: 60_000,
  })
  const rows = query.data?.items ?? []
  const selected = rows.find(row => keyOf(row) === params.get('entity')) ?? rows[0] ?? null

  return (
    <CanvasPage>
      <CanvasHeader
        title="Entities & risk"
        sub="Risk scores add up the alerts each host and user collected across every detection source · a score halves every 24 h without new alerts"
        counts={{ '/lateral': lateral.data || null }}
      >
        <div className="cv-row">
          <Seg label="Entity type" value={entityType} onChange={value => patch({ type: value === 'all' ? null : value, entity: null })}
            options={[{ value: 'user', label: 'Users' }, { value: 'host', label: 'Hosts' }, { value: 'all', label: 'All' }]} />
          <select className="cv-select" aria-label="Minimum risk" value={minRisk} onChange={event => patch({ min: event.target.value === '1' ? null : event.target.value, entity: null })}>
            <option value={1}>Any risk</option><option value={40}>Risk 40+</option><option value={70}>Risk 70+</option><option value={90}>Risk 90+</option>
          </select>
          <span className="cv-muted cv-small">{query.isFetching ? 'Updating…' : `${rows.length} entities`}</span>
        </div>
      </CanvasHeader>

      <div className="cv-split">
        <section className="cv-pane" aria-label="Risk ranking" style={{ flex: '999 1 560px' }}>
          <div className="cv-tablewrap">
            <table className="cv-table" style={{ minWidth: 680 }}>
              <thead><tr><th>#</th><th>{entityType === 'host' ? 'Host' : entityType === 'user' ? 'User' : 'Entity'}</th><th>Risk</th><th>Tactics (24 h)</th><th>Top factor</th><th>Last alert</th></tr></thead>
              <tbody>
                {rows.map((row, index) => {
                  const active = selected && keyOf(row) === keyOf(selected)
                  const sources = Object.entries(row.sources).sort((a, b) => b[1] - a[1])
                  return (
                    <tr key={keyOf(row)} className={active ? 'is-active' : undefined} style={{ cursor: 'pointer' }} onClick={() => patch({ entity: keyOf(row) })}>
                      <td className="cv-muted">{index + 1}</td>
                      <td>
                        <div className="cv-stack">
                          <button type="button" className="cv-rowlink cv-mono" style={{ fontSize: 13 }} onClick={() => patch({ entity: keyOf(row) })}>{row.entity_value}</button>
                          <span className="cv-muted cv-small">{row.entity_type === 'host' ? 'Host' : 'User'}{row.group_id !== 'default' ? ` · ${row.group_id}` : ''}{sources[0] ? ` · ${sources.map(([s, n]) => `${SOURCE_LABEL[s] ?? s} ${n}`).slice(0, 2).join(', ')}` : ''}</span>
                        </div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <Chip tone={riskTone(row.risk_score)}>{Math.round(row.risk_score)}</Chip>{' '}
                        <span className="cv-small cv-muted">peak {Math.round(row.peak_score)}</span>
                      </td>
                      <td className="cv-small" style={{ textTransform: 'capitalize' }}>{row.tactics.length ? row.tactics.map(label).join(', ') : <span className="cv-muted">none</span>}</td>
                      <td className="cv-dim" style={{ overflowWrap: 'anywhere' }}>{row.top_alert ?? '—'}</td>
                      <td className="cv-small cv-dim" style={{ whiteSpace: 'nowrap' }}>{row.last_alert_at ? `${formatDistanceToNowStrict(new Date(row.last_alert_at))} ago` : '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {query.isPending && <Empty>Loading entities…</Empty>}
            {query.isError && <Empty>Could not load entity risk.</Empty>}
            {!query.isPending && !query.isError && rows.length === 0 && <Empty>No entity carries risk right now. Risk builds as alerts arrive.</Empty>}
          </div>
          <p className="cv-muted cv-small" style={{ margin: 0 }}>
            Each alert adds points by severity (low 5, medium 15, high 30, critical 50), plus 10 for a tactic new in the last 24 h.
            A [Risk] alert is raised when an entity crosses the threshold across two or more tactics.
          </p>
        </section>

        <aside className="cv-list" aria-label="Risk breakdown" style={{ flex: '1 1 340px', maxWidth: 400, borderRight: 0, borderLeft: '1px solid #222733', padding: '16px 20px', gap: 14 }}>
          {selected ? <Breakdown entity={selected} /> : <Empty>Select an entity to see what makes up its score.</Empty>}
        </aside>
      </div>
    </CanvasPage>
  )
}

function Breakdown({ entity }: { readonly entity: RiskEntity }) {
  const detail = useQuery<RiskDetail>({
    queryKey: ['entity-risk', entity.entity_type, entity.entity_value, entity.group_id],
    queryFn: () => api.get(`/api/entity-risk/${entity.entity_type}/${encodeURIComponent(entity.entity_value)}`,
      { params: { group_id: entity.group_id } }).then(r => r.data),
  })
  const ueba = useUebaEntityDetail(entity.entity_type, entity.entity_value)
  const history = useUebaRiskHistory(entity.entity_type, entity.entity_value)
  const contributions = detail.data?.recent ?? []
  // Group contributions by alert title, largest first: "what makes up the score".
  const factors = useMemo(() => {
    const byTitle = new Map<string, { title: string; severity: string; points: number; count: number; alertId: string }>()
    for (const c of contributions) {
      const current = byTitle.get(c.title)
      if (current) { current.points += c.points; current.count += 1 }
      else byTitle.set(c.title, { title: c.title, severity: c.severity, points: c.points, count: 1, alertId: c.alert_id })
    }
    return [...byTitle.values()].sort((a, b) => b.points - a.points).slice(0, 6)
  }, [contributions])
  const maxPoints = Math.max(1, ...factors.map(f => f.points))
  const reasons = (ueba.data?.anomalies ?? []).flatMap(a => a.reasons ?? []).slice(0, 4)
  const trend = (history.data?.history ?? []).slice(-14).map(day => day.max_risk)
  const searchQuery = entity.entity_type === 'user' ? `user_name:"${entity.entity_value}"` : `"${entity.entity_value}"`

  return <>
    <div className="cv-row cv-row--between" style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}>
      <div className="cv-stack">
        <p className="cv-eyebrow">{entity.entity_type === 'host' ? 'Host' : 'User'}</p>
        <h2 className="cv-mono" style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>{entity.entity_value}</h2>
        <span className="cv-muted cv-small">{entity.alert_count} alerts · group {entity.group_id}</span>
      </div>
      <span className={`cv-riskbadge cv-riskbadge--${riskTone(entity.risk_score)}`}>{Math.round(entity.risk_score)}</span>
    </div>
    {trend.length > 1 && (
      <div className="cv-stack">
        <span className="cv-muted cv-small">Behaviour risk, last {trend.length} days</span>
        <Spark values={trend} tone={riskTone(entity.risk_score)} />
      </div>
    )}

    <SectionTitle>What makes up the score</SectionTitle>
    {detail.isPending && <span className="cv-muted cv-small">Loading…</span>}
    {factors.map(factor => (
      <div key={factor.title} className="cv-stack" style={{ gap: 5 }}>
        <div className="cv-row cv-row--between" style={{ flexWrap: 'nowrap', alignItems: 'baseline' }}>
          <Link to={`/alerts?alert=${factor.alertId}`} style={{ color: '#C9D0DB', overflowWrap: 'anywhere' }}>
            {factor.title}{factor.count > 1 ? ` ×${factor.count}` : ''}
          </Link>
          <span className="cv-mono" style={{ color: '#E8ECF2', whiteSpace: 'nowrap' }}>+{factor.points}</span>
        </div>
        <Meter value={(factor.points / maxPoints) * 100} tone={severityTone(factor.severity)} />
      </div>
    ))}
    {!detail.isPending && factors.length === 0 && <span className="cv-muted cv-small">No contributing alerts in the window.</span>}

    <SectionTitle>Deviations from baseline</SectionTitle>
    {reasons.map((reason, index) => (
      <div key={`${reason.feature}-${index}`} className="cv-card" style={{ padding: '10px 12px', gap: 2 }}>
        <span>{reason.text}</span>
        <span className="cv-muted cv-small">{label(reason.feature)} · {reason.z.toFixed(1)}σ from usual</span>
      </div>
    ))}
    {reasons.length === 0 && <span className="cv-muted cv-small">{ueba.isPending ? 'Loading…' : 'No behaviour anomalies recorded for this entity.'}</span>}

    <div className="cv-row" style={{ marginTop: 4 }}>
      <Link className="cv-btn" to={`/events?q=${encodeURIComponent(searchQuery)}&range=7d`}>View activity</Link>
      <Link className="cv-btn" to={`/alerts?view=all&q=${encodeURIComponent(entity.entity_value)}`}>Open alerts</Link>
      <Link className="cv-btn" to="/hunts">Hunt</Link>
    </div>
  </>
}
