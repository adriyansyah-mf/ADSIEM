import { Fragment, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronDown, ChevronRight, Search, TriangleAlert } from 'lucide-react'
import { formatDistanceToNowStrict } from 'date-fns'
import { AgentActions } from '@/components/AgentActions'
import DeployAgentModal from '@/components/DeployAgentModal'
import { AssetTierChip, AssetTierEditor } from '@/components/AssetTier'
import { EvidenceHealthPanel } from '@/components/EvidenceHealth'
import { useAgents } from '@/hooks/useAgents'
import { useSyslogSources } from '@/hooks/useSyslogSources'
import { useAuthStore } from '@/stores/auth'
import { CanvasHeader, CanvasPage, Chip, Empty, Seg, type Tone } from '@/components/canvas/Canvas'
import type { Agent, AgentSensorStat } from '@/types'

const SENSOR_LABEL: Record<string, string> = { etw: 'ETW', procexec: 'exec', netwatch: 'net', linsensor: 'eBPF' }
const PAGE = 50

type Filter = 'all' | 'attention' | 'isolated' | 'offline'

function compareVersions(a: string, b: string) {
  const pa = a.split(/[.-]/).map(n => Number(n) || 0)
  const pb = b.split(/[.-]/).map(n => Number(n) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0)
  }
  return 0
}

interface Health { label: string; tone: Tone; dot: string; why: string; attention: boolean }

function healthOf(agent: Agent, latest: string | null): Health {
  const sensorsOff = Object.entries(agent.sensor_health ?? {}).filter(([, s]: [string, AgentSensorStat]) => !s.running).map(([n]) => SENSOR_LABEL[n] ?? n)
  const blocked = agent.evidence?.status === 'blocked'
  if (agent.approved === false) return { label: 'Pending approval', tone: 'warn', dot: 'warn', why: 'Enrolled, waiting for an admin', attention: true }
  if (agent.status === 'offline') {
    return { label: 'Offline', tone: 'muted', dot: 'muted', why: agent.last_seen_at ? `No heartbeat for ${formatDistanceToNowStrict(new Date(agent.last_seen_at))}` : 'Never connected', attention: true }
  }
  if (agent.is_isolated) return { label: 'Isolated', tone: 'info', dot: 'info', why: blocked ? 'Evidence throttled' : 'Network contained', attention: blocked }
  if (blocked) return { label: 'Throttled', tone: 'warn', dot: 'warn', why: agent.evidence?.reason ?? 'Evidence upload blocked', attention: true }
  if (sensorsOff.length) return { label: 'Degraded', tone: 'warn', dot: 'warn', why: `Sensor off: ${sensorsOff.join(', ')}`, attention: true }
  if (agent.config_error) return { label: 'Degraded', tone: 'warn', dot: 'warn', why: `Config not applied: ${agent.config_error}`, attention: true }
  if (latest && agent.version && compareVersions(agent.version, latest) < 0) return { label: 'Outdated', tone: 'yellow', dot: 'warn', why: `Behind ${latest}`, attention: false }
  return { label: 'Healthy', tone: 'good', dot: 'good', why: '', attention: false }
}

export default function AgentsPage() {
  const [params, setParams] = useSearchParams()
  const filter = (['all', 'attention', 'isolated', 'offline'] as const).find(f => f === params.get('view')) ?? 'all'
  const [search, setSearch] = useState(params.get('search') ?? '')
  const [page, setPage] = useState(1)
  const [open, setOpen] = useState<string | null>(null)
  const [showInstall, setShowInstall] = useState(false)
  const query = useAgents(1, 500)
  const syslog = useSyslogSources()
  const canManage = useAuthStore(state => state.hasRole('admin'))
  const agents = query.data?.items ?? []

  const latest = useMemo(() => agents.map(a => a.version).filter((v): v is string => !!v).sort(compareVersions).pop() ?? null, [agents])
  const rows = useMemo(() => agents.map(agent => ({ agent, health: healthOf(agent, latest) })), [agents, latest])
  const counts = {
    all: rows.length,
    attention: rows.filter(r => r.health.attention).length,
    isolated: rows.filter(r => r.agent.is_isolated).length,
    offline: rows.filter(r => r.agent.status === 'offline').length,
  }
  const behind = rows.filter(r => latest && r.agent.version && compareVersions(r.agent.version, latest) < 0).length
  const term = search.trim().toLowerCase()
  const visible = rows.filter(({ agent, health }) =>
    (filter === 'all' || (filter === 'attention' ? health.attention : filter === 'isolated' ? agent.is_isolated : agent.status === 'offline'))
    && (!term || `${agent.name} ${agent.hostname} ${agent.group_id} ${agent.asset_role ?? ''}`.toLowerCase().includes(term)))
  const pageRows = visible.slice((page - 1) * PAGE, page * PAGE)
  const blocked = rows.filter(r => r.agent.evidence?.status === 'blocked')
  const setFilter = (value: Filter) => { setPage(1); setParams(current => { const next = new URLSearchParams(current); if (value === 'all') next.delete('view'); else next.set('view', value); return next }, { replace: true }) }

  return (
    <CanvasPage>
      <CanvasHeader
        title="Endpoints"
        sub={query.data ? `${agents.length} agents · ${counts.offline} offline · refreshes every 30 s` : 'Agents, syslog devices and agent updates'}
        counts={{ '/agents': agents.length || null, '/syslog': syslog.data?.length ?? null, '/agent-updates': behind || null }}
        actions={canManage && <>
          <Link className="cv-btn" to="/agent-updates">Roll out update{behind ? ` · ${behind} behind` : ''}</Link>
          <button type="button" className="cv-btn cv-btn--primary" onClick={() => setShowInstall(true)}>Deploy agent</button>
        </>}
      />
      <div className="cv-body cv-body--wide" style={{ maxWidth: 1400 }}>
        {blocked.length > 0 && (
          <div className="cv-banner">
            <TriangleAlert size={18} aria-hidden="true" />
            <div className="cv-stack" style={{ flex: 1 }}>
              <strong>{blocked.length === 1 ? `${blocked[0].agent.hostname} cannot upload evidence` : `${blocked.length} endpoints cannot upload evidence`}</strong>
              <span className="cv-dim">{blocked[0].agent.evidence?.reason ?? 'The group evidence budget is full.'} Alerts still arrive; evidence files do not.</span>
            </div>
            <button type="button" className="cv-btn" onClick={() => { setFilter('attention'); setOpen(blocked[0].agent.id) }}>Review</button>
            {canManage && <Link className="cv-btn" to="/settings">Change budget</Link>}
          </div>
        )}

        <div className="cv-row">
          <div className="cv-search" style={{ flex: '1 1 260px', maxWidth: 360 }}>
            <Search size={14} aria-hidden="true" />
            <label htmlFor="find-endpoint" className="sr-only">Find endpoint</label>
            <input id="find-endpoint" placeholder="Hostname, name, group or role" value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} />
          </div>
          <Seg label="Status filter" value={filter} onChange={setFilter} options={[
            { value: 'all', label: `All ${counts.all}` },
            { value: 'attention', label: `Needs attention ${counts.attention}` },
            { value: 'isolated', label: `Isolated ${counts.isolated}` },
            { value: 'offline', label: `Offline ${counts.offline}` },
          ]} />
          {query.isFetching && <span className="cv-muted cv-small">Updating…</span>}
        </div>

        <div className="cv-tablewrap">
          <table className="cv-table" style={{ minWidth: 900 }}>
            <thead><tr>
              <th style={{ width: 28 }}><span className="sr-only">Expand</span></th>
              <th>Endpoint</th><th>Health</th><th>Agent</th><th>Last seen</th><th>Sensors</th><th>Criticality</th><th>Actions</th>
            </tr></thead>
            <tbody>
              {pageRows.map(({ agent, health }) => {
                const isOpen = open === agent.id
                const outdated = latest && agent.version && compareVersions(agent.version, latest) < 0
                return (
                  <Fragment key={agent.id}>
                    <tr className={isOpen ? 'is-active' : undefined}>
                      <td>
                        <button type="button" aria-label={isOpen ? `Collapse ${agent.hostname}` : `Expand ${agent.hostname}`} aria-expanded={isOpen}
                          style={{ border: 0, background: 'transparent', color: '#8A94A6', padding: 0, cursor: 'pointer' }} onClick={() => setOpen(isOpen ? null : agent.id)}>
                          {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        </button>
                      </td>
                      <td>
                        <div className="cv-stack">
                          <button type="button" className="cv-rowlink cv-mono" style={{ fontSize: 13 }} onClick={() => setOpen(isOpen ? null : agent.id)}>{agent.hostname}</button>
                          <span className="cv-muted cv-small">{agent.name !== agent.hostname ? `${agent.name} · ` : ''}{agent.group_id}</span>
                        </div>
                      </td>
                      <td>
                        <div className="cv-stack">
                          <span className="cv-row" style={{ gap: 6, flexWrap: 'nowrap' }}><span className={`cv-dot cv-dot--${health.dot}`} /><span className={`cv-t-${health.tone === 'muted' ? 'info' : health.tone}`} style={health.tone === 'muted' ? { color: '#A9B2C1' } : undefined}>{health.label}</span></span>
                          {health.why && <span className="cv-muted cv-small" style={{ overflowWrap: 'anywhere' }}>{health.why}</span>}
                        </div>
                      </td>
                      <td>
                        <div className="cv-stack">
                          <span className="cv-mono">{agent.version ?? '—'}</span>
                          {agent.version && <span className={`cv-small ${outdated ? 'cv-t-yellow' : 'cv-muted'}`}>{outdated ? 'update available' : 'latest'}</span>}
                        </div>
                      </td>
                      <td className="cv-dim" style={{ whiteSpace: 'nowrap' }}>{agent.last_seen_at ? (Date.now() - Date.parse(agent.last_seen_at) < 90_000 ? 'now' : formatDistanceToNowStrict(new Date(agent.last_seen_at))) : 'never'}</td>
                      <td>
                        <span className="cv-row" style={{ gap: 4 }}>
                          {Object.entries(agent.sensor_health ?? {}).sort(([a], [b]) => a.localeCompare(b)).map(([name, s]) => (
                            <Chip key={name} tone={!s.running ? 'bad' : s.lost > 0 ? 'warn' : 'good'}>{SENSOR_LABEL[name] ?? name}{!s.running ? ' off' : ''}</Chip>
                          ))}
                          {!agent.sensor_health && <span className="cv-muted cv-small">not reported</span>}
                        </span>
                      </td>
                      <td><AssetTierChip tier={agent.asset_tier} role={agent.asset_role} /></td>
                      <td>
                        <span className="cv-row" style={{ gap: 4, flexWrap: 'nowrap' }}>
                          <Link className="cv-btn cv-btn--sm" to={`/live-response?agent=${agent.id}`}>Respond</Link>
                          {canManage && <Link className="cv-btn cv-btn--sm" to={`/agents/${agent.id}/sources`}>Sources</Link>}
                        </span>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="is-active">
                        <td />
                        <td colSpan={7}>
                          <div className="cv-agentpanel">
                            <AgentActions agent={agent} />
                            {canManage && <AssetTierEditor agentId={agent.id} tier={agent.asset_tier} role={agent.asset_role} />}
                            <EvidenceHealthPanel agent={agent} canManage={canManage} />
                            {canManage && <div className="cv-row"><Link to={`/agents/${agent.id}/sources`}>Log sources</Link><Link to={`/agents/${agent.id}/firewall`}>Firewall rules</Link></div>}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
          {query.isPending && <Empty>Loading endpoints…</Empty>}
          {query.isError && <Empty>Could not load endpoints.</Empty>}
          {!query.isPending && !query.isError && visible.length === 0 && (
            <Empty>{agents.length ? 'No endpoint matches this view.' : canManage ? 'Deploy an agent to start collecting endpoint telemetry.' : 'An administrator can deploy agents for this group.'}</Empty>
          )}
        </div>
        {visible.length > PAGE && (
          <div className="cv-row cv-small">
            <button type="button" className="cv-btn cv-btn--sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</button>
            <span className="cv-muted">{(page - 1) * PAGE + 1}–{Math.min(page * PAGE, visible.length)} of {visible.length}</span>
            <button type="button" className="cv-btn cv-btn--sm" disabled={page * PAGE >= visible.length} onClick={() => setPage(p => p + 1)}>Next</button>
          </div>
        )}
        <p className="cv-muted cv-small" style={{ margin: 0 }}>Expand a row for isolation, response actions, criticality and evidence delivery. Log sources and firewall rules open per host.</p>
      </div>
      {showInstall && <DeployAgentModal onClose={() => setShowInstall(false)} />}
    </CanvasPage>
  )
}
