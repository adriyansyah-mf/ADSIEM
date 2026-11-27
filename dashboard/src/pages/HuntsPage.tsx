import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { format } from 'date-fns'
import MarkdownNote from '@/components/MarkdownNote'
import { HuntSchedules, IOC_TYPES } from '@/components/HuntSchedules'
import { useHunts, useStartHunt } from '@/hooks/useHunts'
import { huntError, useHuntSchedules } from '@/hooks/useHuntSchedules'
import { useAuthStore } from '@/stores/auth'
import { CanvasHeader, CanvasPage, Chip, Empty, Seg, SectionTitle, severityTone, type Tone } from '@/components/canvas/Canvas'
import type { ThreatHunt } from '@/types'

type Filter = 'active' | 'done' | 'all'

function parseAnalysis(value: string | null): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(value ?? 'null')
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null
  } catch { return null }
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

const TYPE_LABEL: Record<string, string> = { ip: 'IP address', hostname: 'Host', user: 'User', hash: 'File hash' }
const STATUS: Record<ThreatHunt['status'], { label: string; tone: Tone }> = {
  pending: { label: 'QUEUED', tone: 'muted' },
  running: { label: 'IN PROGRESS', tone: 'info' },
  done: { label: 'CONCLUDED', tone: 'good' },
  failed: { label: 'FAILED', tone: 'bad' },
}

function resultLine(hunt: ThreatHunt): { text: string; tone: string } {
  if (hunt.status === 'pending' || hunt.status === 'running') return { text: 'Collecting…', tone: 'cv-t-info' }
  if (hunt.status === 'failed') return { text: 'Failed', tone: 'cv-t-bad' }
  const hits = hunt.alert_count + hunt.event_count + hunt.fim_count
  if (!hits) return { text: 'No hits', tone: 'cv-t-good' }
  return { text: `${hits.toLocaleString('en-US')} hit${hits === 1 ? '' : 's'}`, tone: hunt.risk_level === 'critical' ? 'cv-t-bad' : 'cv-t-warn' }
}

function huntRef(hunt: ThreatHunt) {
  return `HNT-${hunt.id.replace(/-/g, '').slice(0, 6).toUpperCase()}`
}

function eventsQuery(hunt: ThreatHunt) {
  const value = hunt.ioc_value.includes(' ') ? `"${hunt.ioc_value}"` : hunt.ioc_value
  switch (hunt.ioc_type) {
    case 'ip': return `source_ip:${value}`
    case 'user': return `user_name:${value}`
    default: return value
  }
}

export default function HuntsPage() {
  const [params, setParams] = useSearchParams()
  const view = params.get('view') === 'schedules' ? 'schedules' : 'hunts'
  const query = useHunts()
  const schedules = useHuntSchedules()
  const start = useStartHunt()
  const canHunt = useAuthStore(state => state.hasRole('analyst'))
  const [filter, setFilter] = useState<Filter>('all')
  const [showForm, setShowForm] = useState(false)
  const [iocType, setIocType] = useState('ip')
  const [iocValue, setIocValue] = useState('')
  const [formError, setFormError] = useState('')

  const hunts = Array.isArray(query.data) ? query.data : []
  const visible = useMemo(() => hunts.filter(hunt => filter === 'all'
    || (filter === 'active' ? hunt.status === 'pending' || hunt.status === 'running' : hunt.status === 'done' || hunt.status === 'failed')), [hunts, filter])
  const selectedId = params.get('hunt') ?? visible[0]?.id
  const selected = hunts.find(hunt => hunt.id === selectedId) ?? null
  const select = (id: string) => setParams(current => { const next = new URLSearchParams(current); next.set('hunt', id); return next }, { replace: true })

  const launch = (type: string, value: string) => {
    setFormError('')
    start.mutate({ ioc_type: type, ioc_value: value }, {
      onSuccess: hunt => { setIocValue(''); setShowForm(false); setFilter('all'); select(hunt.id) },
      onError: error => setFormError(huntError(error)),
    })
  }

  const tabs = [
    { to: '/hunts', label: 'Hunts', count: hunts.length || null, active: view === 'hunts' },
    { to: '/retro-hunt', label: 'Retro-hunt (IoC sweep)' },
    { to: '/hunts?view=schedules', label: 'Schedules', count: schedules.data?.length ?? null, active: view === 'schedules' },
  ]

  return (
    <CanvasPage>
      <CanvasHeader
        title="Threat hunting"
        sub="Trace an indicator across alerts, endpoint events and file integrity history, with an AI read of what it finds"
        tabs={tabs}
        actions={canHunt && view === 'hunts' && (
          <button type="button" className="cv-btn cv-btn--primary" aria-expanded={showForm} onClick={() => setShowForm(value => !value)}>
            {showForm ? 'Cancel' : 'New hunt'}
          </button>
        )}
      />

      {view === 'schedules' ? (
        <div className="cv-body"><HuntSchedules /></div>
      ) : (
        <div className="cv-split">
          <aside className="cv-list" aria-label="Hunt library">
            <div className="cv-list__tools">
              {showForm && (
                <form className="cv-stack" style={{ gap: 8 }} onSubmit={event => {
                  event.preventDefault()
                  const value = iocValue.trim()
                  if (!value) { setFormError('Enter an indicator value.'); return }
                  launch(iocType, value)
                }}>
                  <select className="cv-select" aria-label="Indicator type" value={iocType} onChange={event => setIocType(event.target.value)}>
                    {IOC_TYPES.map(type => <option key={type.value} value={type.value}>{type.label}</option>)}
                  </select>
                  <input className="cv-input cv-mono" aria-label="Indicator value" autoFocus value={iocValue} onChange={event => setIocValue(event.target.value)}
                    placeholder={iocType === 'ip' ? '192.0.2.42' : iocType === 'hostname' ? 'finance-server' : iocType === 'user' ? 'alex.morgan' : 'SHA256 hash'} />
                  <button type="submit" className="cv-btn cv-btn--primary" disabled={start.isPending}>{start.isPending ? 'Starting…' : 'Start hunt'}</button>
                  {formError && <p role="alert" className="cv-t-bad cv-small" style={{ margin: 0 }}>{formError}</p>}
                </form>
              )}
              <Seg label="Hunt status" value={filter} onChange={setFilter}
                options={[{ value: 'active', label: 'Active' }, { value: 'done', label: 'Concluded' }, { value: 'all', label: 'All' }]} />
            </div>
            {visible.map(hunt => {
              const analysis = parseAnalysis(hunt.analysis)
              const technique = strings(analysis?.mitre_techniques)[0]
              const result = resultLine(hunt)
              return (
                <button key={hunt.id} type="button" className="cv-list__item" aria-current={hunt.id === selected?.id} onClick={() => select(hunt.id)}>
                  <span className="cv-list__title"><span className="cv-muted">{TYPE_LABEL[hunt.ioc_type] ?? hunt.ioc_type}:</span> <span className="cv-mono" style={{ fontSize: 13 }}>{hunt.ioc_value}</span></span>
                  <span className="cv-list__meta">
                    {technique && <span className="cv-mono">{technique}</span>}
                    <span>{format(new Date(hunt.created_at), 'dd MMM HH:mm')}</span>
                    <span className={result.tone}>{result.text}</span>
                  </span>
                </button>
              )
            })}
            {query.isPending && <Empty>Loading hunts…</Empty>}
            {query.isError && <Empty>Could not load hunts.</Empty>}
            {!query.isPending && !query.isError && visible.length === 0 && <Empty>{hunts.length ? 'No hunts in this view.' : 'No hunts yet. Start one with “New hunt”.'}</Empty>}
          </aside>

          <section className="cv-pane" aria-label="Hunt workspace">
            {selected ? <HuntWorkspace hunt={selected} canHunt={canHunt} rerun={() => launch(selected.ioc_type, selected.ioc_value)} rerunning={start.isPending} />
              : <Empty>Select a hunt, or start a new one.</Empty>}
          </section>
        </div>
      )}
    </CanvasPage>
  )
}

function HuntWorkspace({ hunt, canHunt, rerun, rerunning }: {
  readonly hunt: ThreatHunt
  readonly canHunt: boolean
  readonly rerun: () => void
  readonly rerunning: boolean
}) {
  const analysis = parseAnalysis(hunt.analysis)
  const narrative = typeof analysis?.attack_narrative === 'string' ? analysis.attack_narrative : null
  const techniques = strings(analysis?.mitre_techniques)
  const actions = strings(analysis?.recommended_actions)
  const phase = typeof analysis?.kill_chain_phase === 'string' ? analysis.kill_chain_phase.replace(/_/g, ' ') : null
  const status = STATUS[hunt.status]
  const pending = hunt.status === 'pending' || hunt.status === 'running'
  const timeline = hunt.timeline ?? []
  const duration = hunt.completed_at ? Math.max(0, (Date.parse(hunt.completed_at) - Date.parse(hunt.created_at)) / 1000) : null

  return <>
    <div className="cv-row cv-row--between" style={{ alignItems: 'flex-start' }}>
      <div className="cv-stack">
        <p className="cv-eyebrow">Indicator hunt · {huntRef(hunt)}</p>
        <h2 style={{ margin: '2px 0 0', fontSize: 17, fontWeight: 600, overflowWrap: 'anywhere' }}>
          Where else has {TYPE_LABEL[hunt.ioc_type]?.toLowerCase() ?? 'indicator'} <span className="cv-mono" style={{ fontSize: 16 }}>{hunt.ioc_value}</span> appeared?
        </h2>
      </div>
      <Chip tone={status.tone}>{status.label}</Chip>
    </div>

    <dl className="cv-dl" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))' }}>
      <div><dt>Technique</dt><dd>{techniques.length ? techniques.slice(0, 2).join(', ') : '—'}</dd></div>
      <div><dt>Scope</dt><dd>Group {hunt.group_id} · stored history</dd></div>
      <div><dt>Risk</dt><dd>{hunt.risk_level && hunt.risk_level !== 'unknown' ? <Chip tone={severityTone(hunt.risk_level)}>{hunt.risk_level}</Chip> : '—'}</dd></div>
      <div><dt>Kill chain</dt><dd style={{ textTransform: 'capitalize' }}>{phase ?? '—'}</dd></div>
    </dl>

    <div className="cv-row cv-row--between">
      <h3 className="cv-h3">What was searched</h3>
      <span className="cv-muted cv-small">
        Started {format(new Date(hunt.created_at), 'dd MMM HH:mm')}{duration != null ? ` · ${duration < 60 ? `${duration.toFixed(1)} s` : `${Math.round(duration / 60)} min`}` : ''}
        {' · '}{hunt.alert_count} alerts, {hunt.event_count} events, {hunt.fim_count} FIM records
      </span>
    </div>
    <pre className="cv-pre">{`${hunt.ioc_type} = "${hunt.ioc_value}"\n| match alerts, endpoint events, file integrity records\n| ai: summarise, map to ATT&CK, recommend actions`}</pre>
    <div className="cv-row">
      {canHunt && <button type="button" className="cv-btn" disabled={rerunning || pending} onClick={rerun}>{rerunning ? 'Starting…' : 'Run again'}</button>}
      <Link className="cv-btn" to="/hunts?view=schedules">Schedule</Link>
      <Link className="cv-btn" to={`/events?q=${encodeURIComponent(eventsQuery(hunt))}&range=30d`}>Open in Search</Link>
      <Link className="cv-btn" to={`/rules?new=1&query=${encodeURIComponent(eventsQuery(hunt))}`}>Promote to detection rule</Link>
    </div>

    <h3 className="cv-h3">Results · {timeline.length} {timeline.length === 1 ? 'row' : 'rows'}</h3>
    <div className="cv-tablewrap">
      <table className="cv-table" style={{ minWidth: 560 }}>
        <thead><tr><th>Time</th><th>Type</th><th>What</th><th>Host</th><th>Source IP</th></tr></thead>
        <tbody>
          {timeline.slice(0, 100).map((entry, index) => (
            <tr key={`${entry.id}-${index}`}>
              <td className="cv-mono cv-dim" style={{ whiteSpace: 'nowrap' }}>{format(new Date(entry.time), 'dd MMM HH:mm:ss')}</td>
              <td>{entry.type === 'alert' ? <Chip tone={severityTone(entry.severity)}>{entry.severity ?? 'alert'}</Chip> : <Chip>event</Chip>}</td>
              <td style={{ overflowWrap: 'anywhere' }}>
                {entry.type === 'alert'
                  ? <Link to={`/alerts?alert=${entry.id}`} style={{ color: '#E8ECF2' }}>{entry.title}</Link>
                  : <span className="cv-dim">{entry.category ?? 'activity'} / {entry.action ?? 'unknown'}{entry.user ? ` · ${entry.user}` : ''}</span>}
              </td>
              <td className="cv-mono">{entry.hostname ?? '—'}</td>
              <td className="cv-mono">{entry.source_ip ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {pending && <Empty>{hunt.status === 'pending' ? 'Waiting in the queue…' : 'Hunt in progress; results appear as they come in.'}</Empty>}
      {!pending && timeline.length === 0 && <Empty>No related history was found for this indicator.</Empty>}
    </div>

    <h3 className="cv-h3">Findings</h3>
    {hunt.status === 'failed' && <p className="cv-t-bad" style={{ margin: 0 }}>{narrative ?? 'This hunt failed. Run it again to retry.'}</p>}
    {hunt.status === 'done' && (
      <div className="cv-card">
        <div className="cv-row cv-small cv-muted">
          <span className="cv-mono">{hunt.completed_at ? format(new Date(hunt.completed_at), 'HH:mm') : ''}</span>
          <span>AI analyst · verify against the evidence before acting</span>
        </div>
        {narrative ? <MarkdownNote content={narrative} /> : hunt.analysis && !analysis ? <pre className="cv-pre">{hunt.analysis}</pre> : <span className="cv-muted">No narrative was returned.</span>}
        {actions.length > 0 && (
          <>
            <SectionTitle>Recommended next steps</SectionTitle>
            <ol style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {actions.map((action, index) => <li key={index}>{action}</li>)}
            </ol>
          </>
        )}
      </div>
    )}
    {pending && <span className="cv-muted">Findings appear when the hunt completes.</span>}
  </>
}
