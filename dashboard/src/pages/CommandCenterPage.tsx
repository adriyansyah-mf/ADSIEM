import { Suspense, lazy, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, Copy, Maximize2, Minimize2, Pause, Play, RefreshCw, Search, X } from 'lucide-react'
import { format } from 'date-fns'
import { PageHeader, Panel, QueryState } from '@/components/Workspace'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import type { MapFocus } from '@/components/AttackMap'
import { SEVERITY_COLOR } from '@/lib/severityColors'
import { useQuickThreatLookup, useSocGeo, useSocMetrics, useSocPosture } from '@/hooks/useMetrics'
import type { GeoCountry, GeoPoint, GeoRecentAlert, SeverityCounts, SocPosture } from '@/hooks/useMetrics'

// The map pulls in d3-geo and the world topology; keep them out of the main bundle.
const AttackMap = lazy(() => import('@/components/AttackMap'))

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
type Severity = typeof SEVERITIES[number]
const BUCKET_LABEL: Readonly<Record<string, string>> = { lt_1h: '< 1h', '1h_4h': '1–4h', '4h_24h': '4–24h', gt_24h: '> 24h' }

const fmtMinutes = (m?: number | null) => m == null ? '—' : m >= 1440 ? `${(m / 1440).toFixed(1)}d` : m >= 60 ? `${(m / 60).toFixed(1)}h` : `${Math.round(m)}m`
const ago = (iso: string | null) => {
  if (!iso) return '—'
  const m = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 60000))
  return m < 1 ? 'now' : m < 60 ? `${m}m` : m < 1440 ? `${Math.round(m / 60)}h` : `${Math.round(m / 1440)}d`
}
const place = (p: { city: string | null; country: string | null }) => [p.city, p.country].filter(Boolean).join(', ') || 'Unknown location'

function filterSeverities(counts: SeverityCounts, active: ReadonlySet<string>) {
  const kept: Record<string, number> = {}
  let total = 0
  for (const [sev, n] of Object.entries(counts)) {
    if (n && active.has(sev)) { kept[sev] = n; total += n }
  }
  const max = SEVERITIES.find(s => kept[s]) ?? 'info'
  return { kept, total, max }
}

function SeverityStack({ counts, total }: { readonly counts: SeverityCounts; readonly total: number }) {
  return <span className="sev-stack" aria-hidden="true">
    {SEVERITIES.filter(s => counts[s]).map(s => <i key={s} style={{ width: `${((counts[s] ?? 0) / Math.max(total, 1)) * 100}%`, background: SEVERITY_COLOR[s] }} />)}
  </span>
}

function Kpi({ label, value, detail, to, tone }: {
  readonly label: string; readonly value: string; readonly detail: string; readonly to?: string; readonly tone?: 'critical' | 'warning' | 'ok'
}) {
  const body = <><span className="metric-card__label">{label}</span>
    <strong className="metric-card__value">{value}</strong><span className="metric-card__detail">{detail}</span></>
  const cls = `panel metric-card cc-kpi${tone ? ` cc-kpi--${tone}` : ''}`
  return to ? <Link className={cls} to={to}>{body}</Link> : <div className={cls}>{body}</div>
}

export default function CommandCenterPage() {
  const rootRef = useRef<HTMLDivElement>(null)
  const [days, setDays] = useState(1)
  const [live, setLive] = useState(true)
  const [wall, setWall] = useState(false)
  const [showArcs, setShowArcs] = useState(true)
  const [active, setActive] = useState<ReadonlySet<string>>(() => new Set(SEVERITIES))
  const [selectedIp, setSelectedIp] = useState<string | null>(null)
  const [focus, setFocus] = useState<MapFocus | null>(null)
  const geo = useSocGeo(days, live)
  const posture = useSocPosture(days, live)
  const metrics = useSocMetrics(days, live)
  const since = useMemo(() => new Date(Date.now() - days * 86_400_000).toISOString(), [days, geo.dataUpdatedAt])

  // Alerts that appear between refreshes are "fresh": animated on the map and flagged in the feed.
  const seen = useRef<{ days: number; ids: Set<string> } | null>(null)
  const [fresh, setFresh] = useState<readonly GeoRecentAlert[]>([])
  const [freshIds, setFreshIds] = useState<ReadonlySet<string>>(new Set())
  useEffect(() => {
    const recent = geo.data?.recent
    if (!recent) return
    const prev = seen.current
    const ids = new Set(prev?.days === days ? prev.ids : [])
    const arrived = prev?.days === days ? recent.filter(r => !ids.has(r.id)) : []
    recent.forEach(r => ids.add(r.id))
    seen.current = { days, ids }
    if (arrived.length === 0) return
    setFresh(arrived.slice(0, 12))
    setFreshIds(new Set(arrived.map(r => r.id)))
    const timer = window.setTimeout(() => setFresh([]), 2400)
    return () => window.clearTimeout(timer)
  }, [geo.data?.recent, days])

  useEffect(() => {
    const onChange = () => setWall(document.fullscreenElement === rootRef.current)
    document.addEventListener('fullscreenchange', onChange)
    return () => document.removeEventListener('fullscreenchange', onChange)
  }, [])
  const toggleWall = () => {
    if (document.fullscreenElement) void document.exitFullscreen()
    else void rootRef.current?.requestFullscreen?.().catch(() => setWall(w => !w))
  }

  const points = useMemo<GeoPoint[]>(() => (geo.data?.points ?? []).flatMap(p => {
    const f = filterSeverities(p.by_severity, active)
    return f.total ? [{ ...p, by_severity: f.kept, count: f.total, max_severity: f.max }] : []
  }), [geo.data?.points, active])

  const countries = useMemo<GeoCountry[]>(() => (geo.data?.countries ?? []).flatMap(c => {
    const f = filterSeverities(c.by_severity, active)
    return f.total ? [{ ...c, by_severity: f.kept, count: f.total, max_severity: f.max }] : []
  }).sort((a, b) => b.count - a.count), [geo.data?.countries, active])

  const selected = selectedIp ? geo.data?.points.find(p => p.ip === selectedIp) ?? null : null
  const visibleFresh = useMemo(() => fresh.filter(a => active.has(a.severity)), [fresh, active])

  const refresh = () => { void geo.refetch(); void posture.refetch(); void metrics.refetch() }
  const toggleSeverity = (s: Severity) => setActive(prev => {
    const next = new Set(prev)
    if (next.has(s)) { if (next.size > 1) next.delete(s) } else next.add(s)
    return next
  })
  const focusCountry = (c: GeoCountry) => {
    const coords = points.filter(p => (p.country_code ?? p.country) === (c.country_code ?? c.country)).map(p => [p.lon, p.lat] as const)
    setFocus({ key: `${c.country_code ?? c.country}-${Date.now()}`, coords })
  }
  const focusPoint = (p: { lon: number; lat: number; ip?: string; source_ip?: string }) => {
    setSelectedIp(p.ip ?? p.source_ip ?? null)
    setFocus({ key: `${p.lon},${p.lat}-${Date.now()}`, coords: [[p.lon, p.lat]] })
  }

  const b = posture.data?.backlog
  const agents = posture.data?.agents
  const windowLabel = days === 1 ? 'last 24 hours' : `last ${days} days`
  const updatedAt = Math.max(geo.dataUpdatedAt, posture.dataUpdatedAt)

  return <div ref={rootRef} className={`workspace command-center${wall ? ' is-wall' : ''}`}>
    <PageHeader eyebrow="Security operations" title="SOC command center"
      description="Where attacks come from, what they hit, and whether the team is keeping up, refreshed live."
      actions={<>
        <select aria-label="Time window" className="ui-input w-auto" value={days} onChange={e => { setDays(Number(e.target.value)); setSelectedIp(null) }}>
          <option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option><option value={30}>Last 30 days</option>
        </select>
        <button type="button" className="ui-icon-button" onClick={() => setLive(v => !v)} aria-pressed={live}
          aria-label={live ? 'Pause live refresh' : 'Resume live refresh'} title={live ? 'Pause live refresh' : 'Resume live refresh'}>
          {live ? <Pause size={16} /> : <Play size={16} />}
        </button>
        <button type="button" className="ui-icon-button" onClick={refresh} aria-label="Refresh now" title="Refresh now" disabled={geo.isFetching || posture.isFetching || metrics.isFetching}>
          <RefreshCw size={16} className={geo.isFetching ? 'animate-spin' : undefined} />
        </button>
        <button type="button" className="ui-button" onClick={toggleWall} aria-pressed={wall}>
          {wall ? <><Minimize2 size={14} /> Exit wall mode</> : <><Maximize2 size={14} /> Wall mode</>}
        </button>
      </>} />

    <div className="state-banner cc-status" role="status">
      <span className={`cc-live-dot${live ? ' is-live' : ''}`} aria-hidden="true" />
      <span>{live ? 'Live · every 30 seconds' : 'Paused'}</span>
      <span>· {updatedAt ? `Updated ${format(new Date(updatedAt), 'HH:mm:ss')}` : 'Loading…'}</span>
      <span>· Alert window: {windowLabel}</span>
    </div>

    <div className="cc-kpis" aria-busy={posture.isPending}>
      <Kpi label="Open backlog" value={b ? b.open_total.toLocaleString() : '—'}
        detail={b ? `${b.unassigned.toLocaleString()} unassigned · all time` : 'New + in progress'} to="/alerts?status=new"
        tone={b && b.unassigned > 0 ? 'warning' : undefined} />
      <Kpi label="SLA breaches" value={b ? b.sla_breaches_total.toLocaleString() : '—'}
        detail="Unacknowledged past target" to="/alerts?status=new" tone={b ? b.sla_breaches_total > 0 ? 'critical' : 'ok' : undefined} />
      <Kpi label="Critical detections" value={metrics.data ? (metrics.data.by_severity.critical ?? 0).toLocaleString() : '—'}
        detail={`All statuses · ${windowLabel}`} to={`/alerts?severity=critical&start_time=${encodeURIComponent(since)}`}
        tone={(metrics.data?.by_severity.critical ?? 0) > 0 ? 'critical' : undefined} />
      <Kpi label="Attack origins" value={geo.data ? countries.length.toLocaleString() : '—'}
        detail={geo.data ? `countries · ${geo.data.distinct_source_ips.toLocaleString()} source IPs` : 'Countries'} />
      <Kpi label="Mean time to acknowledge" value={fmtMinutes(metrics.data?.avg_ack_minutes)}
        detail={`Resolve: ${fmtMinutes(metrics.data?.avg_mttr_minutes)} · ${windowLabel}`} />
      <Kpi label="Agents online" value={agents ? `${agents.online}/${agents.total}` : '—'}
        detail={agents ? `${agents.offline} offline · ${agents.isolated} isolated` : 'Fleet health'} to="/agents"
        tone={agents ? agents.offline > 0 ? 'warning' : 'ok' : undefined} />
    </div>

    {geo.data && !geo.data.geoip_available && <div className="state-banner cc-warning" role="note">
      GeoIP database not found, so attacks can't be placed on the map. Run <code>./scripts/update-geoip.sh</code> on the server, then restart server-api.
    </div>}

    <div className="cc-map-row">
      <section className="panel cc-map-panel" aria-labelledby="cc-map-title">
        <header className="panel__header">
          <div>
            <h2 id="cc-map-title">Attack origins</h2>
            <p className="panel__description">
              {geo.data ? `${geo.data.located_alerts.toLocaleString()} geolocated alerts · ${geo.data.unlocated_alerts.toLocaleString()} from internal or unknown addresses` : 'Source IPs of alerts in the selected window'}
            </p>
          </div>
          <div className="control-cluster" role="group" aria-label="Severity filter">
            {SEVERITIES.map(s => <button key={s} type="button" aria-pressed={active.has(s)} onClick={() => toggleSeverity(s)}
              className={`cc-chip${active.has(s) ? ' is-on' : ''}`} style={{ '--chip-color': SEVERITY_COLOR[s] } as CSSProperties}>
              <i aria-hidden="true" />{s}
            </button>)}
            <label className="cc-toggle"><input type="checkbox" checked={showArcs} onChange={e => setShowArcs(e.target.checked)} /> Attack paths</label>
          </div>
        </header>
        <div className="cc-map-body">
          {geo.isPending ? <QueryState kind="loading" title="Loading attack map…" />
            : geo.isError && !geo.data ? <QueryState kind="error" title="Attack map unavailable" onRetry={() => { void geo.refetch() }} />
            : <Suspense fallback={<QueryState kind="loading" title="Loading map…" />}>
              <AttackMap points={points} target={geo.data?.target ?? null} fresh={visibleFresh} selectedIp={selectedIp}
                onSelect={setSelectedIp} focus={focus} showArcs={showArcs} wheelZoom={wall} />
            </Suspense>}
        </div>
        {geo.data && <footer className="cc-map-foot">
          {!geo.data.target && <span>Set <code>SOC_HQ_LAT</code> / <code>SOC_HQ_LON</code> on server-api to draw attack paths to your site.</span>}
          {(geo.data.points_truncated || geo.data.ip_scan_truncated) && <span>Showing the busiest source addresses only.</span>}
          <span>Drag to pan · double-click to zoom · Ctrl + scroll to zoom</span>
        </footer>}
      </section>

      <aside className="panel cc-side" aria-label={selected ? `Source ${selected.ip}` : 'Top origin countries'}>
        {selected ? <SourceDetail key={selected.ip} point={selected} since={since} onClose={() => setSelectedIp(null)} />
          : <>
            <header className="panel__header"><div><h2>Top origin countries</h2>
              <p className="panel__description">Select a country to zoom the map</p></div></header>
            <div className="panel__body cc-country-list">
              {geo.isPending ? <QueryState kind="loading" title="Loading origins…" />
                : countries.length === 0 ? <QueryState kind="empty" title="No geolocated attacks"
                  description={geo.data?.geoip_available === false ? 'GeoIP data is not mounted.' : 'No alerts with a public source IP in this window.'} />
                : <ol>{countries.slice(0, 8).map((c, i) => <li key={c.country_code ?? c.country}>
                  <button type="button" className="cc-country" onClick={() => focusCountry(c)}>
                    <span className="cc-country__rank">{i + 1}</span>
                    <span className="cc-country__name">{c.country}<small>{c.unique_ips} IP{c.unique_ips === 1 ? '' : 's'}</small></span>
                    <span className="cc-country__count tabular-nums">{c.count.toLocaleString()}</span>
                    <SeverityStack counts={c.by_severity} total={c.count} />
                  </button>
                </li>)}</ol>}
              {geo.data && geo.data.unlocated_alerts > 0 && <p className="cc-note">
                + {geo.data.unlocated_alerts.toLocaleString()} alerts from {geo.data.unlocated_ips.toLocaleString()} internal or unresolvable addresses.
              </p>}
            </div>
          </>}
      </aside>
    </div>

    <div className="cc-grid">
      <Panel title="Detection severity" description={`All alerts · ${windowLabel} · independent of map filters`}
        actions={<Link className="ui-button ui-button--quiet" to={`/alerts?start_time=${encodeURIComponent(since)}`}>All alerts <ArrowRight size={14} /></Link>}>
        {metrics.isPending ? <QueryState kind="loading" title="Loading severity breakdown…" />
          : metrics.isError ? <QueryState kind="error" title="Severity breakdown unavailable" onRetry={() => { void metrics.refetch() }} />
          : metrics.data && <>
            <p className="cc-note">{metrics.data.total_alerts.toLocaleString()} detections in this window. Select a severity to investigate.</p>
            <ul className="cc-bars">{SEVERITIES.map(severity => {
              const count = metrics.data.by_severity[severity] ?? 0
              const share = metrics.data.total_alerts ? Math.round(count / metrics.data.total_alerts * 100) : 0
              return <li key={severity}>
                <Link className="cc-bars__row" to={`/alerts?severity=${severity}&start_time=${encodeURIComponent(since)}`}>
                  <SeverityBadge severity={severity} />
                  <span className="cc-bars__value tabular-nums">{count.toLocaleString()} <small className="text-muted-foreground">· {share}%</small></span>
                  <span className="cc-bars__track"><SeverityStack counts={{ [severity]: count }} total={metrics.data.total_alerts} /></span>
                </Link>
              </li>
            })}</ul>
          </>}
      </Panel>

      <Panel title="Response progress" description={`Status of alerts created in the ${windowLabel}`}>
        {metrics.isPending ? <QueryState kind="loading" title="Loading response breakdown…" />
          : metrics.isError ? <QueryState kind="error" title="Response breakdown unavailable" onRetry={() => { void metrics.refetch() }} />
          : metrics.data && <>
            <ul className="cc-bars">{['new', 'in_progress', 'resolved', 'false_positive'].map(status => <li key={status}>
              <Link className="cc-bars__row" to={`/alerts?status=${status}&start_time=${encodeURIComponent(since)}`}>
                <StatusBadge status={status} /><span className="cc-bars__value tabular-nums">{(metrics.data.by_status[status] ?? 0).toLocaleString()}</span>
              </Link>
            </li>)}</ul>
            <dl className="cc-source__facts mt-4">
              <div><dt>Active cases created in window</dt><dd>{metrics.data.open_cases.toLocaleString()}</dd></div>
              <div><dt>False positives / all detections</dt><dd>{metrics.data.false_positive_rate_pct.toFixed(1)}%</dd></div>
              <div><dt>Mean acknowledgment</dt><dd>{fmtMinutes(metrics.data.avg_ack_minutes)}</dd></div>
              <div><dt>Mean resolution</dt><dd>{fmtMinutes(metrics.data.avg_mttr_minutes)}</dd></div>
            </dl>
            <p className="cc-note">Response times include only alerts with a recorded acknowledgment or resolution.</p>
            <Link className="ui-button ui-button--quiet" to={`/cases?start_time=${encodeURIComponent(since)}`}>Cases created in window <ArrowRight size={14} /></Link>
          </>}
      </Panel>

      <Panel title="Live attack feed" description="Latest geolocated detections · newest first">
        {geo.isPending ? <QueryState kind="loading" title="Loading feed…" />
          : (geo.data?.recent.length ?? 0) === 0 ? <QueryState kind="empty" title="Quiet for now" description="No alerts with a public source IP in this window." />
          : <ul className="cc-feed">{geo.data?.recent.filter(a => active.has(a.severity)).slice(0, 8).map(a => <li key={a.id} className={freshIds.has(a.id) ? 'is-fresh' : undefined}>
            <span className="cc-feed__dot" style={{ background: SEVERITY_COLOR[a.severity] }} aria-label={a.severity} />
            <div className="cc-feed__main">
              <Link to={`/alerts/${a.id}`} className="cc-feed__title">{a.title}</Link>
              <button type="button" className="cc-feed__meta" onClick={() => focusPoint(a)} title="Show on map">
                <span className="font-mono">{a.source_ip}</span> · {place(a)}{a.hostname ? <> → <span className="font-mono">{a.hostname}</span></> : null}
              </button>
            </div>
            <time dateTime={a.created_at ?? undefined} className="cc-feed__time">{freshIds.has(a.id) ? 'New' : ago(a.created_at)}</time>
          </li>)}</ul>}
      </Panel>

      <Panel title="Triage backlog & SLA" description="Open alerts by age · all time"
        actions={<Link className="ui-button ui-button--quiet" to="/alerts?status=new">Queue <ArrowRight size={14} /></Link>}>
        {posture.isPending ? <QueryState kind="loading" title="Loading backlog…" />
          : posture.isError && !posture.data ? <QueryState kind="error" title="Backlog unavailable" onRetry={() => { void posture.refetch() }} />
          : posture.data && <BacklogMatrix backlog={posture.data.backlog} />}
      </Panel>

      <Panel title="Most targeted hosts" description={`By alert count · ${windowLabel}`}>
        {posture.isPending ? <QueryState kind="loading" title="Loading hosts…" />
          : (posture.data?.top_hosts.length ?? 0) === 0 ? <QueryState kind="empty" title="No host-attributed alerts" />
          : <ul className="cc-bars">{posture.data?.top_hosts.map(h => {
            const max = posture.data?.top_hosts[0]?.count ?? 1
            return <li key={h.hostname}>
              <Link to={`/alerts?hostname=${encodeURIComponent(h.hostname)}&start_time=${encodeURIComponent(since)}`} className="cc-bars__row">
                <span className="cc-bars__label font-mono">{h.hostname}</span>
                <span className="cc-bars__value tabular-nums">{h.count.toLocaleString()}</span>
                <span className="cc-bars__track"><SeverityStack counts={h.by_severity} total={max} /></span>
              </Link>
            </li>
          })}</ul>}
      </Panel>

      <Panel title="Noisiest detections" description={`Top rules by volume · ${windowLabel}`}
        actions={<Link className="ui-button ui-button--quiet" to="/rules">Rules <ArrowRight size={14} /></Link>}>
        {posture.isPending ? <QueryState kind="loading" title="Loading detections…" />
          : (posture.data?.top_detections.length ?? 0) === 0 ? <QueryState kind="empty" title="No detections in this window" />
          : <ul className="cc-detections">{posture.data?.top_detections.map(d => {
            const fp = d.count ? Math.round(d.false_positives / d.count * 100) : 0
            return <li key={d.title}>
              <Link to={`/alerts?search=${encodeURIComponent(d.title)}&start_time=${encodeURIComponent(since)}`} className="cc-detections__title">{d.title}</Link>
              <span className="tabular-nums">{d.count.toLocaleString()}</span>
              <span className={`cc-fp${fp >= 30 ? ' is-high' : ''}`} title="Share closed as false positive">
                {fp >= 30 ? `Tune · ${fp}% FP` : `${fp}% FP`}
              </span>
            </li>
          })}</ul>}
      </Panel>
    </div>
  </div>
}

function BacklogMatrix({ backlog }: { readonly backlog: SocPosture['backlog'] }) {
  const max = Math.max(1, ...backlog.age_buckets.flatMap(b => SEVERITIES.map(s => Number(b[s] ?? 0))))
  return <>
    <div className="cc-matrix" role="table" aria-label="Open alerts by severity and age">
      <div role="row" className="cc-matrix__row cc-matrix__head">
        <span role="columnheader">Severity</span>
        {backlog.age_buckets.map(b => <span role="columnheader" key={b.bucket}>{BUCKET_LABEL[b.bucket]}</span>)}
        <span role="columnheader">SLA</span>
      </div>
      {SEVERITIES.map(s => <div role="row" className="cc-matrix__row" key={s}>
        <span role="rowheader"><SeverityBadge severity={s} /></span>
        {backlog.age_buckets.map(b => {
          const n = Number(b[s] ?? 0)
          return <span role="cell" key={b.bucket} className="cc-matrix__cell tabular-nums"
            style={n ? { background: `color-mix(in srgb, ${SEVERITY_COLOR[s]} ${Math.round(12 + 48 * Math.sqrt(n / max))}%, transparent)` } : undefined}>
            {n || '·'}
          </span>
        })}
        <span role="cell" className={`cc-matrix__sla${(backlog.sla_breaches[s] ?? 0) > 0 ? ' is-breached' : ''}`}>
          {backlog.sla_minutes[s] == null ? '—' : (backlog.sla_breaches[s] ?? 0) > 0 ? `${backlog.sla_breaches[s]} late` : fmtMinutes(backlog.sla_minutes[s])}
        </span>
      </div>)}
    </div>
    {(backlog.oldest_new_minutes.critical != null || backlog.oldest_new_minutes.high != null) && <p className="cc-note">
      Oldest unacknowledged: {['critical', 'high'].filter(s => backlog.oldest_new_minutes[s] != null)
        .map(s => `${s} ${fmtMinutes(backlog.oldest_new_minutes[s])}`).join(' · ')}
    </p>}
  </>
}

function SourceDetail({ point, since, onClose }: { readonly point: GeoPoint; readonly since: string; readonly onClose: () => void }) {
  const ti = useQuickThreatLookup()
  const [copied, setCopied] = useState(false)
  const risk = typeof ti.data?.overall_risk === 'number' ? ti.data.overall_risk : null
  const bullets = Array.isArray(ti.data?.provider_bullets) ? ti.data.provider_bullets.filter((x): x is string => typeof x === 'string') : []
  const copy = () => { void navigator.clipboard?.writeText(point.ip).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }) }
  return <>
    <header className="panel__header">
      <div className="min-w-0"><h2 className="font-mono break-all">{point.ip}</h2>
        <p className="panel__description">{place(point)}</p></div>
      <button type="button" className="ui-icon-button" onClick={onClose} aria-label="Close source details"><X size={16} /></button>
    </header>
    <div className="panel__body cc-source">
      <dl className="cc-source__facts">
        <div><dt>Alerts</dt><dd className="tabular-nums">{point.count.toLocaleString()}</dd></div>
        <div><dt>Worst severity</dt><dd><SeverityBadge severity={point.max_severity} /></dd></div>
        <div><dt>Last seen</dt><dd>{point.last_seen ? format(new Date(point.last_seen), 'dd MMM, HH:mm') : '—'}</dd></div>
        <div><dt>Coordinates</dt><dd className="font-mono">{point.lat.toFixed(2)}, {point.lon.toFixed(2)}</dd></div>
      </dl>
      <div className="cc-source__sev">
        {SEVERITIES.filter(s => point.by_severity[s]).map(s => <span key={s}><SeverityBadge severity={s} /> <b className="tabular-nums">{point.by_severity[s]}</b></span>)}
      </div>
      <div className="cc-source__actions">
        <Link className="ui-button ui-button--primary" to={`/alerts?source_ip=${encodeURIComponent(point.ip)}&start_time=${encodeURIComponent(since)}`}>
          View alerts <ArrowRight size={14} /></Link>
        <button type="button" className="ui-button" onClick={() => ti.mutate({ ioc: point.ip, ioc_type: 'ip' })} disabled={ti.isPending}>
          <Search size={14} /> {ti.isPending ? 'Looking up…' : 'Threat intel'}</button>
        <button type="button" className="ui-icon-button" onClick={copy} aria-label="Copy IP address" title={copied ? 'Copied' : 'Copy IP address'}><Copy size={16} /></button>
      </div>
      {ti.isError && <p role="alert" className="text-destructive">Lookup failed. Try again.</p>}
      {ti.data && (ti.data.status === 'worker_unreachable'
        ? <p role="alert" className="cc-note">Threat intelligence worker is unavailable.</p>
        : <div className="cc-ti">
          {risk !== null && <p><strong>Risk score</strong> <span className={`cc-risk${risk >= 0.7 ? ' is-high' : risk >= 0.4 ? ' is-mid' : ''}`}>{Math.round(risk * 100)}/100</span></p>}
          {bullets.length > 0 ? <ul>{bullets.slice(0, 6).map(line => <li key={line}>{line}</li>)}</ul>
            : <p className="cc-note">No provider findings for this address.</p>}
        </div>)}
    </div>
  </>
}
