import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Check, Copy, Search } from 'lucide-react'
import { formatDistanceToNowStrict } from 'date-fns'
import { api } from '@/api/client'
import { IOC_PAGE, IOC_TYPES, type Ioc, type IocFilter, type IocType, useIocAlerts, useIocs } from '@/hooks/useIocs'
import { useAddMalwareHashes, useMalwareHashes } from '@/hooks/useMalwareHashes'
import { useStartHunt } from '@/hooks/useHunts'
import { apiError, useBlockWeb } from '@/hooks/useWebProtection'
import { CanvasHeader, CanvasPage, Chip, Empty, KpiStrip, severityTone, type Tone } from '@/components/canvas/Canvas'

const TYPE_LABEL: Record<IocType, string> = {
  ip: 'IPv4', domain: 'Domain', url: 'URL', sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', email: 'Email',
}
const WINDOWS = [{ days: 1, label: 'Last 24 h' }, { days: 7, label: 'Last 7 days' }, { days: 30, label: 'Last 30 days' },
  { days: 90, label: 'Last 90 days' }, { days: 0, label: 'All time' }]

interface WebFeed { name: string; enabled_key_present: boolean; status: string; last_success: string | null; entries?: number | null; error: string }

const TABS = [
  { to: '/threat-iocs', label: 'Indicators' },
  { to: '/malware-hashes', label: 'Malware hashes' },
  { to: '/mitre-heatmap', label: 'MITRE coverage' },
]

function ago(iso: string | null | undefined): string {
  return iso ? `${formatDistanceToNowStrict(new Date(iso))} ago` : '—'
}

function huntType(type: IocType): 'ip' | 'hash' | null {
  if (type === 'ip') return 'ip'
  return type === 'sha256' || type === 'sha1' || type === 'md5' ? 'hash' : null
}

function shortValue(ioc: Ioc) {
  return ioc.type === 'sha256' || ioc.type === 'sha1' || ioc.type === 'md5' ? `${ioc.value.slice(0, 4)}…${ioc.value.slice(-4)}` : ioc.value
}

function useTotal(key: string, url: string, params: Record<string, unknown>) {
  return useQuery<number>({
    queryKey: ['intel-total', key, params],
    queryFn: () => api.get(url, { params }).then(r => Number(r.data.total) || 0),
    retry: false,
    staleTime: 60_000,
  })
}

export default function ThreatIocsPage() {
  const [filter, setFilter] = useState<IocFilter>({ type: '', q: '', days: 30, sort: 'last_seen', offset: 0 })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Ioc | null>(null)
  const [copied, setCopied] = useState('')
  const { data, isLoading, isError, isFetching } = useIocs(filter)
  const last24 = useIocs({ type: '', q: '', days: 1, sort: 'last_seen', offset: 0 })
  const blockedIps = useTotal('ip-blocks', '/api/ip-blocks', { limit: 1 })
  const hashes = useMalwareHashes({ q: '', source: '', status: '', offset: 0 })
  const webFeeds = useQuery<{ feeds: WebFeed[] }>({
    queryKey: ['web-feeds'],
    queryFn: () => api.get('/api/web-blocks/feeds').then(r => r.data),
    retry: false,
    refetchInterval: 60_000,
  })
  const update = (patch: Partial<IocFilter>) => { setFilter(f => ({ ...f, offset: 0, ...patch })); setSelected(null) }
  const isSelected = (ioc: Ioc) => selected?.type === ioc.type && selected.value === ioc.value
  const copy = (value: string) => {
    void navigator.clipboard?.writeText(value)
    setCopied(value)
    setTimeout(() => setCopied(''), 1500)
  }
  const activeHashes = (hashes.data?.counts ?? []).filter(c => c.status === 'active').reduce((sum, c) => sum + c.count, 0)
  const feed = hashes.data?.feed
  const feeds: { name: string; state: string; tone: Tone }[] = [
    ...(feed ? [{
      name: 'Malware hashes · MalwareBazaar',
      state: feed.status === 'ok' ? `Synced ${ago(feed.last_success)}` : feed.status === 'no_key' ? 'No API key' : feed.status === 'error' ? 'Sync failing' : feed.status ?? 'Never run',
      tone: (feed.status === 'ok' ? 'good' : feed.status === 'error' ? 'bad' : 'warn') as Tone,
    }] : []),
    ...(webFeeds.data?.feeds ?? []).map(item => ({
      name: `Web blocklist · ${item.name}`,
      state: !item.enabled_key_present && item.status === 'never_run' ? 'Not configured'
        : item.status === 'ok' ? `Synced ${ago(item.last_success)}${item.entries ? ` · ${item.entries.toLocaleString('en-US')}` : ''}`
        : item.status === 'error' ? 'Sync failing' : item.status.replace(/_/g, ' '),
      tone: (item.status === 'ok' ? 'good' : item.status === 'error' ? 'bad' : 'muted') as Tone,
    })),
  ]
  const staleFeeds = feeds.filter(item => item.tone === 'bad' || item.tone === 'warn').length

  return (
    <CanvasPage>
      <CanvasHeader
        title="Threat intelligence"
        sub="Attacker indicators recorded in your alerts, with what the platform already blocks"
        tabs={TABS}
        actions={<>
          <Link className="cv-btn" to="/malware-hashes">Import hashes</Link>
          <Link className="cv-btn cv-btn--primary" to="/ip-blocklist">Block an indicator</Link>
        </>}
      />
      <div className="cv-split">
        <section className="cv-pane" aria-label="Indicators" style={{ padding: '20px 24px 40px' }}>
          <KpiStrip items={[
            { label: 'Indicators', value: data ? data.total.toLocaleString('en-US') : '–', note: WINDOWS.find(w => w.days === filter.days)?.label.toLowerCase() },
            { label: 'Seen, 24 h', value: last24.data ? last24.data.total.toLocaleString('en-US') : '–', note: 'in new alerts', tone: last24.data?.total ? 'warn' : 'muted' },
            { label: 'Blocked IPs', value: blockedIps.data != null ? blockedIps.data.toLocaleString('en-US') : '–', note: 'enforced on endpoints' },
            { label: 'Malware hashes', value: hashes.data ? activeHashes.toLocaleString('en-US') : '–', note: 'active, blocked on execution' },
          ]} />

          <div className="cv-row">
            <form className="cv-search" style={{ flex: '1 1 260px', maxWidth: 380 }} onSubmit={event => { event.preventDefault(); update({ q: search }) }}>
              <Search size={14} aria-hidden="true" />
              <label htmlFor="ioc-search" className="sr-only">Search indicators</label>
              <input id="ioc-search" value={search} onChange={event => setSearch(event.target.value)} placeholder="IP, domain, hash, URL" />
            </form>
            <select className="cv-select" aria-label="Type" value={filter.type} onChange={event => update({ type: event.target.value as IocType | '' })}>
              <option value="">Type: all</option>
              {IOC_TYPES.map(type => <option key={type} value={type}>{TYPE_LABEL[type]} · {(data?.type_counts?.[type] ?? 0).toLocaleString('en-US')}</option>)}
            </select>
            <select className="cv-select" aria-label="Time window" value={filter.days} onChange={event => update({ days: Number(event.target.value) })}>
              {WINDOWS.map(w => <option key={w.days} value={w.days}>{w.label}</option>)}
            </select>
            <select className="cv-select" aria-label="Sort" value={filter.sort} onChange={event => update({ sort: event.target.value as IocFilter['sort'] })}>
              <option value="last_seen">Most recent</option>
              <option value="alerts">Most matches</option>
            </select>
            {isFetching && <span className="cv-muted cv-small">Updating…</span>}
          </div>

          <div className="cv-tablewrap">
            <table className="cv-table" style={{ minWidth: 720 }}>
              <thead><tr><th>Type</th><th>Indicator</th><th>Hosts</th><th>Severity</th><th className="is-num">Matches</th><th>Last seen</th><th>Action</th></tr></thead>
              <tbody>
                {(data?.items ?? []).map(ioc => (
                  <tr key={`${ioc.type}:${ioc.value}`} className={isSelected(ioc) ? 'is-active' : undefined} style={{ cursor: 'pointer' }}
                    tabIndex={0} onClick={() => setSelected(ioc)}
                    onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(ioc) } }}>
                    <td><Chip>{TYPE_LABEL[ioc.type]}</Chip></td>
                    <td className="cv-mono" style={{ maxWidth: 320 }}>
                      <button type="button" className="cv-rowlink cv-mono" title={`${ioc.value} · copy`} style={{ fontWeight: 400, display: 'inline-flex', gap: 6, alignItems: 'center', maxWidth: '100%' }}
                        onClick={event => { event.stopPropagation(); copy(ioc.value) }}>
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{shortValue(ioc)}</span>
                        {copied === ioc.value ? <Check size={11} className="cv-t-good" /> : <Copy size={11} style={{ opacity: 0.45, flex: 'none' }} />}
                      </button>
                    </td>
                    <td className="cv-dim">{ioc.hosts}</td>
                    <td>{ioc.max_severity ? <Chip tone={severityTone(ioc.max_severity)}>{ioc.max_severity}</Chip> : '—'}</td>
                    <td className="is-num">{ioc.alerts}</td>
                    <td className="cv-dim cv-small" style={{ whiteSpace: 'nowrap' }}>{ago(ioc.last_seen)}</td>
                    <td>{ioc.blocked ? <span className="cv-t-bad">Block</span> : ioc.alerts > 0 ? <span className="cv-t-warn">Alert</span> : <span className="cv-t-info">Watch</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {isError && <Empty>Could not load indicators.</Empty>}
            {isLoading && <Empty>Loading indicators…</Empty>}
            {!isLoading && !isError && !data?.items.length && <Empty>No indicators in this window.</Empty>}
          </div>
          {data && data.total > IOC_PAGE && (
            <div className="cv-row cv-small">
              <button type="button" className="cv-btn cv-btn--sm" disabled={filter.offset === 0} onClick={() => setFilter(f => ({ ...f, offset: Math.max(0, f.offset - IOC_PAGE) }))}>Previous</button>
              <span className="cv-muted">{filter.offset + 1}–{Math.min(filter.offset + IOC_PAGE, data.total)} of {data.total.toLocaleString('en-US')}</span>
              <button type="button" className="cv-btn cv-btn--sm" disabled={filter.offset + IOC_PAGE >= data.total} onClick={() => setFilter(f => ({ ...f, offset: f.offset + IOC_PAGE }))}>Next</button>
              {data.total >= 1000 && <span className="cv-muted">Top 1,000 of this window; search or narrow it to see others.</span>}
            </div>
          )}
        </section>

        <aside className="cv-list" aria-label="Indicator detail and feeds" style={{ flex: '1 1 320px', maxWidth: 380, borderRight: 0, borderLeft: '1px solid #222733', padding: '20px', gap: 12 }}>
          {selected && <IocDetail key={`${selected.type}:${selected.value}`} ioc={selected} onClose={() => setSelected(null)} />}
          <section className="cv-card">
            <div className="cv-card__head">
              <h2>Feed health</h2>
              {staleFeeds > 0 && <Chip tone="warn">{staleFeeds} need attention</Chip>}
            </div>
            <div className="cv-kv">
              {feeds.map(item => (
                <div key={item.name}>
                  <span style={{ display: 'flex', gap: 8, alignItems: 'center', color: '#C9D0DB' }}><span className={`cv-dot cv-dot--${item.tone}`} />{item.name}</span>
                  <span className={item.tone === 'bad' ? 'cv-t-bad' : item.tone === 'warn' ? 'cv-t-warn' : 'cv-dim'}>{item.state}</span>
                </div>
              ))}
              {feeds.length === 0 && <span className="cv-muted cv-small">No feed status available.</span>}
            </div>
          </section>
          <section className="cv-card">
            <h2>Where indicators come from</h2>
            <p className="cv-dim" style={{ margin: 0 }}>
              Every IP, domain, URL, hash and email an alert carries is recorded here. Block one from its detail to push it to endpoints; hashes go to the malware list.
            </p>
            <Link to="/settings">Feed keys and retention in settings</Link>
          </section>
        </aside>
      </div>
    </CanvasPage>
  )
}

function IocDetail({ ioc, onClose }: { readonly ioc: Ioc; readonly onClose: () => void }) {
  const { data, isLoading, isError } = useIocAlerts(ioc)
  const hunt = useStartHunt()
  const addHash = useAddMalwareHashes()
  const block = useBlockWeb()
  const navigate = useNavigate()
  const kind = huntType(ioc.type)
  return (
    <section className="cv-card cv-card--accent">
      <div className="cv-card__head" style={{ flexWrap: 'nowrap', alignItems: 'flex-start' }}>
        <div className="cv-stack">
          <span className="cv-eyebrow">{TYPE_LABEL[ioc.type]}</span>
          <span className="cv-mono" style={{ fontSize: 13 }}>{ioc.value}</span>
        </div>
        <button type="button" className="cv-btn cv-btn--sm" onClick={onClose} aria-label="Close indicator detail">×</button>
      </div>
      <div className="cv-kv">
        <div><span>Alerts</span><span>{ioc.alerts}</span></div>
        <div><span>Hosts</span><span>{ioc.hosts}</span></div>
        <div><span>First seen</span><span>{ago(ioc.first_seen)}</span></div>
        <div><span>Last seen</span><span>{ago(ioc.last_seen)}</span></div>
      </div>
      <div className="cv-row">
        {kind && <button type="button" className="cv-btn cv-btn--sm" disabled={hunt.isPending}
          onClick={() => hunt.mutate({ ioc_type: kind, ioc_value: ioc.value }, { onSuccess: created => navigate(`/hunts?hunt=${created.id}`) })}>Hunt</button>}
        {ioc.type === 'sha256' && <button type="button" className="cv-btn cv-btn--sm" disabled={addHash.isPending || addHash.isSuccess}
          onClick={() => addHash.mutate({ hashes: [ioc.value], label: '', reference: 'Threat IoCs' })}>{addHash.isSuccess ? 'Added to malware hashes' : 'Add to malware hashes'}</button>}
        {(ioc.type === 'domain' || ioc.type === 'url') && (ioc.blocked
          ? <Chip tone="bad">Blocked on endpoints</Chip>
          : <button type="button" className="cv-btn cv-btn--sm cv-btn--danger" disabled={block.isPending || block.isSuccess}
            onClick={() => block.mutate({ value: ioc.value, reason: `Threat IoC seen in ${ioc.alerts} alert(s)` })}>{block.isSuccess ? 'Blocked' : 'Block web'}</button>)}
        {ioc.type === 'ip' && <Link className="cv-btn cv-btn--sm" to={`/events?q=${encodeURIComponent(`source_ip:${ioc.value}`)}&range=7d`}>Search events</Link>}
      </div>
      {hunt.isError && <p className="cv-t-bad cv-small" style={{ margin: 0 }}>Hunt could not be started.</p>}
      {addHash.isError && <p className="cv-t-bad cv-small" style={{ margin: 0 }}>Could not add the hash.</p>}
      {block.isError && <p className="cv-t-bad cv-small" style={{ margin: 0 }}>{apiError(block.error, 'Could not block.')}</p>}
      <h3 className="cv-h3">Alerts with this indicator</h3>
      {isError ? <span className="cv-t-bad cv-small">Could not load alerts.</span>
        : isLoading ? <span className="cv-muted cv-small">Loading…</span>
        : !data?.items.length ? <span className="cv-muted cv-small">No alerts visible to you.</span>
        : <div className="cv-feed">{data.items.slice(0, 8).map(alert => (
          <div key={alert.id} style={{ flexDirection: 'column', gap: 2 }}>
            <Link to={`/alerts?alert=${alert.id}`} style={{ color: '#E8ECF2' }}>{alert.title}</Link>
            <span className="cv-muted cv-small">
              <span className={`cv-t-${severityTone(alert.severity)}`}>{alert.severity}</span> · {alert.hostname ?? 'no host'} · {ago(alert.created_at)}{alert.ai_verdict ? ` · AI: ${alert.ai_verdict}` : ''}
            </span>
          </div>
        ))}</div>}
    </section>
  )
}
