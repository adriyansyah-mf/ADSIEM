import { Fragment, useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronDown, ChevronRight, RefreshCw, Search } from 'lucide-react'
import { format } from 'date-fns'
import QueryBuilder, { EMPTY_GROUP, isEmptyTree, type Group } from '@/components/QueryBuilder'
import { TelemetryDetails, type TelemetryRecord } from '@/components/TelemetryDetails'
import { useCursorPagination } from '@/hooks/useCursorPagination'
import { useTelemetryFacets, useTelemetryRecords, type TimeWindow } from '@/hooks/useTelemetryRecords'
import { useAgents } from '@/hooks/useAgents'
import SavedSearchBar from '@/components/SavedSearchBar'
import { CanvasHeader, CanvasPage, Empty, Meter } from '@/components/canvas/Canvas'

type Kind = 'logs' | 'events'
const FIELDS: Readonly<Record<Kind, string[]>> = {
  logs: ['log_type', 'raw_message', 'agent_id', 'created_at', 'decoded_fields.source.ip', 'decoded_fields.user.name'],
  events: ['event_category', 'event_action', 'source_ip', 'user_name', 'group_id', 'created_at', 'decoded_fields.source.ip', 'decoded_fields.user.name'],
}

const RANGES = [
  { value: '15m', label: 'Last 15 minutes', ms: 15 * 60_000 },
  { value: '1h', label: 'Last hour', ms: 3_600_000 },
  { value: '4h', label: 'Last 4 hours', ms: 4 * 3_600_000 },
  { value: '24h', label: 'Last 24 hours', ms: 24 * 3_600_000 },
  { value: '7d', label: 'Last 7 days', ms: 7 * 86_400_000 },
  { value: '30d', label: 'Last 30 days', ms: 30 * 86_400_000 },
] as const

const MODES = [
  { to: '/logs', label: 'Logs' },
  { to: '/events', label: 'Endpoint events' },
  { to: '/live-events', label: 'Live tail' },
]

function quote(value: string) {
  return /^[\w.:\\/-]+$/.test(value) ? value : `"${value.replace(/[\\"]/g, '\\$&')}"`
}

export default function TelemetryExplorer({ kind }: { readonly kind: Kind }) {
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const range = RANGES.find(item => item.value === params.get('range')) ?? RANGES[3]
  const from = params.get('from')
  const to = params.get('to')
  const [draft, setDraft] = useState(search)
  const [showBuilder, setShowBuilder] = useState(false)
  const [tree, setTree] = useState<Group>(EMPTY_GROUP)
  const [applied, setApplied] = useState<Group>(EMPTY_GROUP)
  const [preferredPageSize, setPreferredPageSize] = useState(50)
  // The relative window is anchored when the query changes, so pages and the chart agree.
  const [anchor, setAnchor] = useState(() => Date.now())
  useEffect(() => { setDraft(search) }, [search])
  const filterTree = isEmptyTree(applied) ? undefined : JSON.stringify(applied)
  const timeWindow: TimeWindow = useMemo(() => from
    ? { since: from, until: to ?? undefined }
    : { since: new Date(anchor - range.ms).toISOString() }, [from, to, anchor, range.ms])

  const patch = (changes: Record<string, string | null>) => setParams(current => {
    const next = new URLSearchParams(current)
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value)
      else next.delete(key)
    }
    return next
  })
  const runSearch = (value: string) => { setAnchor(Date.now()); patch({ q: value.trim() || null }) }
  const addTerm = (field: string, value: string) => {
    const term = `${field}:${quote(value)}`
    const next = search.trim() ? `${search.trim()} AND ${term}` : term
    setDraft(next)
    runSearch(next)
  }
  const agents = useAgents(1, 500)
  const agentName = useMemo(() => {
    const map = new Map((agents.data?.items ?? []).map(agent => [agent.id, agent.hostname || agent.name]))
    return (id: string | null | undefined) => (id && map.get(id)) || id || '—'
  }, [agents.data])

  const facets = useTelemetryFacets(kind, search || undefined, filterTree, timeWindow)
  const histogram = facets.data?.histogram ?? []
  const peak = Math.max(1, ...histogram.map(bar => bar.count))
  const zoomTo = (index: number) => {
    const bar = histogram[index]
    const next = histogram[index + 1]
    if (!bar) return
    const start = new Date(bar.t)
    const end = next ? new Date(next.t) : new Date(facets.data?.until ?? Date.now())
    patch({ from: start.toISOString(), to: end.toISOString() })
  }

  const ruleHref = `/rules?new=1${search ? `&query=${encodeURIComponent(search)}` : ''}`
  const rangeLabel = from ? `${format(new Date(from), 'dd MMM HH:mm')} – ${to ? format(new Date(to), 'HH:mm') : 'now'}` : range.label

  return (
    <CanvasPage>
      <CanvasHeader
        title="Search"
        crumb={MODES.find(mode => mode.to === `/${kind}`)?.label}
        sub={kind === 'logs' ? 'Original messages from agents and syslog devices' : 'Decoded endpoint activity: process, network, logon and DNS events'}
        tabs={MODES}
        actions={<>
          <SavedSearchBar kind={kind} query={search} filterTree={filterTree} onLoad={saved => {
            setDraft(saved.query); runSearch(saved.query)
            const loaded = (saved.filter_tree as Group | null) ?? EMPTY_GROUP
            setTree(loaded); setApplied(loaded)
          }} />
          <Link className="cv-btn" to={ruleHref}>Save as rule</Link>
          <Link className="cv-btn" to="/dashboards">Add to dashboard</Link>
        </>}
      >
        <form className="cv-querybar" onSubmit={event => { event.preventDefault(); runSearch(draft) }}>
          <label htmlFor="telemetry-query" className="sr-only">Query</label>
          <div className="cv-querybar__input">
            <Search size={16} aria-hidden="true" />
            <input id="telemetry-query" value={draft} onChange={event => setDraft(event.target.value)} spellCheck={false} autoComplete="off"
              placeholder={kind === 'logs' ? 'log_type:linux_auth AND raw_message:"Failed password"' : 'event_action:login_failed AND user_name:root'} />
          </div>
          <select className="cv-select cv-querybar__range" aria-label="Time range" value={from ? 'custom' : range.value}
            onChange={event => { setAnchor(Date.now()); patch({ range: event.target.value, from: null, to: null }) }}>
            {from && <option value="custom">{rangeLabel}</option>}
            {RANGES.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
          <button type="submit" className="cv-btn cv-btn--primary cv-querybar__go">Search</button>
        </form>
        <div className="cv-filters" style={{ paddingBottom: 4 }}>
          <span className="cv-muted">Filters</span>
          {from && <span className="cv-filter">time = {rangeLabel}<button type="button" aria-label="Remove time zoom" onClick={() => patch({ from: null, to: null })}>×</button></span>}
          {filterTree && <span className="cv-filter">{applied.children.length} advanced condition{applied.children.length === 1 ? '' : 's'} ({applied.logic})
            <button type="button" aria-label="Remove advanced filters" onClick={() => { setTree(EMPTY_GROUP); setApplied(EMPTY_GROUP) }}>×</button></span>}
          {search && <span className="cv-filter">query<button type="button" aria-label="Clear query" onClick={() => { setDraft(''); runSearch('') }}>×</button></span>}
          <button type="button" className="cv-filter cv-filter--add" aria-expanded={showBuilder} onClick={() => setShowBuilder(value => !value)}>+ Add filter</button>
          <span className="cv-muted" style={{ marginLeft: 'auto' }}>Lucene: field:value, AND / OR / NOT, quoted phrases, wildcards</span>
        </div>
        {showBuilder && (
          <div className="cv-card" style={{ marginBottom: 12 }}>
            <QueryBuilder node={tree} onChange={setTree} fields={FIELDS[kind]} />
            <div className="cv-row">
              <button type="button" className="cv-btn cv-btn--primary" onClick={() => { setApplied(tree); setShowBuilder(false) }}>Apply filters</button>
              <button type="button" className="cv-btn" onClick={() => { setTree(EMPTY_GROUP); setApplied(EMPTY_GROUP) }}>Reset</button>
            </div>
          </div>
        )}
      </CanvasHeader>

      <div className="cv-split">
        <aside className="cv-list cv-facets" aria-label="Fields">
          {(facets.data?.facets ?? []).map(facet => {
            const max = Math.max(1, ...facet.values.map(value => value.count))
            return (
              <div key={facet.field} className="cv-facet">
                <h3>{facet.field}</h3>
                {facet.values.length === 0 && <span className="cv-muted cv-small">No values</span>}
                {facet.values.map(value => (
                  <button key={value.value} type="button" className="cv-facet__value" title={`Add ${facet.field}:${value.value} to the query`}
                    onClick={() => addTerm(facet.field, value.value)}>
                    <span className="cv-row cv-row--between" style={{ width: '100%', flexWrap: 'nowrap' }}>
                      <span className="cv-facet__label">{facet.field === 'agent_id' ? agentName(value.value) : value.value}</span>
                      <span className="cv-muted" style={{ fontVariantNumeric: 'tabular-nums' }}>{value.count.toLocaleString('en-US')}</span>
                    </span>
                    <Meter value={(value.count / max) * 100} />
                  </button>
                ))}
              </div>
            )
          })}
          {facets.isError && <Empty>Field summary unavailable.</Empty>}
          {facets.isPending && <Empty>Summarising fields…</Empty>}
        </aside>

        <section className="cv-pane" aria-label="Results">
          <div className="cv-row cv-row--between" style={{ alignItems: 'baseline' }}>
            <p style={{ margin: 0, fontSize: 14 }}>
              <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{facets.data ? facets.data.total.toLocaleString('en-US') : '–'}</strong>{' '}
              <span className="cv-dim">{kind === 'logs' ? 'log lines' : 'events'}{facets.data ? ` · ${(facets.data.took_ms / 1000).toFixed(2)} s` : ''}</span>
            </p>
            <span className="cv-muted cv-small">Click a bar to zoom the time range</span>
          </div>
          <div className="cv-hist" role="img" aria-label={`Event count histogram, ${rangeLabel}`}>
            {histogram.map((bar, index) => (
              <span key={bar.t} title={`${format(new Date(bar.t), 'dd MMM HH:mm')} · ${bar.count.toLocaleString('en-US')}`}
                style={{ height: `${bar.count ? Math.max(3, (bar.count / peak) * 100) : 0}%`, cursor: 'zoom-in' }}
                onClick={() => zoomTo(index)} />
            ))}
          </div>
          <TelemetryResults key={JSON.stringify([kind, search, filterTree, timeWindow])} kind={kind} search={search} filterTree={filterTree}
            timeWindow={timeWindow} agentName={agentName} onFilter={addTerm}
            initialPageSize={preferredPageSize} onPageSizeChange={setPreferredPageSize} />
        </section>
      </div>
    </CanvasPage>
  )
}

function flatten(value: unknown, prefix = '', out: [string, string][] = []): [string, string][] {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) flatten(inner, prefix ? `${prefix}.${key}` : key, out)
  } else if (prefix) {
    out.push([prefix, Array.isArray(value) ? value.join(', ') : String(value ?? '')])
  }
  return out
}

function summary(row: TelemetryRecord): string {
  if ('raw_message' in row) return row.raw_message
  const fields = flatten(row.decoded_fields).filter(([, value]) => value)
  const preferred = fields.filter(([key]) => /command|image|process|query|dest|destination|target|path|message/i.test(key))
  return (preferred.length ? preferred : fields).slice(0, 3).map(([key, value]) => `${key.split('.').pop()}=${value}`).join(' · ')
}

/** A new query remounts this boundary so old search_after cursors cannot leak. */
function TelemetryResults({ kind, search, filterTree, timeWindow, agentName, onFilter, initialPageSize, onPageSizeChange }: {
  readonly kind: Kind; readonly search: string; readonly filterTree?: string; readonly timeWindow: TimeWindow
  readonly agentName: (id: string | null | undefined) => string
  readonly onFilter: (field: string, value: string) => void
  readonly initialPageSize: number; readonly onPageSizeChange: (size: number) => void
}) {
  const pagination = useCursorPagination(initialPageSize)
  const { page, pageSize, after, onPageData, goToPage, changePageSize } = pagination
  const [selected, setSelected] = useState<TelemetryRecord | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [rawOpen, setRawOpen] = useState(false)
  const query = useTelemetryRecords<TelemetryRecord>(kind, pageSize, after, search || undefined, filterTree, timeWindow)
  useEffect(() => { if (!query.isPlaceholderData) onPageData(query.data?.next_after) }, [query.data?.next_after, query.isPlaceholderData, onPageData])
  const loading = query.isPending || query.isPlaceholderData
  const items = query.data?.items ?? []

  return <>
    <div className="cv-tablewrap">
      <table className="cv-table" style={{ minWidth: 720 }}>
        <thead><tr>
          <th style={{ width: 28 }}><span className="sr-only">Expand</span></th>
          <th>Time</th>
          <th>{kind === 'logs' ? 'Type' : 'Event'}</th>
          <th>{kind === 'logs' ? 'Agent' : 'User'}</th>
          <th>Detail</th>
        </tr></thead>
        <tbody>
          {items.map(row => {
            const isOpen = open === row.id
            const at = 'raw_message' in row ? row.received_at : row.created_at
            const type = 'raw_message' in row ? row.log_type ?? 'unknown' : row.event_action ?? row.event_category ?? 'event'
            const who = 'raw_message' in row ? agentName(row.agent_id) : row.user_name ?? agentName(row.agent_id)
            const fields = 'raw_message' in row
              ? [['log_type', row.log_type], ['agent', agentName(row.agent_id)], ['agent_id', row.agent_id]] as [string, string | null][]
              : [['event_action', row.event_action], ['event_category', row.event_category], ['user_name', row.user_name],
                ['source_ip', row.source_ip], ['agent', agentName(row.agent_id)], ...flatten(row.decoded_fields).slice(0, 12)] as [string, string | null][]
            return (
              <Fragment key={row.id}>
                <tr className={isOpen ? 'is-active' : undefined}>
                  <td>
                    <button type="button" className="cv-btn--link" aria-label={isOpen ? 'Collapse event' : 'Expand event'} aria-expanded={isOpen}
                      style={{ border: 0, background: 'transparent', color: '#8A94A6', padding: 0, cursor: 'pointer' }}
                      onClick={() => { setOpen(isOpen ? null : row.id); setRawOpen(false) }}>
                      {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>
                  </td>
                  <td className="cv-mono cv-dim" style={{ whiteSpace: 'nowrap' }}><time dateTime={at} title={at}>{format(new Date(at), 'dd MMM HH:mm:ss.SSS')}</time></td>
                  <td><span className="cv-chip cv-chip--muted" style={{ fontWeight: 500 }}>{type}</span></td>
                  <td className="cv-mono" style={{ whiteSpace: 'nowrap' }}>{who}</td>
                  <td className="cv-mono cv-trunc" style={{ color: '#C9D0DB' }} title={summary(row)}>{summary(row)}</td>
                </tr>
                {isOpen && (
                  <tr className="is-active">
                    <td />
                    <td colSpan={4} style={{ paddingTop: 0 }}>
                      <div className="cv-eventgrid">
                        {fields.filter(([, value]) => value).map(([key, value]) => (
                          <span key={key}><span className="cv-muted">{key}</span> {value}</span>
                        ))}
                      </div>
                      {'raw_message' in row && <pre className="cv-pre" style={{ marginTop: 8 }}>{row.raw_message}</pre>}
                      {rawOpen && !('raw_message' in row) && <pre className="cv-pre" style={{ marginTop: 8 }}>{JSON.stringify(row.decoded_fields, null, 2)}</pre>}
                      <div className="cv-row" style={{ gap: 12, marginTop: 8, fontSize: 12.5 }}>
                        {'source_ip' in row && row.source_ip && <button type="button" className="cv-btn cv-btn--link" onClick={() => onFilter('source_ip', row.source_ip!)}>Filter on this IP</button>}
                        {row.agent_id && <button type="button" className="cv-btn cv-btn--link" onClick={() => onFilter('agent_id', row.agent_id!)}>Filter on this host</button>}
                        {'user_name' in row && row.user_name && <button type="button" className="cv-btn cv-btn--link" onClick={() => onFilter('user_name', row.user_name!)}>Filter on this user</button>}
                        {!('raw_message' in row) && <button type="button" className="cv-btn cv-btn--link" onClick={() => setRawOpen(value => !value)}>{rawOpen ? 'Hide raw JSON' : 'View raw JSON'}</button>}
                        <button type="button" className="cv-btn cv-btn--link" onClick={() => setSelected(row)}>Open evidence view</button>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
      {query.isError && (
        <div className="cv-empty">
          Could not load {kind}. Your query is kept; check its syntax and try again.{' '}
          <button type="button" className="cv-btn cv-btn--link" onClick={() => { void query.refetch() }}>Retry</button>
        </div>
      )}
      {!query.isError && loading && <Empty>Loading {kind}…</Empty>}
      {!query.isError && !loading && items.length === 0 && <Empty>{search || filterTree ? 'Nothing matches. Widen the time range or remove a filter.' : `No ${kind} in this time range.`}</Empty>}
    </div>
    <div className="cv-row cv-row--between cv-small cv-muted">
      <span>
        {query.isFetching ? 'Updating…' : query.data ? `Page ${page} · ${items.length} shown · updated ${format(new Date(query.dataUpdatedAt), 'HH:mm:ss')}` : ''}
      </span>
      <div className="cv-row">
        <button type="button" className="cv-btn cv-btn--sm" disabled={query.isFetching} onClick={() => { void query.refetch() }}><RefreshCw size={13} /> Refresh</button>
        <select className="cv-select cv-btn--sm" aria-label="Results per page" value={pageSize} disabled={query.isFetching} onChange={event => {
          const size = Number(event.target.value)
          changePageSize(size)
          onPageSizeChange(size)
        }}>
          {[25, 50, 100].map(size => <option key={size} value={size}>{size} / page</option>)}
        </select>
        <button type="button" className="cv-btn cv-btn--sm" disabled={page <= 1 || query.isFetching} onClick={() => goToPage(page - 1)}>Previous</button>
        <button type="button" className="cv-btn cv-btn--sm" disabled={query.isFetching || query.isError || !query.data?.next_after} onClick={() => goToPage(page + 1)}>Next</button>
      </div>
    </div>
    {selected && <TelemetryDetails record={selected} onClose={() => setSelected(null)} />}
  </>
}
