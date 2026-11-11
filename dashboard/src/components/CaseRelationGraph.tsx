import { useMemo, useState } from 'react'
import { useQueries } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Case } from '@/types'
import SeverityBadge from './SeverityBadge'

// Related cases as a network graph that shows *why* cases are related: case
// nodes link to the hosts and indicators they contain, so two cases sharing a
// host meet at that host's node. This case sits in the centre, the shared
// hosts/indicators on the inner ring, the related cases on the outer ring next
// to what they share. A related case with nothing in common is tied to the
// centre by a dashed "campaign" edge (grouped by campaign correlation).
// Hover or focus a node to highlight its neighbours; click or Enter opens a case.

const SEVERITY_COLOR: Readonly<Record<string, string>> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-cyan)',
}

const MAX_CASES = 12
const MAX_ENTITIES = 14
const R_ENTITY = 150
const R_CASE = 300
const HALF = 380 // viewBox half-size

type EntityKind = 'host' | 'ioc'

interface CaseNode {
  kind: 'case'
  id: string
  data?: Case
  state: 'loading' | 'error' | 'ok'
  center: boolean
  x: number
  y: number
}
interface EntityNode {
  kind: EntityKind
  id: string // "host:otakunesia" / "ioc:ip:1.2.3.4"
  label: string
  x: number
  y: number
}
type GraphNode = CaseNode | EntityNode
interface Edge { from: string; to: string; campaign?: boolean }

function hostsOf(c?: Pick<Case, 'ioc_data'>): string[] {
  if (!c) return []
  const ioc = (c.ioc_data ?? {}) as Record<string, unknown>
  const hosts = (ioc.affected_hosts as string[] | undefined) ?? (ioc.hostname ? [String(ioc.hostname)] : [])
  return [...new Set(hosts.filter(Boolean))]
}

function keysOf(c?: Pick<Case, 'ioc_data'>): string[] {
  if (!c) return []
  const ioc = (c.ioc_data ?? {}) as Record<string, unknown>
  return [...new Set(((ioc.ioc_keys as string[] | undefined) ?? []).filter(Boolean))]
}

function entitiesOf(c?: Case): string[] {
  return [...hostsOf(c).map(h => `host:${h}`), ...keysOf(c).map(k => `ioc:${k}`)]
}

function truncate(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s
}

const polar = (r: number, a: number) => ({ x: r * Math.cos(a), y: r * Math.sin(a) })

// Mean direction of a set of angles (NaN when empty).
function meanAngle(angles: number[]) {
  if (!angles.length) return Number.NaN
  const s = angles.reduce((acc, a) => acc + Math.sin(a), 0)
  const c = angles.reduce((acc, a) => acc + Math.cos(a), 0)
  return Math.atan2(s, c)
}

export default function CaseRelationGraph({ center, relatedIds, onOpen }: {
  readonly center: Case
  readonly relatedIds: readonly string[]
  readonly onOpen: (id: string) => void
}) {
  // related_cases is appended in time order: the newest are drawn, the rest listed
  const ids = useMemo(() => [...new Set(relatedIds)].filter(id => id !== center.id).reverse(), [relatedIds, center.id])
  const shown = useMemo(() => ids.slice(0, MAX_CASES), [ids])
  const older = useMemo(() => ids.slice(MAX_CASES), [ids])
  const queries = useQueries({
    queries: shown.map(id => ({
      queryKey: ['case', id],
      queryFn: () => api.get<Case>(`/api/cases/${id}`).then(r => r.data),
      staleTime: 60_000,
      retry: 1,
    })),
  })
  const [active, setActive] = useState<string | null>(null)

  const graph = useMemo(() => {
    const related = shown.map((id, i) => {
      const q = queries[i]
      return { id, data: q?.data, state: (q?.data ? 'ok' : q?.isError ? 'error' : 'loading') as CaseNode['state'] }
    })
    const centerEnts = new Set(entitiesOf(center))

    // an entity is worth a node when it links this case to another, or two others
    const owners = new Map<string, Set<string>>()
    const own = (ent: string, caseId: string) => {
      if (!owners.has(ent)) owners.set(ent, new Set())
      owners.get(ent)!.add(caseId)
    }
    centerEnts.forEach(e => own(e, center.id))
    related.forEach(r => entitiesOf(r.data).forEach(e => own(e, r.id)))
    const entities = [...owners.entries()]
      .filter(([, cs]) => cs.size >= 2)
      .sort(([a, ca], [b, cb]) => (a.startsWith('host:') === b.startsWith('host:') ? cb.size - ca.size : a.startsWith('host:') ? -1 : 1))
      .slice(0, MAX_ENTITIES)
      .map(([ent]) => ent)

    const nodes = new Map<string, GraphNode>()
    nodes.set(center.id, { kind: 'case', id: center.id, data: center, state: 'ok', center: true, x: 0, y: 0 })
    const entAngle = new Map<string, number>()
    entities.forEach((ent, i) => {
      const a = -Math.PI / 2 + (i / entities.length) * Math.PI * 2
      entAngle.set(ent, a)
      const kind: EntityKind = ent.startsWith('host:') ? 'host' : 'ioc'
      nodes.set(ent, { kind, id: ent, label: ent.slice(kind === 'host' ? 5 : 4), ...polar(R_ENTITY, a) })
    })

    // each related case sits on the outer ring, as close as it can to what it shares
    const want = related.map((r, i) => {
      const a = meanAngle(entitiesOf(r.data).filter(e => entAngle.has(e)).map(e => entAngle.get(e)!))
      return { r, a: Number.isNaN(a) ? (i / Math.max(1, related.length)) * Math.PI * 2 : a }
    }).sort((p, q) => p.a - q.a)
    // keep that order but spread evenly so the boxes never overlap
    const step = (Math.PI * 2) / Math.max(1, want.length)
    const offset = want.length ? meanAngle(want.map((w, i) => w.a - i * step)) : 0
    want.forEach((w, i) => {
      nodes.set(w.r.id, { kind: 'case', id: w.r.id, data: w.r.data, state: w.r.state, center: false, ...polar(R_CASE, offset + i * step) })
    })

    const edges: Edge[] = []
    const entSet = new Set(entities)
    for (const caseId of [center.id, ...related.map(r => r.id)]) {
      const c = caseId === center.id ? center : related.find(r => r.id === caseId)?.data
      const linked = entitiesOf(c).filter(e => entSet.has(e))
      linked.forEach(e => edges.push({ from: caseId, to: e }))
      if (caseId !== center.id && linked.length === 0) edges.push({ from: center.id, to: caseId, campaign: true })
    }
    return { nodes, edges }
  }, [shown, queries, center])

  const neighbours = useMemo(() => {
    if (!active) return null
    const set = new Set([active])
    graph.edges.forEach(e => {
      if (e.from === active) set.add(e.to)
      if (e.to === active) set.add(e.from)
    })
    return set
  }, [active, graph.edges])

  const focused = active ? graph.nodes.get(active) : undefined
  const sharedWithCenter = (c?: Case) => {
    const mine = new Set(entitiesOf(center))
    return entitiesOf(c).filter(e => mine.has(e))
  }

  const nodeLabel = (n: GraphNode) => n.kind === 'case'
    ? (n.data ? `${n.center ? 'This case' : 'Related case'}: ${n.data.title} — ${n.data.severity}, ${n.data.status}, ${n.data.alert_count} alerts`
      : `Related case ${n.id.slice(0, 8)}${n.state === 'error' ? ' (unavailable)' : ''}`)
    : `${n.kind === 'host' ? 'Host' : 'Indicator'} ${n.label}, shared by ${graph.edges.filter(e => e.to === n.id).length} cases`

  return (
    <div className="case-graph">
      <div className="case-graph__scroll">
      <svg className="case-graph__canvas" viewBox={`${-HALF} ${-HALF} ${HALF * 2} ${HALF * 2}`} role="group"
        aria-label={`Related cases network: ${ids.length} related case${ids.length === 1 ? '' : 's'}`}>
        <g className="case-graph__edges">
          {graph.edges.map(e => {
            const a = graph.nodes.get(e.from)
            const b = graph.nodes.get(e.to)
            if (!a || !b) return null
            const lit = neighbours ? neighbours.has(e.from) && neighbours.has(e.to) : false
            return (
              <line key={`${e.from}>${e.to}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                className={`case-graph__edge${e.campaign ? ' case-graph__edge--campaign' : ''}${lit ? ' case-graph__edge--lit' : ''}`}
                opacity={neighbours && !lit ? 0.12 : undefined} />
            )
          })}
        </g>

        {[...graph.nodes.values()].map(n => {
          const dim = neighbours && !neighbours.has(n.id)
          const common = {
            transform: `translate(${n.x} ${n.y})`,
            opacity: dim ? 0.25 : 1,
            tabIndex: 0,
            'aria-label': nodeLabel(n),
            onMouseEnter: () => setActive(n.id),
            onMouseLeave: () => setActive(cur => (cur === n.id ? null : cur)),
            onFocus: () => setActive(n.id),
          }
          if (n.kind === 'case') {
            const color = n.data ? SEVERITY_COLOR[n.data.severity] ?? 'var(--text-muted)' : 'var(--text-muted)'
            const w = n.center ? 200 : 160
            const h = n.center ? 52 : 40
            const faded = n.data && (n.data.status === 'resolved' || n.data.status === 'closed')
            const title = n.data ? n.data.title.replace(/^🚨\s*/, '') : `case ${n.id.slice(0, 8)}`
            return (
              <g key={n.id} {...common} role={n.center ? 'img' : 'link'}
                className={`case-graph__node case-graph__case${n.center ? ' case-graph__case--center' : ''}${faded ? ' case-graph__case--faded' : ''}`}
                onClick={n.center ? undefined : () => onOpen(n.id)}
                onKeyDown={n.center ? undefined : e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(n.id) } }}>
                <rect x={-w / 2} y={-h / 2} width={w} height={h} rx={8} className="case-graph__box" style={{ stroke: color }} />
                <rect x={-w / 2} y={-h / 2} width={5} height={h} rx={2} style={{ fill: color }} />
                <text x={-w / 2 + 12} y={n.center ? -6 : -3} className="case-graph__title">{truncate(title, n.center ? 27 : 22)}</text>
                <text x={-w / 2 + 12} y={n.center ? 13 : 12} className="case-graph__sub">
                  {n.data ? `${n.data.severity.charAt(0).toUpperCase()}${n.data.severity.slice(1)} · ${n.data.alert_count} alert${n.data.alert_count === 1 ? '' : 's'}` : n.state === 'error' ? 'unavailable' : 'loading…'}
                </text>
                {active === n.id && <rect x={-w / 2 - 4} y={-h / 2 - 4} width={w + 8} height={h + 8} rx={10} className="case-graph__ring" />}
              </g>
            )
          }
          return (
            <g key={n.id} {...common} role="img" className={`case-graph__node case-graph__entity case-graph__entity--${n.kind}`}>
              <rect x={-44} y={-14} width={88} height={44} fill="transparent" />{/* hit area: shape and label */}
              {n.kind === 'host'
                ? <rect x={-9} y={-9} width={18} height={18} rx={4} className="case-graph__entity-shape" />
                : <rect x={-8} y={-8} width={16} height={16} transform="rotate(45)" className="case-graph__entity-shape" />}
              <text y={24} textAnchor="middle" className="case-graph__entity-label">{truncate(n.label, 22)}</text>
              {active === n.id && <circle r={16} className="case-graph__ring" />}
            </g>
          )
        })}
      </svg>
      </div>

      <div className="case-graph__info" aria-live="polite">
        {focused?.kind === 'case' && !focused.center ? (
          <>
            <div className="case-graph__info-title">{focused.data?.title ?? `Case ${focused.id.slice(0, 8)}`}</div>
            {focused.data && (
              <div className="case-graph__meta">
                <SeverityBadge severity={focused.data.severity} />
                <span className="case-graph__status">{focused.data.status.replace(/_/g, ' ')}</span>
                <span>{focused.data.alert_count} alert{focused.data.alert_count === 1 ? '' : 's'}</span>
              </div>
            )}
            {focused.state === 'error' && <div className="case-graph__muted">This case could not be loaded.</div>}
            {focused.state === 'ok' && (() => {
              const shared = sharedWithCenter(focused.data)
              return shared.length
                ? <div className="case-graph__shared">Shares with this case: <b>{shared.slice(0, 4).map(e => e.replace(/^(host|ioc):/, '')).join(', ')}</b>{shared.length > 4 && ` +${shared.length - 4}`}</div>
                : <div className="case-graph__muted">Grouped by campaign correlation; no host or indicator in common with this case.</div>
            })()}
            <button className="case-graph__open" onClick={() => onOpen(focused.id)}>Open case →</button>
          </>
        ) : focused && focused.kind !== 'case' ? (
          <>
            <div className="case-graph__info-title">{focused.kind === 'host' ? 'Host' : 'Indicator'}: <span className="case-graph__mono">{focused.label}</span></div>
            <div className="case-graph__muted">
              Shared by {graph.edges.filter(e => e.to === focused.id).length} of the cases shown — this is what links them.
            </div>
          </>
        ) : (
          <div className="case-graph__muted">
            {older.length > 0
              ? <>Showing this case and the {shown.length} newest of {ids.length} related cases. </>
              : <>{ids.length} related case{ids.length === 1 ? '' : 's'}. </>}
            Lines run from each case to the hosts and indicators it contains, so cases that share one meet at its node;
            dashed lines are cases grouped by campaign with nothing in common. Hover or tab to a node to highlight its links.
          </div>
        )}
        <div className="case-graph__legend" aria-hidden="true">
          <span><i className="case-graph__legend-case" />case</span>
          <span><i className="case-graph__legend-host" />host</span>
          <span><i className="case-graph__legend-ioc" />indicator</span>
          <span><i className="case-graph__legend-campaign" />campaign link</span>
        </div>
        {older.length > 0 && (
          <details className="case-graph__older">
            <summary>{older.length} older related case{older.length === 1 ? '' : 's'}</summary>
            <div className="case-graph__older-ids">
              {older.map(id => (
                <button key={id} className="case-graph__link" onClick={() => onOpen(id)}>{id.slice(0, 8)}</button>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  )
}
