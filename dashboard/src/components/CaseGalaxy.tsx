import { useMemo, useState } from 'react'
import { useQueries } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Case } from '@/types'
import SeverityBadge from './SeverityBadge'

// Related cases drawn as a small galaxy: this case is the star, every related
// case a planet. A planet's orbit is closer the more hosts and indicators it
// shares with this case, its size follows its alert count, its colour its
// severity; closed work fades. Hover or focus a planet to read why it is
// related, click (or Enter) to open it.

const SEVERITY_COLOR: Readonly<Record<string, string>> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-cyan)',
}

const MAX_PLANETS = 12
const SIZE = 400
const C = SIZE / 2
const RINGS = [74, 116, 158] as const // close, near, far
const BELT_RADIUS = 186
const BELT_MAX_DOTS = 220

function hostsOf(c: Pick<Case, 'ioc_data'>): string[] {
  const ioc = (c.ioc_data ?? {}) as Record<string, unknown>
  const hosts = (ioc.affected_hosts as string[] | undefined) ?? (ioc.hostname ? [String(ioc.hostname)] : [])
  return hosts.filter(Boolean)
}

function keysOf(c: Pick<Case, 'ioc_data'>): string[] {
  const ioc = (c.ioc_data ?? {}) as Record<string, unknown>
  return ((ioc.ioc_keys as string[] | undefined) ?? []).filter(Boolean)
}

// Deterministic 0..1 sequence from a string, so the sky does not reshuffle on
// every render or refetch.
function seeded(seed: string) {
  let h = 2166136261
  for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 16777619)
  return () => {
    h = Math.imul(h ^ (h >>> 15), 2246822507)
    h = Math.imul(h ^ (h >>> 13), 3266489909)
    h ^= h >>> 16
    return (h >>> 0) / 4294967296
  }
}

interface Planet {
  id: string
  data?: Case
  state: 'loading' | 'error' | 'ok'
  sharedHosts: string[]
  sharedKeys: string[]
  ring: number
  angle: number
  r: number
  color: string
  faded: boolean
}

export default function CaseGalaxy({ center, relatedIds, onOpen }: {
  readonly center: Case
  readonly relatedIds: readonly string[]
  readonly onOpen: (id: string) => void
}) {
  // related_cases is appended in time order: the newest become planets, the
  // rest form the asteroid belt (a campaign can relate hundreds of cases)
  const ids = useMemo(() => [...new Set(relatedIds)].filter(id => id !== center.id).reverse(), [relatedIds, center.id])
  const shown = useMemo(() => ids.slice(0, MAX_PLANETS), [ids])
  const extra = useMemo(() => ids.slice(MAX_PLANETS), [ids])
  const queries = useQueries({
    queries: shown.map(id => ({
      queryKey: ['case', id],
      queryFn: () => api.get<Case>(`/api/cases/${id}`).then(r => r.data),
      staleTime: 60_000,
      retry: 1,
    })),
  })
  const [active, setActive] = useState<string | null>(null)

  const centerHosts = useMemo(() => new Set(hostsOf(center)), [center])
  const centerKeys = useMemo(() => new Set(keysOf(center)), [center])

  const planets: Planet[] = useMemo(() => {
    const base = shown.map((id, i) => {
      const q = queries[i]
      const data = q?.data
      const sharedHosts = data ? hostsOf(data).filter(h => centerHosts.has(h)) : []
      const sharedKeys = data ? keysOf(data).filter(k => centerKeys.has(k)) : []
      const affinity = sharedKeys.length * 2 + sharedHosts.length
      return {
        id,
        data,
        state: (data ? 'ok' : q?.isError ? 'error' : 'loading') as Planet['state'],
        sharedHosts,
        sharedKeys,
        ring: !data ? 2 : affinity >= 3 ? 0 : affinity >= 1 ? 1 : 2,
        angle: 0,
        r: data ? 7 + Math.min(9, Math.sqrt(Math.max(0, data.alert_count)) * 1.8) : 6,
        color: data ? SEVERITY_COLOR[data.severity] ?? 'var(--text-muted)' : 'var(--text-muted)',
        faded: !!data && (data.status === 'resolved' || data.status === 'closed'),
      }
    })
    // spread the planets of each ring evenly, each ring starting at its own angle
    const rand = seeded(center.id)
    RINGS.forEach((_, ring) => {
      const onRing = base.filter(p => p.ring === ring)
      const start = rand() * Math.PI * 2
      onRing.forEach((p, i) => { p.angle = start + (i / onRing.length) * Math.PI * 2 })
    })
    return base
  }, [shown, queries, centerHosts, centerKeys, center.id])

  const stars = useMemo(() => {
    const rand = seeded(`${center.id}:stars`)
    return Array.from({ length: 70 }, (_, i) => ({
      x: rand() * SIZE, y: rand() * SIZE, r: rand() * 1.1 + 0.25, o: rand() * 0.6 + 0.2, twinkle: i % 7 === 0,
    }))
  }, [center.id])

  // one dot per older related case (capped), scattered around the outer belt
  const belt = useMemo(() => {
    const rand = seeded(`${center.id}:belt`)
    return Array.from({ length: Math.min(extra.length, BELT_MAX_DOTS) }, () => {
      const a = rand() * Math.PI * 2
      const radius = BELT_RADIUS + (rand() - 0.5) * 14
      return { x: C + radius * Math.cos(a), y: C + radius * Math.sin(a), r: rand() * 1.1 + 0.9 }
    })
  }, [extra.length, center.id])

  const sunColor = SEVERITY_COLOR[center.severity] ?? 'var(--accent-cyan)'
  const focused = planets.find(p => p.id === active)

  return (
    <div className="case-galaxy">
      <svg className="case-galaxy__sky" viewBox={`0 0 ${SIZE} ${SIZE}`} role="group"
        aria-label={`Related cases galaxy: ${ids.length} case${ids.length === 1 ? '' : 's'} around this one`}>
        <defs>
          <radialGradient id="case-galaxy-sun">
            <stop offset="0%" stopColor="#fff" stopOpacity="0.95" />
            <stop offset="35%" style={{ stopColor: sunColor }} stopOpacity="0.9" />
            <stop offset="100%" style={{ stopColor: sunColor }} stopOpacity="0" />
          </radialGradient>
          <radialGradient id="case-galaxy-nebula" cx="35%" cy="40%" r="70%">
            <stop offset="0%" style={{ stopColor: 'var(--accent-cyan)' }} stopOpacity="0.10" />
            <stop offset="60%" style={{ stopColor: 'var(--accent-purple, #a78bfa)' }} stopOpacity="0.05" />
            <stop offset="100%" stopColor="#000" stopOpacity="0" />
          </radialGradient>
          <clipPath id="case-galaxy-clip">
            <circle cx={C} cy={C} r={C} />
          </clipPath>
        </defs>

        <g clipPath="url(#case-galaxy-clip)">
          <rect width={SIZE} height={SIZE} fill="url(#case-galaxy-nebula)" />
          {stars.map((s, i) => (
            <circle key={i} cx={s.x} cy={s.y} r={s.r} fill="#fff" opacity={s.o}
              className={s.twinkle ? 'case-galaxy__twinkle' : undefined} style={{ animationDelay: `${(i % 5) * 0.7}s` }} />
          ))}
        </g>

        {RINGS.map((radius, ring) => (
          <circle key={ring} cx={C} cy={C} r={radius} className="case-galaxy__ring" />
        ))}

        {belt.length > 0 && (
          <g className="case-galaxy__belt" aria-hidden="true">
            {belt.map((d, i) => <circle key={i} cx={d.x} cy={d.y} r={d.r} fill="#b9c3d3" opacity={0.8} />)}
          </g>
        )}

        {RINGS.map((radius, ring) => (
          <g key={ring} className={`case-galaxy__orbit case-galaxy__orbit--${ring}`}>
            {planets.filter(p => p.ring === ring).map(p => {
              const x = C + radius * Math.cos(p.angle)
              const y = C + radius * Math.sin(p.angle)
              const label = p.data
                ? `${p.data.title} — ${p.data.severity}, ${p.data.status}, ${p.data.alert_count} alerts`
                : `case ${p.id.slice(0, 8)}${p.state === 'error' ? ' (unavailable)' : ''}`
              return (
                <g key={p.id} className="case-galaxy__planet" transform={`translate(${x} ${y})`}
                  role="link" tabIndex={0} aria-label={label}
                  onMouseEnter={() => setActive(p.id)} onFocus={() => setActive(p.id)}
                  onClick={() => onOpen(p.id)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(p.id) } }}>
                  <circle r={p.r + 10} fill="transparent" />
                  <circle r={p.r * 2} style={{ fill: p.color }} opacity={p.faded ? 0.06 : 0.16} />
                  <circle r={p.r} style={{ fill: p.color }} opacity={p.faded ? 0.4 : p.state === 'ok' ? 0.95 : 0.35}
                    className={p.state === 'loading' ? 'case-galaxy__pulse' : undefined} />
                  {active === p.id && <circle r={p.r + 5} className="case-galaxy__halo" />}
                </g>
              )
            })}
          </g>
        ))}

        <circle cx={C} cy={C} r={46} fill="url(#case-galaxy-sun)" className="case-galaxy__corona" />
        <circle cx={C} cy={C} r={15} style={{ fill: sunColor }} />
        <circle cx={C} cy={C} r={7} fill="#fff" opacity={0.85} />
      </svg>

      <div className="case-galaxy__info" aria-live="polite">
        {focused ? (
          <>
            <div className="case-galaxy__title">
              {focused.data?.title ?? `Case ${focused.id.slice(0, 8)}`}
            </div>
            {focused.data && (
              <div className="case-galaxy__meta">
                <SeverityBadge severity={focused.data.severity} />
                <span className="case-galaxy__status">{focused.data.status.replace(/_/g, ' ')}</span>
                <span>{focused.data.alert_count} alert{focused.data.alert_count === 1 ? '' : 's'}</span>
              </div>
            )}
            {focused.state === 'error' && <div className="case-galaxy__muted">This case could not be loaded.</div>}
            {focused.state === 'ok' && (focused.sharedHosts.length + focused.sharedKeys.length > 0 ? (
              <div className="case-galaxy__shared">
                {focused.sharedHosts.length > 0 && <div>Shared hosts: <b>{focused.sharedHosts.slice(0, 4).join(', ')}</b></div>}
                {focused.sharedKeys.length > 0 && <div>Shared indicators: <b>{focused.sharedKeys.slice(0, 3).join(', ')}</b>
                  {focused.sharedKeys.length > 3 && ` +${focused.sharedKeys.length - 3}`}</div>}
              </div>
            ) : <div className="case-galaxy__muted">Grouped by campaign correlation; no host or indicator in common with this case.</div>)}
            <button className="case-galaxy__open" onClick={() => onOpen(focused.id)}>Open case →</button>
          </>
        ) : (
          <div className="case-galaxy__muted">
            {extra.length > 0
              ? <>The {shown.length} newest of {ids.length} related cases are planets; the other {extra.length} form the outer belt. </>
              : <>{ids.length} related case{ids.length === 1 ? '' : 's'}. </>}
            Closer orbits share more hosts and indicators; bigger planets have more alerts. Hover or tab to a planet for details.
          </div>
        )}
        <div className="case-galaxy__legend" aria-hidden="true">
          {(['critical', 'high', 'medium', 'low'] as const).map(s => (
            <span key={s}><i style={{ background: SEVERITY_COLOR[s] }} />{s}</span>
          ))}
          <span><i className="case-galaxy__legend-faded" />closed</span>
        </div>
        {extra.length > 0 && (
          <details className="case-galaxy__belt-list">
            <summary>Outer belt: {extra.length} older related case{extra.length === 1 ? '' : 's'}</summary>
            <div className="case-galaxy__belt-ids">
              {extra.map(id => (
                <button key={id} className="case-galaxy__link" onClick={() => onOpen(id)}>{id.slice(0, 8)}</button>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  )
}
