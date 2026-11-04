import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { PointerEvent as ReactPointerEvent } from 'react'
import { geoBounds, geoContains, geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo'
import type { ExtendedFeature, ExtendedFeatureCollection } from 'd3-geo'
import { feature } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import { Minus, Plus, RotateCcw } from 'lucide-react'
import worldData from 'world-atlas/countries-110m.json'
import type { GeoPoint, GeoRecentAlert } from '@/hooks/useMetrics'
import { SEVERITY_COLOR } from '@/lib/severityColors'

const W = 960
const H = 500
const MIN_K = 1
const MAX_K = 10

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const

type CountryFeature = ExtendedFeature<GeoJSON.Geometry, { name: string }>
interface View { readonly k: number; readonly x: number; readonly y: number }
export interface MapTarget { readonly lat: number; readonly lon: number; readonly label: string }
export interface MapFocus { readonly key: string; readonly coords: readonly (readonly [number, number])[] }

// The world geometry and projection never change, so build them once per page load.
const topology = worldData as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>
const COUNTRIES: readonly CountryFeature[] = (feature(topology, topology.objects.countries) as ExtendedFeatureCollection<CountryFeature>)
  .features.filter(f => f.properties.name !== 'Antarctica')
const projection = geoNaturalEarth1().fitExtent([[8, 8], [W - 8, H - 8]],
  { type: 'FeatureCollection', features: [...COUNTRIES] } as ExtendedFeatureCollection<CountryFeature>)
const path = geoPath(projection)
const GRATICULE = path(geoGraticule10()) ?? ''
const COUNTRY_SHAPES = COUNTRIES.map(f => ({ feature: f, name: f.properties.name, d: path(f) ?? '', bounds: geoBounds(f) }))

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))
const clampView = ({ k, x, y }: View): View => ({ k, x: clamp(x, W - W * k, 0), y: clamp(y, H - H * k, 0) })

function project(lon: number, lat: number): [number, number] | null {
  const p = projection([lon, lat])
  return p ? [p[0], p[1]] : null
}

function arcPath(from: [number, number], to: [number, number]) {
  const [x0, y0] = from
  const [x1, y1] = to
  const dx = x1 - x0
  const dy = y1 - y0
  const dist = Math.hypot(dx, dy)
  // Bow the arc to the left of travel, always bulging "up" the screen so arcs read as flight paths.
  const sign = dx >= 0 ? -1 : 1
  const cx = (x0 + x1) / 2 + sign * dy * 0.25
  const cy = (y0 + y1) / 2 - Math.abs(dx) * 0.25 - dist * 0.05
  return `M${x0.toFixed(1)},${y0.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`
}

function inBounds([[w, s], [e, n]]: [[number, number], [number, number]], lon: number, lat: number) {
  if (lat < s || lat > n) return false
  return w <= e ? lon >= w && lon <= e : lon >= w || lon <= e // antimeridian-crossing countries
}

const timeAgo = (iso: string | null) => {
  if (!iso) return 'unknown'
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000)
  return m < 1 ? 'just now' : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`
}

export default function AttackMap({ points, target, fresh, selectedIp, onSelect, focus, showArcs, wheelZoom }: {
  readonly points: readonly GeoPoint[]
  readonly target: MapTarget | null
  /** Alerts that arrived since the previous refresh; animated as projectiles toward the target. */
  readonly fresh: readonly GeoRecentAlert[]
  readonly selectedIp: string | null
  readonly onSelect: (ip: string | null) => void
  readonly focus: MapFocus | null
  readonly showArcs: boolean
  /** Plain wheel zooms (wall mode). Otherwise Ctrl/⌘ + wheel zooms so page scrolling keeps working. */
  readonly wheelZoom: boolean
}) {
  const svgRef = useRef<SVGSVGElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const [view, setView] = useState<View>({ k: 1, x: 0, y: 0 })
  const [animating, setAnimating] = useState(false)
  const [hover, setHover] = useState<{ point: GeoPoint; x: number; y: number } | null>(null)
  const [hint, setHint] = useState(false)
  const drag = useRef<{ id: number; sx: number; sy: number; vx: number; vy: number; moved: boolean } | null>(null)

  const animateTo = useCallback((next: View) => {
    setAnimating(true)
    setView(clampView(next))
    window.setTimeout(() => setAnimating(false), 450)
  }, [])

  const zoomAt = useCallback((factor: number, px = W / 2, py = H / 2, smooth = true) => {
    setView(v => {
      const k = clamp(v.k * factor, MIN_K, MAX_K)
      const next = clampView({ k, x: px - (px - v.x) * (k / v.k), y: py - (py - v.y) * (k / v.k) })
      return next
    })
    if (smooth) { setAnimating(true); window.setTimeout(() => setAnimating(false), 300) }
  }, [])

  const toViewBox = useCallback((clientX: number, clientY: number): [number, number] => {
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect || rect.width === 0) return [W / 2, H / 2]
    return [(clientX - rect.left) * (W / rect.width), (clientY - rect.top) * (H / rect.height)]
  }, [])

  // Native, non-passive wheel listener: React's onWheel cannot preventDefault page scroll.
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    let hintTimer = 0
    const onWheel = (event: WheelEvent) => {
      if (!wheelZoom && !event.ctrlKey && !event.metaKey) {
        setHint(true)
        window.clearTimeout(hintTimer)
        hintTimer = window.setTimeout(() => setHint(false), 1200)
        return
      }
      event.preventDefault()
      const [px, py] = toViewBox(event.clientX, event.clientY)
      zoomAt(Math.exp(-event.deltaY * 0.0025), px, py, false)
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => { svg.removeEventListener('wheel', onWheel); window.clearTimeout(hintTimer) }
  }, [toViewBox, wheelZoom, zoomAt])

  useEffect(() => {
    if (!focus) return
    const projected = focus.coords.map(([lon, lat]) => project(lon, lat)).filter((p): p is [number, number] => p !== null)
    if (projected.length === 0) return
    const xs = projected.map(p => p[0])
    const ys = projected.map(p => p[1])
    const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)]
    const k = clamp(0.7 * Math.min(W / Math.max(x1 - x0, 40), H / Math.max(y1 - y0, 40)), 2, 6)
    animateTo({ k, x: W / 2 - k * (x0 + x1) / 2, y: H / 2 - k * (y0 + y1) / 2 })
    // Re-run only when a new focus is requested, not when the same focus object is re-created.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focus?.key, animateTo])

  const maxCount = useMemo(() => Math.max(1, ...points.map(p => p.count)), [points])
  const radius = useCallback((count: number) => 2.5 + 9 * Math.sqrt(count / maxCount), [maxCount])

  const projectedPoints = useMemo(() => points
    .map(point => ({ point, xy: project(point.lon, point.lat) }))
    .filter((p): p is { point: GeoPoint; xy: [number, number] } => p.xy !== null)
    // Draw low severity first so critical markers sit on top.
    .sort((a, b) => SEVERITY_ORDER.indexOf(b.point.max_severity as typeof SEVERITY_ORDER[number])
      - SEVERITY_ORDER.indexOf(a.point.max_severity as typeof SEVERITY_ORDER[number])), [points])

  const heat = useMemo(() => {
    const totals = new Map<string, number>()
    for (const { lon, lat, count } of points) {
      const shape = COUNTRY_SHAPES.find(c => inBounds(c.bounds, lon, lat) && geoContains(c.feature, [lon, lat]))
      if (shape) totals.set(shape.name, (totals.get(shape.name) ?? 0) + count)
    }
    const max = Math.max(1, ...totals.values())
    return { totals, max }
  }, [points])

  const targetLat = target?.lat
  const targetLon = target?.lon
  const targetXY = useMemo(() => targetLat === undefined || targetLon === undefined ? null : project(targetLon, targetLat),
    [targetLat, targetLon])
  const arcs = useMemo(() => {
    if (!targetXY || !showArcs) return []
    return [...points].sort((a, b) => b.count - a.count).slice(0, 80)
      .map(point => ({ point, xy: project(point.lon, point.lat) }))
      .filter((a): a is { point: GeoPoint; xy: [number, number] } => a.xy !== null && Math.hypot(a.xy[0] - targetXY[0], a.xy[1] - targetXY[1]) > 4)
      .map(({ point, xy }) => ({ point, d: arcPath(xy, targetXY) }))
  }, [points, showArcs, targetXY])

  const projectiles = useMemo(() => {
    if (!targetXY) return []
    return fresh.map(alert => ({ alert, xy: project(alert.lon, alert.lat) }))
      .filter((p): p is { alert: GeoRecentAlert; xy: [number, number] } => p.xy !== null)
      .map(({ alert, xy }) => ({ alert, xy, d: arcPath(xy, targetXY) }))
  }, [fresh, targetXY])

  const onPointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (event.button !== 0) return
    drag.current = { id: event.pointerId, sx: event.clientX, sy: event.clientY, vx: view.x, vy: view.y, moved: false }
  }
  const onPointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    const d = drag.current
    if (!d || d.id !== event.pointerId) return
    const rect = svgRef.current?.getBoundingClientRect()
    const scale = rect && rect.width ? W / rect.width : 1
    const dx = (event.clientX - d.sx) * scale
    const dy = (event.clientY - d.sy) * scale
    if (!d.moved && Math.hypot(dx, dy) < 4) return
    if (!d.moved) { d.moved = true; svgRef.current?.setPointerCapture(event.pointerId); setHover(null) }
    setView(v => clampView({ k: v.k, x: d.vx + dx, y: d.vy + dy }))
  }
  const endDrag = (event: ReactPointerEvent<SVGSVGElement>) => {
    const d = drag.current
    if (d && d.id === event.pointerId && d.moved) {
      svgRef.current?.releasePointerCapture(event.pointerId)
      // Swallow the click that follows a drag so panning never selects a marker.
      window.setTimeout(() => { drag.current = null }, 0)
      return
    }
    drag.current = null
  }
  const wasDrag = () => drag.current?.moved === true

  const showTooltip = (point: GeoPoint, event: ReactPointerEvent<SVGElement>) => {
    if (drag.current?.moved) return
    const rect = wrapRef.current?.getBoundingClientRect()
    if (!rect) return
    setHover({ point, x: event.clientX - rect.left, y: event.clientY - rect.top })
  }

  const k = view.k
  return <div className="attack-map" ref={wrapRef}>
    <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="attack-map__svg" role="img"
      aria-label={`Attack origin map: ${points.length} geolocated source addresses${target ? `, paths toward ${target.label}` : ''}. The origin list beside the map holds the same data.`}
      onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={endDrag} onPointerCancel={endDrag}
      onPointerLeave={() => setHover(null)}
      onDoubleClick={event => { const [px, py] = toViewBox(event.clientX, event.clientY); zoomAt(2, px, py) }}
      onClick={() => { if (!wasDrag()) onSelect(null) }}>
      <defs>
        <radialGradient id="attack-map-glow">
          <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity="0.55" />
          <stop offset="100%" stopColor="var(--accent-cyan)" stopOpacity="0" />
        </radialGradient>
      </defs>
      <g className={animating ? 'attack-map__layer is-animating' : 'attack-map__layer'}
        style={{ transform: `translate(${view.x}px, ${view.y}px) scale(${k})` }}>
        <path d={GRATICULE} className="attack-map__graticule" vectorEffect="non-scaling-stroke" />
        {COUNTRY_SHAPES.map(shape => {
          const n = heat.totals.get(shape.name) ?? 0
          const level = n ? 0.18 + 0.62 * Math.sqrt(n / heat.max) : 0
          return <path key={shape.name} d={shape.d} className="attack-map__country" vectorEffect="non-scaling-stroke"
            style={n ? { fill: `color-mix(in srgb, var(--accent-cyan) ${Math.round(level * 100)}%, var(--map-land))` } : undefined}
            onDoubleClick={event => {
              event.stopPropagation()
              const [[x0, y0], [x1, y1]] = path.bounds(shape.feature)
              const nk = clamp(0.8 * Math.min(W / (x1 - x0), H / (y1 - y0)), 1.5, MAX_K)
              animateTo({ k: nk, x: W / 2 - nk * (x0 + x1) / 2, y: H / 2 - nk * (y0 + y1) / 2 })
            }}>
            <title>{n ? `${shape.name}: ${n.toLocaleString()} alerts` : shape.name}</title>
          </path>
        })}

        {arcs.map(({ point, d }) => <path key={`arc-${point.ip}`} d={d} vectorEffect="non-scaling-stroke"
          className={`attack-map__arc${selectedIp && selectedIp !== point.ip ? ' is-dimmed' : ''}`}
          style={{ stroke: SEVERITY_COLOR[point.max_severity] ?? 'var(--text-muted)', strokeWidth: 0.8 + 1.8 * Math.sqrt(point.count / maxCount) }} />)}

        {projectiles.map(({ alert, xy, d }) => <g key={`shot-${alert.id}`} className="attack-map__projectile">
          <circle cx={xy[0]} cy={xy[1]} r={4 / k} className="attack-map__ripple" style={{ stroke: SEVERITY_COLOR[alert.severity] }} vectorEffect="non-scaling-stroke" />
          <circle r={3 / k} style={{ fill: SEVERITY_COLOR[alert.severity] ?? 'var(--text-primary)' }}>
            <animateMotion dur="1.8s" repeatCount="1" fill="freeze" path={d} />
          </circle>
        </g>)}

        {projectedPoints.map(({ point, xy }) => {
          const r = radius(point.count) / k
          const color = SEVERITY_COLOR[point.max_severity] ?? 'var(--text-muted)'
          const selected = selectedIp === point.ip
          return <g key={point.ip} className="attack-map__point" transform={`translate(${xy[0]},${xy[1]})`}
            onPointerEnter={event => showTooltip(point, event)} onPointerMove={event => showTooltip(point, event)}
            onPointerLeave={() => setHover(null)}
            onClick={event => { event.stopPropagation(); if (!wasDrag()) onSelect(selected ? null : point.ip) }}>
            {point.max_severity === 'critical' && <circle r={r} className="attack-map__pulse" style={{ stroke: color }} vectorEffect="non-scaling-stroke" />}
            <circle r={r} style={{ fill: color }} className="attack-map__dot" vectorEffect="non-scaling-stroke" />
            {selected && <circle r={r + 4 / k} className="attack-map__selected" vectorEffect="non-scaling-stroke" />}
          </g>
        })}

        {targetXY && <g transform={`translate(${targetXY[0]},${targetXY[1]})`} className="attack-map__target">
          <circle r={22 / k} fill="url(#attack-map-glow)" />
          <circle r={4.5 / k} className="attack-map__target-dot" vectorEffect="non-scaling-stroke" />
          <text y={-9 / k} textAnchor="middle" style={{ fontSize: 11 / k }}>{target?.label}</text>
        </g>}
      </g>
    </svg>

    {hover && <div className="attack-map__tooltip" role="tooltip"
      style={{ left: Math.min(hover.x + 14, (wrapRef.current?.clientWidth ?? 0) - 230), top: Math.max(hover.y - 12, 4) }}>
      <strong className="font-mono">{hover.point.ip}</strong>
      <span>{[hover.point.city, hover.point.country].filter(Boolean).join(', ') || 'Unknown location'}</span>
      <span className="attack-map__tooltip-count">{hover.point.count.toLocaleString()} alerts · last {timeAgo(hover.point.last_seen)}</span>
      <span className="attack-map__sev-row">
        {SEVERITY_ORDER.filter(s => hover.point.by_severity[s]).map(s => <span key={s} style={{ color: SEVERITY_COLOR[s] }}>
          {s} {hover.point.by_severity[s]}</span>)}
      </span>
      <span className="attack-map__tooltip-hint">Click to inspect</span>
    </div>}

    <div className="attack-map__controls" role="group" aria-label="Map zoom">
      <button type="button" className="ui-icon-button" onClick={() => zoomAt(1.6)} aria-label="Zoom in" title="Zoom in" disabled={k >= MAX_K}><Plus size={16} /></button>
      <button type="button" className="ui-icon-button" onClick={() => zoomAt(1 / 1.6)} aria-label="Zoom out" title="Zoom out" disabled={k <= MIN_K}><Minus size={16} /></button>
      <button type="button" className="ui-icon-button" onClick={() => animateTo({ k: 1, x: 0, y: 0 })} aria-label="Reset view" title="Reset view" disabled={k === 1 && view.x === 0 && view.y === 0}><RotateCcw size={16} /></button>
    </div>

    <div className="attack-map__legend" aria-hidden="true">
      {SEVERITY_ORDER.map(s => <span key={s}><i style={{ background: SEVERITY_COLOR[s] }} />{s}</span>)}
      <span className="attack-map__legend-heat"><i />alert volume</span>
    </div>

    {hint && <div className="attack-map__hint" aria-hidden="true">Hold Ctrl (⌘) and scroll to zoom</div>}
  </div>
}
