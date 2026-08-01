import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Alert } from '@/types'
import AlertDetailModal from '@/components/AlertDetailModal'

export interface TimelineItem {
  type: 'alert' | 'note'
  id: string
  ts: string
  title: string
  severity?: string
  source_ip?: string | null
  hostname?: string | null
  is_this_case?: boolean
  mitre_techniques?: string[]
  kill_chain_stage?: string | null
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ff2244', high: '#ff6b00', medium: '#ffd700', low: '#00ff88', info: '#00d4ff',
}
const NOTE_COLOR = '#6b8aad'

// Canonical MITRE ATT&CK kill-chain order — matches the enum the AI campaign
// analyzer already writes to case notes (worker/worker/llm_client.py). Only
// stages actually present in this case's alerts get a lane.
const STAGE_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
  'Command & Control', 'Exfiltration', 'Impact',
]

function fmtShort(ts: string) {
  return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })
}
function fmtFull(ts: string) {
  return new Date(ts).toLocaleString('en-US', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}
function truncate(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

const CHIPS: { key: string; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: SEV_COLOR.critical },
  { key: 'high', label: 'High', color: SEV_COLOR.high },
  { key: 'medium', label: 'Medium', color: SEV_COLOR.medium },
  { key: 'low', label: 'Low', color: SEV_COLOR.low },
  { key: 'info', label: 'Info', color: SEV_COLOR.info },
  { key: 'note', label: 'Notes', color: NOTE_COLOR },
]

export default function AttackGraph({ items }: { items: TimelineItem[] }) {
  const [filters, setFilters] = useState<Record<string, boolean>>({
    critical: true, high: true, medium: true, low: true, info: true, note: true,
  })
  const [selected, setSelected] = useState<TimelineItem | null>(null)
  const [hovered, setHovered] = useState<string | null>(null)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [openAlertId, setOpenAlertId] = useState<string | null>(null)
  const svgRef = useRef<SVGSVGElement | null>(null)
  const dragRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null)

  const alerts = useMemo(() => items.filter(i => i.type === 'alert'), [items])
  const notes = useMemo(() => items.filter(i => i.type === 'note'), [items])

  const lanes = useMemo(() => {
    const present = new Set(alerts.map(a => a.kill_chain_stage || 'Unknown'))
    const ordered = STAGE_ORDER.filter(s => present.has(s))
    if (present.has('Unknown')) ordered.push('Unknown')
    if (notes.length > 0) ordered.push('Notes')
    return ordered.length > 0 ? ordered : ['Unknown']
  }, [alerts, notes])

  const W = 980
  const padL = 132, padR = 28, padT = 14, padB = 34
  const laneH = 58
  const H = padT + padB + lanes.length * laneH

  const domain = useMemo(() => {
    const tss = alerts.map(a => new Date(a.ts).getTime())
    if (tss.length === 0) return { min: Date.now() - 3600_000, max: Date.now() }
    const min = Math.min(...tss), max = Math.max(...tss)
    return { min, max: max > min ? max : min + 60_000 }
  }, [alerts])

  const xFor = (ts: string) => {
    const frac = Math.min(1, Math.max(0, (new Date(ts).getTime() - domain.min) / (domain.max - domain.min)))
    return padL + frac * (W - padL - padR)
  }
  const yFor = (stage: string | null | undefined) => {
    const idx = lanes.indexOf(stage || 'Unknown')
    return padT + Math.max(0, idx) * laneH + laneH / 2
  }
  const yForNote = () => padT + (lanes.indexOf('Notes')) * laneH + laneH / 2

  const visibleAlerts = alerts.filter(a => filters[a.severity || 'info'])
  const visibleNotes = notes.filter(() => filters.note)

  const entityLabel = useMemo(() => {
    const ip = alerts.find(a => a.source_ip)?.source_ip
    const host = alerts.find(a => a.hostname)?.hostname
    return [ip, host].filter(Boolean).join(' → ')
  }, [alerts])

  const pathD = useMemo(() => {
    if (visibleAlerts.length < 2) return ''
    let d = `M ${xFor(visibleAlerts[0].ts)} ${yFor(visibleAlerts[0].kill_chain_stage)}`
    for (let i = 1; i < visibleAlerts.length; i++) {
      const x0 = xFor(visibleAlerts[i - 1].ts), y0 = yFor(visibleAlerts[i - 1].kill_chain_stage)
      const x1 = xFor(visibleAlerts[i].ts), y1 = yFor(visibleAlerts[i].kill_chain_stage)
      const mx = (x0 + x1) / 2
      d += ` C ${mx} ${y0}, ${mx} ${y1}, ${x1} ${y1}`
    }
    return d
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleAlerts, lanes])

  // pan (drag) + wheel zoom — native listeners so preventDefault actually works on wheel
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      setZoom(z => Math.min(2.4, Math.max(0.6, z + (e.deltaY > 0 ? -0.08 : 0.08))))
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [])

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!dragRef.current) return
      setPan({ x: dragRef.current.panX + (e.clientX - dragRef.current.x), y: dragRef.current.panY + (e.clientY - dragRef.current.y) })
    }
    const onUp = () => { dragRef.current = null }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp) }
  }, [])

  const { data: fullAlert } = useQuery<Alert>({
    queryKey: ['alert', openAlertId],
    queryFn: () => api.get(`/api/alerts/${openAlertId}`).then(r => r.data),
    enabled: !!openAlertId,
  })

  if (alerts.length === 0) {
    return (
      <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', padding: '8px 0' }}>
        No related events found in ±24h window.
      </div>
    )
  }

  return (
    <div>
      {/* toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {CHIPS.map(c => {
            const on = filters[c.key]
            return (
              <button
                key={c.key}
                onClick={() => setFilters(f => ({ ...f, [c.key]: !f[c.key] }))}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer',
                  fontFamily: 'Share Tech Mono, monospace', fontSize: 10, letterSpacing: '.5px', textTransform: 'uppercase',
                  padding: '4px 9px', borderRadius: 20,
                  border: `1px solid ${on ? c.color : 'var(--border)'}`,
                  background: on ? `${c.color}22` : 'var(--bg-panel)',
                  color: on ? c.color : 'var(--text-muted)',
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor' }} />
                {c.label}
              </button>
            )
          })}
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button onClick={() => setZoom(z => Math.max(0.6, z - 0.15))} style={zoomBtnStyle}>−</button>
          <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 10, color: 'var(--text-muted)', width: 34, textAlign: 'center' }}>{Math.round(zoom * 100)}%</span>
          <button onClick={() => setZoom(z => Math.min(2.4, z + 0.15))} style={zoomBtnStyle}>+</button>
          <button onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }} style={zoomBtnStyle} title="Reset view">⤾</button>
        </div>
      </div>

      {entityLabel && (
        <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--accent-cyan)', marginBottom: 8 }}>
          ENTITY: {entityLabel}
        </div>
      )}

      {/* canvas */}
      <div style={{ position: 'relative', background: 'var(--bg-base)', borderRadius: 6, border: '1px solid var(--border)', overflow: 'hidden' }}>
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          style={{ display: 'block', width: '100%', height: Math.min(420, H), cursor: dragRef.current ? 'grabbing' : 'grab' }}
          onMouseDown={e => { dragRef.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y } }}
        >
          <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
            {/* lanes */}
            {lanes.map((lane, i) => {
              const y = padT + i * laneH
              return (
                <g key={lane}>
                  {i % 2 === 1 && <rect x={0} y={y} width={W} height={laneH} fill="rgba(255,255,255,.02)" />}
                  <line x1={0} y1={y} x2={W} y2={y} stroke="var(--border)" strokeWidth={1} />
                  <text x={12} y={y + laneH / 2 + 3} style={{ font: '9.5px "Share Tech Mono", monospace', letterSpacing: '1px', textTransform: 'uppercase', fill: 'var(--text-muted)' } as React.CSSProperties}>
                    {lane}
                  </text>
                </g>
              )
            })}
            <line x1={0} y1={padT + lanes.length * laneH} x2={W} y2={padT + lanes.length * laneH} stroke="var(--border)" strokeWidth={1} />

            {/* connecting path */}
            {pathD && (
              <path d={pathD} fill="none" stroke="var(--accent-cyan)" strokeWidth={1.6} strokeOpacity={hovered ? 0.18 : 0.55} />
            )}

            {/* note markers */}
            {visibleNotes.map(n => {
              const x = xFor(n.ts), y = yForNote()
              const dim = hovered && hovered !== n.id
              return (
                <g key={n.id} style={{ cursor: 'pointer', opacity: dim ? 0.25 : 1 }}
                   onClick={() => setSelected(n)}
                   onMouseEnter={() => setHovered(n.id)} onMouseLeave={() => setHovered(null)}>
                  <path d={diamond(x, y - 20, 6)} fill="var(--bg-card)" stroke={NOTE_COLOR} strokeWidth={1} />
                  <text x={x} y={y - 28} textAnchor="middle" style={{ font: '9px sans-serif', fill: 'var(--text-secondary)' } as React.CSSProperties}>📝</text>
                </g>
              )
            })}

            {/* alert nodes */}
            {visibleAlerts.map(a => {
              const x = xFor(a.ts), y = yFor(a.kill_chain_stage)
              const color = SEV_COLOR[a.severity || 'info'] || SEV_COLOR.info
              const dim = hovered && hovered !== a.id
              const isSel = selected?.id === a.id
              return (
                <g key={a.id} style={{ cursor: 'pointer', opacity: dim ? 0.25 : 1 }}
                   onClick={() => setSelected(a)}
                   onMouseEnter={() => setHovered(a.id)} onMouseLeave={() => setHovered(null)}>
                  <circle cx={x} cy={y} r={13} fill={color} opacity={0.15} />
                  <circle cx={x} cy={y} r={isSel ? 9 : 6.5} fill={color} stroke="var(--bg-base)" strokeWidth={2} />
                  <text x={x} y={y - 16} textAnchor="middle" style={{ font: '8.5px "Share Tech Mono", monospace', fill: 'var(--text-muted)' } as React.CSSProperties}>
                    {fmtShort(a.ts)}
                  </text>
                  <text x={x > W - 200 ? x - 10 : x + 10} y={y + 22} textAnchor={x > W - 200 ? 'end' : 'start'}
                        style={{ font: '600 10.5px Rajdhani, sans-serif', fill: 'var(--text-primary)' } as React.CSSProperties}>
                    {truncate(a.title, 30)}
                  </text>
                </g>
              )
            })}
          </g>
        </svg>

        {/* legend */}
        <div style={{
          position: 'absolute', left: 10, bottom: 8, display: 'flex', gap: 10, flexWrap: 'wrap',
          padding: '5px 9px', background: 'rgba(8,14,26,.85)', border: '1px solid var(--border)', borderRadius: 5,
          fontFamily: 'Share Tech Mono, monospace', fontSize: 9, color: 'var(--text-secondary)', textTransform: 'uppercase',
        }}>
          {CHIPS.map(c => (
            <span key={c.key} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 7, height: 7, borderRadius: c.key === 'note' ? 0 : '50%', background: c.color }} />
              {c.label}
            </span>
          ))}
        </div>
        <div style={{ position: 'absolute', right: 10, bottom: 8, fontFamily: 'Share Tech Mono, monospace', fontSize: 9, color: 'var(--text-muted)' }}>
          drag to pan · scroll to zoom
        </div>
      </div>

      {/* detail drawer */}
      {selected && (
        <>
          <div onClick={() => setSelected(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(2,5,10,.55)', zIndex: 40 }} />
          <div style={{
            position: 'fixed', top: 0, right: 0, bottom: 0, width: 380, maxWidth: '92vw',
            background: 'var(--bg-panel)', borderLeft: '1px solid var(--border)', zIndex: 41,
            display: 'flex', flexDirection: 'column', boxShadow: '-16px 0 40px rgba(0,0,0,.4)',
          }}>
            <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', gap: 10 }}>
              <div>
                <div style={{
                  fontFamily: 'Share Tech Mono, monospace', fontSize: 10, letterSpacing: '1.5px', textTransform: 'uppercase', marginBottom: 6,
                  color: selected.type === 'note' ? 'var(--text-secondary)' : (SEV_COLOR[selected.severity || 'info'] || SEV_COLOR.info),
                }}>
                  {selected.type === 'note' ? 'CASE NOTE' : `${selected.kill_chain_stage || 'Unknown'} · ${(selected.severity || '').toUpperCase()}`}
                </div>
                <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 16, lineHeight: 1.35, color: 'var(--text-primary)' }}>
                  {selected.title}
                </div>
              </div>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: '1px solid var(--border)', color: 'var(--text-secondary)', width: 26, height: 26, borderRadius: 5, cursor: 'pointer', flexShrink: 0 }}>✕</button>
            </div>
            <div style={{ padding: '16px 18px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
              <Field label="Timestamp" mono value={fmtFull(selected.ts)} />
              {selected.type === 'alert' && (
                <>
                  {(selected.source_ip || selected.hostname) && (
                    <Field label="Entity" mono value={[selected.source_ip, selected.hostname].filter(Boolean).join('  →  ')} />
                  )}
                  {!!selected.mitre_techniques?.length && (
                    <div>
                      <div style={fieldLabelStyle}>MITRE ATT&CK</div>
                      <div>
                        {selected.mitre_techniques.map(t => (
                          <span key={t} style={{
                            display: 'inline-block', fontFamily: 'Share Tech Mono, monospace', fontSize: 10, padding: '3px 8px',
                            borderRadius: 3, background: 'rgba(0,212,255,.1)', border: '1px solid #00d4ff33', color: 'var(--accent-cyan)', margin: '0 6px 6px 0',
                          }}>{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  <button
                    onClick={() => setOpenAlertId(selected.id)}
                    style={{
                      marginTop: 'auto', display: 'block', width: '100%', textAlign: 'center', padding: 10, borderRadius: 5,
                      border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,.08)', color: 'var(--accent-cyan)',
                      fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 12, letterSpacing: '1.5px', cursor: 'pointer', textTransform: 'uppercase',
                    }}
                  >
                    Open Full Alert →
                  </button>
                </>
              )}
            </div>
          </div>
        </>
      )}

      {fullAlert && openAlertId && (
        <AlertDetailModal alert={fullAlert} onClose={() => setOpenAlertId(null)} />
      )}
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div style={fieldLabelStyle}>{label}</div>
      <div style={{ fontSize: 13, color: mono ? 'var(--accent-cyan)' : 'var(--text-primary)', fontFamily: mono ? 'Share Tech Mono, monospace' : undefined, lineHeight: 1.55 }}>
        {value}
      </div>
    </div>
  )
}

const fieldLabelStyle: React.CSSProperties = {
  fontFamily: 'Share Tech Mono, monospace', fontSize: 9.5, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 4,
}
const zoomBtnStyle: React.CSSProperties = {
  border: '1px solid var(--border)', background: 'var(--bg-card)', color: 'var(--text-secondary)',
  width: 26, height: 26, borderRadius: 5, cursor: 'pointer', fontSize: 13,
}

function diamond(cx: number, cy: number, r: number) {
  return `M ${cx} ${cy - r} L ${cx + r} ${cy} L ${cx} ${cy + r} L ${cx - r} ${cy} Z`
}
