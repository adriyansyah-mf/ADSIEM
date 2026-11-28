import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight, Pause, Play } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '@/api/client'
import { QueryState } from '@/components/Workspace'
import { emitToast } from '@/hooks/useToast'
import { useAuthStore } from '@/stores/auth'
import { ASSET_TIERS, assetTierLabel } from '@/lib/assetTier'

// A case's alerts as an entity graph you step through in time order
// (canvas: Case · Relation graph).

interface Step { alert_id: string; title: string; severity: string; at: string; kill_chain_stage: string | null; entities: string[] }
interface Node { key: string; kind: string; value: string; first_step: number; alerts: number; facts: Record<string, string>; asset_tier: number | null; asset_role: string | null }
interface Edge { a: string; b: string; first_step: number }
interface Graph { steps: Step[]; nodes: Node[]; edges: Edge[]; truncated: number }

const NODE_W = 160
const NODE_H = 58
const ROW = 78
const KIND_LABEL: Readonly<Record<string, string>> = { host: 'Host', user: 'User', process: 'Process', file: 'File', hash: 'File hash', ip: 'IP address', domain: 'Domain' }
const KIND_COLUMN: Readonly<Record<string, number>> = { user: 0, hash: 0, host: 1, process: 2, file: 3, ip: 3, domain: 3 }
const SEARCH_FIELD: Readonly<Record<string, string>> = {
  host: 'host.name', user: 'user.name', process: 'process.executable', file: 'file.path', hash: 'file.hash.sha256', ip: 'destination.ip', domain: 'dns.question.name',
}
const IOC_KINDS = new Set(['ip', 'domain', 'hash', 'host'])
const TIER_COLOR = ['#FF8D98', '#FFB46E', '#9DB4FF', '#A9B2C1']
const PLAY_MS = 1600

type Layout = 'type' | 'time'

function place(nodes: readonly Node[], layout: Layout) {
  const columns = new Map<number, Node[]>()
  for (const node of [...nodes].sort((a, b) => a.first_step - b.first_step)) {
    const col = layout === 'type' ? KIND_COLUMN[node.kind] ?? 3 : node.first_step
    columns.set(col, [...(columns.get(col) ?? []), node])
  }
  const order = [...columns.keys()].sort((a, b) => a - b)
  const gap = layout === 'type' ? 200 : 190
  const pos = new Map<string, { x: number; y: number }>()
  let height = 0
  order.forEach((col, i) => {
    const list = columns.get(col) ?? []
    list.forEach((node, row) => pos.set(node.key, { x: 20 + i * gap, y: 20 + row * ROW }))
    height = Math.max(height, 20 + list.length * ROW)
  })
  return { pos, width: Math.max(780, 40 + (order.length - 1) * gap + NODE_W), height: Math.max(300, height + 10) }
}

function searchQuery(node: Node) {
  const value = node.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  return `${SEARCH_FIELD[node.kind] ?? 'message'}:"${value}"`
}

export default function CaseEntityGraph({ caseId }: { readonly caseId: string }) {
  const queryClient = useQueryClient()
  const canManage = useAuthStore(state => state.hasRole('analyst'))
  const graph = useQuery<Graph>({
    queryKey: ['case-entity-graph', caseId],
    queryFn: () => api.get(`/api/cases/${caseId}/entity-graph`).then(r => r.data),
  })
  const [step, setStep] = useState<number | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [playing, setPlaying] = useState(false)
  const [layout, setLayout] = useState<Layout>('type')
  const data = graph.data
  const last = Math.max(0, (data?.steps.length ?? 1) - 1)
  const current = step ?? last
  const addIoc = useMutation({
    mutationFn: (node: Node) => api.post(`/api/cases/${caseId}/iocs`, { kind: node.kind, value: node.value }).then(r => r.data as { added: boolean }),
    onSuccess: result => {
      void queryClient.invalidateQueries({ queryKey: ['case', caseId] })
      void queryClient.invalidateQueries({ queryKey: ['cases'] })
      emitToast(result.added ? 'Added to the case indicators' : 'Already in the case indicators', 'success')
    },
    onError: () => emitToast('Could not add the indicator', 'error'),
  })

  useEffect(() => {
    if (!playing) return
    const timer = window.setInterval(() => {
      setStep(s => {
        const next = (s ?? -1) + 1
        if (next >= last) setPlaying(false)
        return Math.min(next, last)
      })
    }, PLAY_MS)
    return () => window.clearInterval(timer)
  }, [playing, last])

  const layoutData = useMemo(() => place(data?.nodes ?? [], layout), [data, layout])
  if (graph.isPending) return <QueryState kind="loading" title="Building the relation graph…" />
  if (graph.isError) return <QueryState kind="error" title="Could not build the relation graph" onRetry={() => { void graph.refetch() }} />
  if (!data || data.steps.length === 0) return <p className="cw-muted">This case has no linked alerts to draw.</p>

  const inStep = new Set(data.steps[current]?.entities ?? [])
  const nodes = new Map(data.nodes.map(n => [n.key, n]))
  const sel = nodes.get(selected ?? '') ?? data.nodes.find(n => n.kind === 'host') ?? data.nodes[0]
  const stateOf = (n: Node) => inStep.has(n.key) ? 'now' : n.first_step < current ? 'seen' : n.first_step > current ? 'later' : 'seen'
  const times = data.steps.map(s => format(new Date(s.at), 'HH:mm'))
  const tierHint = sel?.asset_tier != null ? ASSET_TIERS.find(t => t.tier === sel.asset_tier)?.hint : undefined
  const startPlay = () => { if (current >= last) setStep(0); setPlaying(p => !p) }

  return (
    <div className="eg">
      <aside className="eg-steps" aria-label="Alerts in this case">
        <h3>Sequence · step {current + 1} of {data.steps.length}</h3>
        {data.steps.map((s, i) => (
          <button key={s.alert_id} type="button" aria-current={i === current ? 'step' : undefined}
            className={`eg-step ${i === current ? 'eg-step--on' : i < current ? 'eg-step--done' : ''}`}
            onClick={() => { setPlaying(false); setStep(i) }}>
            <span className="eg-step__n">{i + 1}</span>
            <span className="eg-step__text"><span>{s.title}</span><span className="eg-mono">{format(new Date(s.at), 'HH:mm')} · {s.kill_chain_stage?.replace(/_/g, ' ') ?? s.severity}</span></span>
          </button>
        ))}
        {data.truncated > 0 && <p className="cw-muted eg-pad">{data.truncated} later alerts are not drawn.</p>}
      </aside>

      <section className="eg-main" aria-label="Entity graph">
        <div className="eg-bar">
          <div className="eg-legend">
            <span><i className="eg-key eg-key--now" />In this step</span>
            <span><i className="eg-key eg-key--seen" />Seen earlier</span>
            <span className="eg-dim"><i className="eg-key eg-key--later" />Not yet involved</span>
          </div>
          <button type="button" className="eg-btn" onClick={() => setLayout(l => l === 'type' ? 'time' : 'type')}>Layout: by {layout}</button>
        </div>
        <div className="eg-scroll">
          <div className="eg-canvas" style={{ width: layoutData.width, height: layoutData.height }}>
            <svg width={layoutData.width} height={layoutData.height} aria-hidden="true">
              {data.edges.map(e => {
                const a = layoutData.pos.get(e.a), b = layoutData.pos.get(e.b)
                if (!a || !b) return null
                const active = inStep.has(e.a) && inStep.has(e.b) && e.first_step <= current
                const visible = e.first_step <= current
                return <line key={`${e.a}|${e.b}`} x1={a.x + NODE_W / 2} y1={a.y + NODE_H / 2} x2={b.x + NODE_W / 2} y2={b.y + NODE_H / 2}
                  stroke={active ? '#2F6BDB' : '#4A5266'} strokeWidth={active ? 2 : 1.5} strokeDasharray={visible ? undefined : '4 4'} opacity={visible ? 1 : 0.35} />
              })}
            </svg>
            {data.nodes.map(n => {
              const p = layoutData.pos.get(n.key)
              if (!p) return null
              const tier = n.asset_tier != null ? `Tier ${n.asset_tier}` : ''
              return (
                <button key={n.key} type="button" className={`eg-node eg-node--${stateOf(n)}`} aria-pressed={sel?.key === n.key}
                  aria-label={`${KIND_LABEL[n.kind] ?? n.kind} ${n.value}`} style={{ left: p.x, top: p.y }} onClick={() => setSelected(n.key)}>
                  <span className="eg-node__kind"><span>{KIND_LABEL[n.kind] ?? n.kind}</span>{tier && <span style={{ color: TIER_COLOR[n.asset_tier ?? 3] }}>{tier}</span>}</span>
                  <span className="eg-node__value" title={n.value}>{n.value}</span>
                </button>
              )
            })}
          </div>
        </div>
        <div className="eg-player">
          <div className="eg-player__btns">
            <button type="button" className="eg-btn eg-btn--sq" aria-label="Previous step" disabled={current === 0} onClick={() => { setPlaying(false); setStep(Math.max(0, current - 1)) }}><ChevronLeft size={14} /></button>
            <button type="button" className="eg-play" onClick={startPlay}>{playing ? <Pause size={14} aria-hidden="true" /> : <Play size={14} aria-hidden="true" />}{playing ? 'Pause' : 'Play sequence'}</button>
            <button type="button" className="eg-btn eg-btn--sq" aria-label="Next step" disabled={current >= last} onClick={() => { setPlaying(false); setStep(Math.min(last, current + 1)) }}><ChevronRight size={14} /></button>
          </div>
          <div className="eg-progress">
            <div className="eg-progress__track"><div style={{ width: `${data.steps.length > 1 ? (current / last) * 100 : 100}%` }} /></div>
            <div className="eg-mono eg-progress__ticks"><span>{times[0]}</span>{times.length > 1 && <span>{times[times.length - 1]}</span>}</div>
          </div>
          <span className="eg-player__label">Step {current + 1} of {data.steps.length}</span>
        </div>
      </section>

      {sel && (
        <aside className="eg-side" aria-label="Selected entity">
          <div>
            <span className="eg-side__kind">{KIND_LABEL[sel.kind] ?? sel.kind}</span>
            <h3 className="eg-mono">{sel.value}</h3>
          </div>
          {sel.kind === 'host' && (
            <div className="eg-tier">
              <span>Asset criticality</span>
              <strong style={{ color: sel.asset_tier != null ? TIER_COLOR[sel.asset_tier] ?? '#A9B2C1' : '#A9B2C1' }}>{assetTierLabel(sel.asset_tier, sel.asset_role)}</strong>
              <span className="cw-muted">{tierHint ?? 'Not classified yet. Set the tier on the Agents page.'}</span>
            </div>
          )}
          <dl className="eg-facts">
            <div className="eg-facts__row"><dt>First seen</dt><dd>Step {sel.first_step + 1}, {times[sel.first_step]}</dd></div>
            {Object.entries(sel.facts).map(([k, v]) => <div key={k} className="eg-facts__row"><dt>{k}</dt><dd>{v}</dd></div>)}
          </dl>
          <div className="eg-side__actions">
            <Link className="eg-btn eg-btn--wide" to={`/logs?q=${encodeURIComponent(searchQuery(sel))}`}>Search activity for this entity</Link>
            {canManage && IOC_KINDS.has(sel.kind) && (
              <button type="button" className="eg-btn eg-btn--wide" disabled={addIoc.isPending} onClick={() => addIoc.mutate(sel)}>
                {addIoc.isPending ? 'Adding…' : sel.kind === 'host' ? 'Add as affected host' : 'Add as case IoC'}
              </button>
            )}
          </div>
        </aside>
      )}
    </div>
  )
}
