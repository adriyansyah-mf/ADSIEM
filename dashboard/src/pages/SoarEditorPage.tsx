import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import {
  Background, Controls, MiniMap, ReactFlow, ReactFlowProvider, addEdge, useEdgesState, useNodesState, useReactFlow,
} from '@xyflow/react'
import type { Connection, Edge, IsValidConnection, NodeChange } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { AlertTriangle, ArrowLeft, CheckCircle2, Play, Save, ShieldCheck, X } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import {
  apiErrors, useCancelRun, useDecideRun, usePlaybook, usePlaybookRuns, useRun, useRunPlaybook, useSaveGraph,
  useSoarCatalog, useUpdatePlaybook, useValidateGraph,
} from '@/hooks/useSoar'
import { emitToast } from '@/hooks/useToast'
import { useAuthStore } from '@/stores/auth'
import { NODE_META, PALETTE, newNodeId } from '@/components/soar/meta'
import { NodeForm } from '@/components/soar/NodeForm'
import { JsonBlock, S } from '@/components/soar/ui'
import { WorkflowNode } from '@/components/soar/WorkflowNode'
import type { WfFlowNode } from '@/components/soar/WorkflowNode'
import type { Catalog, Graph, NodeType, Playbook, Run, RunDetail, WfNode } from '@/types/soar'

const nodeTypes = { wf: WorkflowNode }
const BAD_OUTPUTS = new Set(['error', 'rejected', 'false', 'no'])

type FlowNode = WfFlowNode & { data: WfFlowNode['data'] & { retry: number; continue_on_error: boolean } }

function toFlowNode(n: WfNode, editable: boolean): FlowNode {
  return {
    id: n.id, type: 'wf', position: { x: n.position[0], y: n.position[1] },
    deletable: editable && n.type !== 'trigger',
    data: { wfType: n.type, label: n.label, params: n.params ?? {}, retry: n.retry ?? 0,
      continue_on_error: n.continue_on_error ?? false },
  }
}

function toFlowEdge(e: { from: string; output: string; to: string }, taken?: boolean): Edge {
  const bad = BAD_OUTPUTS.has(e.output)
  return {
    id: `${e.from}:${e.output}->${e.to}`, source: e.from, sourceHandle: e.output, target: e.to,
    label: e.output === 'main' ? undefined : e.output,
    animated: taken,
    style: { stroke: taken ? 'var(--accent-green)' : bad ? '#ff6b8188' : 'var(--text-secondary)', strokeWidth: taken ? 2.5 : 1.5 },
    labelStyle: { fill: bad ? '#ff6b81' : 'var(--text-secondary)', fontSize: 10 },
    labelBgStyle: { fill: 'var(--bg-base)' },
  }
}

function toGraph(nodes: FlowNode[], edges: Edge[]): Graph {
  return {
    nodes: nodes.map(n => ({
      id: n.id, type: n.data.wfType, label: n.data.label, position: [Math.round(n.position.x), Math.round(n.position.y)],
      params: n.data.params, retry: n.data.retry, continue_on_error: n.data.continue_on_error,
    })),
    edges: edges.map(e => ({ from: e.source, output: e.sourceHandle ?? 'main', to: e.target })),
  }
}

// Postgres JSONB does not keep object key order, so compare with keys sorted.
function canonical(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonical)
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical((v as Record<string, unknown>)[k])]))
  }
  return v
}

function sameGraph(a: Graph, b: Graph): boolean {
  const norm = (g: Graph) => JSON.stringify({
    n: canonical([...g.nodes].sort((x, y) => x.id.localeCompare(y.id))),
    e: g.edges.map(e => `${e.from}:${e.output}->${e.to}`).sort(),
  })
  return norm(a) === norm(b)
}

function reaches(from: string, to: string, edges: Edge[]): boolean {
  const stack = [from]
  const seen = new Set<string>()
  while (stack.length) {
    const cur = stack.pop() as string
    if (cur === to) return true
    if (seen.has(cur)) continue
    seen.add(cur)
    edges.filter(e => e.source === cur).forEach(e => stack.push(e.target))
  }
  return false
}

const RUN_COLOR: Record<Run['status'], string> = {
  queued: 'var(--text-secondary)', running: 'var(--accent-cyan)', resume: 'var(--accent-cyan)',
  waiting: 'var(--accent-yellow)', success: 'var(--accent-green)', failed: 'var(--accent-red)', cancelled: 'var(--text-muted)',
}

function RunBadge({ status }: { status: Run['status'] }) {
  return (
    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
      color: RUN_COLOR[status], border: `1px solid ${RUN_COLOR[status]}`, borderRadius: 4, padding: '1px 6px' }}>
      {status}
    </span>
  )
}

const ago = (iso: string | null) => (iso ? formatDistanceToNow(new Date(iso), { addSuffix: true }) : '')

// ─── Read-only canvas showing one run ──────────────────────────────────────

function RunCanvas({ run, selected, onSelect }: { run: RunDetail; selected: string | null; onSelect: (id: string | null) => void }) {
  const stepFor = useMemo(() => new Map(run.steps.map(s => [s.node_id, s])), [run.steps])
  const decorate = useCallback((n: WfNode): FlowNode => {
    const step = stepFor.get(n.id)
    return { ...toFlowNode(n, false), draggable: false, connectable: false, selected: n.id === selected,
      data: { ...toFlowNode(n, false).data, status: step ? step.status : 'skipped', taken: step?.output_name ?? null } }
  }, [stepFor, selected])
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(run.graph.nodes.map(decorate))
  const taken = (e: { from: string; output: string }) => stepFor.get(e.from)?.output_name === e.output
  const [edges, setEdges] = useEdgesState<Edge>(run.graph.edges.map(e => toFlowEdge(e, taken(e))))

  // Polling updates statuses in place so measured sizes survive.
  useEffect(() => {
    setNodes(prev => prev.map(p => {
      const n = run.graph.nodes.find(x => x.id === p.id)
      return n ? { ...p, selected: p.id === selected, data: decorate(n).data } : p
    }))
    setEdges(run.graph.edges.map(e => toFlowEdge(e, stepFor.get(e.from)?.output_name === e.output)))
  }, [run, selected, decorate, setNodes, setEdges, stepFor])

  return (
    <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} nodeTypes={nodeTypes} colorMode="dark" fitView
      nodesConnectable={false} nodesDraggable={false} elementsSelectable
      onNodeClick={(_, n) => onSelect(n.id)} onPaneClick={() => onSelect(null)}>
      <Background color="#1a2d45" gap={20} />
      <Controls showInteractive={false} />
    </ReactFlow>
  )
}

// ─── Runs tab ──────────────────────────────────────────────────────────────

function RunPanel({ run, selected, canEdit, onClose }: {
  run: RunDetail; selected: string | null; canEdit: boolean; onClose: () => void
}) {
  const decide = useDecideRun()
  const cancel = useCancelRun()
  const [comment, setComment] = useState('')
  const step = selected ? run.steps.find(s => s.node_id === selected) : undefined
  const node = selected ? run.graph.nodes.find(n => n.id === selected) : undefined

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <RunBadge status={run.status} />
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{run.trigger_event} · {ago(run.created_at)}</span>
        <button style={{ ...S.ghost, marginLeft: 'auto' }} onClick={onClose}><ArrowLeft size={12} /> Editor</button>
      </div>
      {run.error && <div style={{ ...S.hint, color: '#ff6b81', marginBottom: 10 }}>{run.error}</div>}

      {run.status === 'waiting' && (
        <div style={{ ...S.card, padding: 12, borderColor: 'var(--accent-yellow)', marginBottom: 12 }}>
          <div style={{ fontSize: 13, color: 'var(--text-primary)', marginBottom: 6 }}>{run.approval?.message ?? 'Approval needed'}</div>
          <div style={S.hint}>Times out {ago(run.wait_until)} (→ rejected).</div>
          {canEdit && (
            <>
              <input style={{ ...S.input, margin: '8px 0' }} placeholder="Comment (optional)" value={comment} onChange={e => setComment(e.target.value)} />
              <div style={{ display: 'flex', gap: 6 }}>
                <button style={S.btn('var(--accent-green)')} disabled={decide.isPending}
                  onClick={() => decide.mutate({ runId: run.id, decision: 'approved', comment })}><CheckCircle2 size={13} /> Approve</button>
                <button style={S.btn('var(--accent-red)', '#fff')} disabled={decide.isPending}
                  onClick={() => decide.mutate({ runId: run.id, decision: 'rejected', comment })}><X size={13} /> Reject</button>
              </div>
            </>
          )}
        </div>
      )}
      {canEdit && ['queued', 'running', 'waiting', 'resume'].includes(run.status) && (
        <button style={{ ...S.ghost, marginBottom: 12 }} onClick={() => cancel.mutate(run.id)}>Cancel run</button>
      )}

      {!selected && (
        <>
          <label style={S.label}>Trigger data</label>
          <JsonBlock value={run.trigger} />
          <div style={S.hint}>Click a node on the canvas to see what went in and came out.</div>
        </>
      )}
      {selected && (
        <>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8 }}>
            {node?.label ?? selected} <span style={{ ...S.mono, color: 'var(--text-muted)' }}>{selected}</span>
          </div>
          {!step && <div style={S.hint}>This node did not run.</div>}
          {step && (
            <>
              <div style={{ display: 'flex', gap: 10, fontSize: 12, color: 'var(--text-secondary)', marginBottom: 10, flexWrap: 'wrap' }}>
                <span>status: <b style={{ color: step.status === 'error' ? 'var(--accent-red)' : 'var(--text-primary)' }}>{step.status}</b></span>
                {step.output_name && <span>output: <b style={{ color: 'var(--text-primary)' }}>{step.output_name}</b></span>}
                {step.duration_ms !== null && <span>{step.duration_ms} ms</span>}
                {step.attempts > 1 && <span>{step.attempts} attempts</span>}
              </div>
              {step.error && <div style={{ ...S.hint, color: '#ff6b81', marginBottom: 10 }}>{step.error}</div>}
              {step.input !== null && step.input !== undefined && (<><label style={S.label}>Input (rendered)</label><JsonBlock value={step.input} /></>)}
              <label style={{ ...S.label, marginTop: 10 }}>Output</label>
              <JsonBlock value={step.output} />
              <div style={S.hint}>Later nodes read this as <code>{`{{ steps.${selected}… }}`}</code></div>
            </>
          )}
        </>
      )}
    </div>
  )
}

function RunList({ playbookId, onOpen }: { playbookId: string; onOpen: (id: string) => void }) {
  const runs = usePlaybookRuns(playbookId)
  if (runs.isLoading) return <div style={S.hint}>Loading…</div>
  if (!runs.data?.length) return <div style={S.hint}>No runs yet. Use Run to try it on an alert.</div>
  return (
    <div>
      {runs.data.map(r => (
        <button key={r.id} onClick={() => onOpen(r.id)}
          style={{ ...S.ghost, width: '100%', justifyContent: 'space-between', marginBottom: 6, padding: '8px 10px' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><RunBadge status={r.status} /> {r.trigger_event}</span>
          <span style={{ fontSize: 11 }}>{ago(r.created_at)}</span>
        </button>
      ))}
    </div>
  )
}

// ─── Editor ────────────────────────────────────────────────────────────────

function Editor({ playbook, catalog }: { playbook: Playbook; catalog: Catalog }) {
  const canEdit = useAuthStore(s => s.hasRole('admin'))
  const rf = useReactFlow()
  const [params, setParams] = useSearchParams()
  const [saved, setSaved] = useState<Graph>(playbook.graph)
  // An old-editor playbook can be saved as-is: that is what converts it.
  const [legacy, setLegacy] = useState(playbook.legacy)
  const [nodes, setNodes, onNodesChangeBase] = useNodesState<FlowNode>(playbook.graph.nodes.map(n => toFlowNode(n, canEdit)))
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(playbook.graph.edges.map(e => toFlowEdge(e)))
  const [selected, setSelected] = useState<string | null>(null)
  const [errors, setErrors] = useState<string[]>([])
  const [tab, setTab] = useState<'node' | 'runs'>(params.get('run') ? 'runs' : 'node')
  const [runAlert, setRunAlert] = useState('')
  const [showRun, setShowRun] = useState(false)
  const runId = params.get('run')
  const run = useRun(runId)

  const save = useSaveGraph()
  const validate = useValidateGraph()
  const runNow = useRunPlaybook()
  const update = useUpdatePlaybook()

  const graph = useMemo(() => toGraph(nodes, edges), [nodes, edges])
  const dirty = !sameGraph(graph, saved)
  const canSave = (dirty || legacy) && canEdit
  const selectedNode = graph.nodes.find(n => n.id === selected)
  const graphKey = useMemo(() => JSON.stringify(canonical(graph)), [graph])

  // Problems describe the graph they were found in; any edit makes them stale.
  useEffect(() => { setErrors([]) }, [graphKey])

  useEffect(() => {
    if (!dirty) return
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault() }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])

  const onNodesChange = useCallback((changes: NodeChange<FlowNode>[]) => {
    onNodesChangeBase(canEdit ? changes : changes.filter(c => c.type === 'dimensions' || c.type === 'select'))
    changes.forEach(c => {
      if (c.type === 'select' && c.selected) setSelected(c.id)
      if (c.type === 'remove' && c.id === selected) setSelected(null)
    })
  }, [onNodesChangeBase, canEdit, selected])

  const isValidConnection: IsValidConnection<Edge> = useCallback(
    (c) => !!c.source && !!c.target && c.source !== c.target && !reaches(c.target, c.source, edges),
    [edges],
  )

  const onConnect = useCallback((c: Connection) => {
    setEdges(es => addEdge(toFlowEdge({ from: c.source, output: c.sourceHandle ?? 'main', to: c.target }), es))
  }, [setEdges])

  const addNode = (type: NodeType) => {
    const id = newNodeId(type, graph)
    const center = rf.screenToFlowPosition({ x: window.innerWidth / 2 - 180, y: window.innerHeight / 2 })
    // Step down from the view's centre until the spot is clear of other nodes.
    const overlaps = (x: number, y: number) =>
      nodes.some(n => Math.abs(n.position.x - x) < 240 && Math.abs(n.position.y - y) < 90)
    let y = center.y
    while (overlaps(center.x, y)) y += 100
    const node: WfNode = { id, type, label: NODE_META[type].label, position: [center.x, y],
      params: NODE_META[type].defaults(), retry: 0, continue_on_error: false }
    setNodes(ns => [...ns.map(n => ({ ...n, selected: false })), { ...toFlowNode(node, true), selected: true }])
    setSelected(id)
    setTab('node')
  }

  const updateNode = (n: WfNode) => setNodes(ns => ns.map(x => (x.id === n.id
    ? { ...x, data: { ...x.data, label: n.label, params: n.params, retry: n.retry, continue_on_error: n.continue_on_error } }
    : x)))

  const doSave = () => save.mutate({ id: playbook.id, graph }, {
    onSuccess: pb => { setSaved(pb.graph); setLegacy(false); setErrors([]); emitToast('Workflow saved', 'success') },
    onError: e => setErrors(apiErrors(e)),
  })

  const openRun = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('run', id); else next.delete('run')
    setParams(next, { replace: true })
    setSelected(null)
    if (id) setTab('runs')
  }

  const startRun = () => {
    if (dirty) { emitToast('Save the workflow first — runs use the saved version', 'error'); return }
    runNow.mutate({ id: playbook.id, alert_id: runAlert.trim() || undefined }, {
      onSuccess: r => { setShowRun(false); openRun(r.id); emitToast('Run queued', 'success') },
    })
  }

  const viewing = !!runId && !!run.data

  return (
    // Layout's <main> pads 20px under a 52px top bar; the editor takes the whole area.
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 52px)', margin: -20 }}>
      {/* toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-panel)', flexWrap: 'wrap' }}>
        <Link to="/soar" style={{ ...S.ghost, textDecoration: 'none' }}><ArrowLeft size={13} /> Playbooks</Link>
        <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 18, color: 'var(--accent-cyan)', letterSpacing: 1 }}>
          {playbook.name}
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
          <input type="checkbox" checked={playbook.is_enabled} disabled={!canEdit}
            onChange={e => update.mutate({ id: playbook.id, data: { is_enabled: e.target.checked } })} />
          enabled
        </label>
        {dirty && <span style={{ fontSize: 11, color: 'var(--accent-yellow)' }}>● unsaved changes</span>}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, position: 'relative' }}>
          <button style={S.ghost} disabled={validate.isPending}
            onClick={() => validate.mutate(graph, {
              onSuccess: r => { setErrors(r.errors); if (r.ok) emitToast('Workflow is valid', 'success') },
              onError: e => setErrors(apiErrors(e)),
            })}><ShieldCheck size={13} /> Validate</button>
          {canEdit && (
            <>
              <button style={S.ghost} onClick={() => setShowRun(v => !v)}><Play size={13} /> Run</button>
              <button style={S.btn(undefined, undefined, !canSave || save.isPending)} disabled={!canSave || save.isPending} onClick={doSave}>
                <Save size={13} /> {save.isPending ? 'Saving…' : 'Save'}
              </button>
            </>
          )}
          {showRun && (
            <div style={{ ...S.card, position: 'absolute', right: 0, top: 38, width: 320, zIndex: 20, padding: 12 }}>
              <label style={S.label}>Run with an alert (optional)</label>
              <input style={{ ...S.input, ...S.mono }} placeholder="alert id" value={runAlert} onChange={e => setRunAlert(e.target.value)} />
              <div style={S.hint}>The alert fills {'{{ trigger.* }}'}. Trigger conditions are skipped for manual runs.</div>
              <button style={{ ...S.btn(), marginTop: 8 }} disabled={runNow.isPending} onClick={startRun}><Play size={12} /> Run now</button>
            </div>
          )}
        </div>
      </div>

      {legacy && (
        <div style={{ padding: '8px 16px', fontSize: 12, background: '#ffd70014', color: 'var(--accent-yellow)', borderBottom: '1px solid var(--border)' }}>
          This playbook was made in the old editor and is shown as a converted workflow. Saving turns it into a workflow for good.
        </div>
      )}
      {errors.length > 0 && (
        <div style={{ padding: '8px 16px', fontSize: 12, background: '#ff224414', color: '#ff8899', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700, marginBottom: 4 }}>
            <AlertTriangle size={13} /> {errors.length} problem{errors.length > 1 ? 's' : ''}
            <button style={{ ...S.ghost, border: 'none', marginLeft: 'auto' }} onClick={() => setErrors([])}><X size={12} /></button>
          </div>
          {errors.map(e => <div key={e}>• {e}</div>)}
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, minHeight: 0 }}>
        {/* palette */}
        {canEdit && !viewing && (
          <div style={{ width: 168, borderRight: '1px solid var(--border)', padding: 10, background: 'var(--bg-panel)', overflowY: 'auto' }}>
            <div style={S.label}>Add node</div>
            {PALETTE.map(t => {
              const m = NODE_META[t]
              const Icon = m.icon
              return (
                <button key={t} onClick={() => addNode(t)} title={m.help}
                  style={{ ...S.ghost, width: '100%', marginBottom: 6, justifyContent: 'flex-start', color: 'var(--text-primary)' }}>
                  <Icon size={13} color={m.color} /> {m.label}
                </button>
              )
            })}
            <div style={{ ...S.hint, marginTop: 10 }}>
              Drag from a node’s right dot to another node to connect. Select + Delete to remove.
            </div>
          </div>
        )}

        {/* canvas */}
        <div style={{ flex: 1, minWidth: 0, background: 'var(--bg-base)' }}>
          {viewing && run.data ? (
            <RunCanvas key={run.data.id} run={run.data} selected={selected} onSelect={setSelected} />
          ) : (
            <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} colorMode="dark" fitView
              onNodesChange={onNodesChange} onEdgesChange={canEdit ? onEdgesChange : undefined}
              onConnect={canEdit ? onConnect : undefined} isValidConnection={isValidConnection}
              nodesDraggable={canEdit} nodesConnectable={canEdit} deleteKeyCode={canEdit ? ['Backspace', 'Delete'] : null}
              onPaneClick={() => setSelected(null)}>
              <Background color="#1a2d45" gap={20} />
              <Controls />
              <MiniMap pannable zoomable style={{ background: 'var(--bg-panel)' }} maskColor="#05091299"
                nodeColor={n => NODE_META[(n as FlowNode).data.wfType].color} />
            </ReactFlow>
          )}
        </div>

        {/* side panel */}
        <div style={{ width: 380, borderLeft: '1px solid var(--border)', background: 'var(--bg-panel)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
            {(['node', 'runs'] as const).map(t => (
              <button key={t} onClick={() => { setTab(t); if (t === 'node') openRun(null) }}
                style={{ flex: 1, padding: 10, background: 'transparent', border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: 700,
                  letterSpacing: '0.06em', textTransform: 'uppercase',
                  color: tab === t ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  borderBottom: tab === t ? '2px solid var(--accent-cyan)' : '2px solid transparent' }}>
                {t === 'node' ? 'Node' : 'Runs'}
              </button>
            ))}
          </div>
          <div style={{ padding: 14, overflowY: 'auto', flex: 1 }}>
            {tab === 'node' && (selectedNode ? (
              <NodeForm key={selectedNode.id} node={selectedNode} graph={graph} catalog={catalog} disabled={!canEdit} onChange={updateNode} />
            ) : (
              <div style={S.hint}>
                Select a node to edit it{canEdit ? ', or add one from the left' : ''}. Every workflow starts at the Trigger and
                follows the wires; a node runs at most once per run.
              </div>
            ))}
            {tab === 'runs' && (viewing && run.data
              ? <RunPanel run={run.data} selected={selected} canEdit={canEdit} onClose={() => { openRun(null); setTab('runs') }} />
              : <RunList playbookId={playbook.id} onOpen={openRun} />)}
          </div>
        </div>
      </div>
    </div>
  )
}

export default function SoarEditorPage() {
  const { id } = useParams()
  const playbook = usePlaybook(id)
  const catalog = useSoarCatalog()
  if (playbook.isLoading || catalog.isLoading) return <div style={S.hint}>Loading…</div>
  if (playbook.isError || !playbook.data) return <div style={{ ...S.hint, color: '#ff8899' }}>{apiErrors(playbook.error)[0]}</div>
  if (!catalog.data) return <div style={S.hint}>Could not load the node catalog.</div>
  return (
    <ReactFlowProvider>
      <Editor key={playbook.data.id} playbook={playbook.data} catalog={catalog.data} />
    </ReactFlowProvider>
  )
}
