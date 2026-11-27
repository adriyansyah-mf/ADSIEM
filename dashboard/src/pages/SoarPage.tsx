import { useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { format, formatDistanceToNow, formatDistanceStrict } from 'date-fns'
import {
  useCreatePlaybook, useDecideRun, useDeletePlaybook, usePlaybookRuns, usePlaybooks, useUpdatePlaybook, useWaitingRuns,
} from '@/hooks/useSoar'
import { useAuthStore } from '@/stores/auth'
import { NODE_META, defaultGraph } from '@/components/soar/meta'
import { CanvasHeader, CanvasPage, Chip, Empty, type Tone } from '@/components/canvas/Canvas'
import type { NodeType, Playbook, Run, WfNode } from '@/types/soar'

const EVENT_LABEL: Record<string, string> = {
  'alert.created': 'Alert created',
  'alert.triaged': 'Alert triaged by AI',
  'case.created': 'Case created',
  'case.alert_linked': 'Alert linked to a case',
  manual: 'Manual run only',
}

const TAG: Record<NodeType, string> = {
  trigger: 'TRG', if: 'IF', enrich: 'ENR', ai_decide: 'AI', approval: 'APR', response: 'ACT', case: 'CASE', notify: 'MSG',
  http: 'HTTP', alert_event: 'EVT', log_search: 'SRCH', scan: 'SCAN', hunt: 'HUNT', block_ioc: 'BLK',
  case_evidence: 'EVD', case_block_ips: 'BLK',
}

const RUN_TONE: Record<Run['status'], Tone> = {
  queued: 'muted', running: 'info', waiting: 'warn', resume: 'info', success: 'good', failed: 'bad', cancelled: 'muted',
}
const RUN_LABEL: Record<Run['status'], string> = {
  queued: 'Queued', running: 'Running', waiting: 'Waiting', resume: 'Resuming', success: 'Succeeded', failed: 'Failed', cancelled: 'Cancelled',
}

function summary(node: WfNode): string {
  const p = node.params ?? {}
  const parts: string[] = []
  if (Array.isArray(p.conditions) && p.conditions.length) parts.push(`${p.conditions.length} condition${p.conditions.length === 1 ? '' : 's'} (${String(p.match ?? 'all')})`)
  for (const key of ['operation', 'channel', 'method', 'url', 'query', 'event', 'message']) {
    if (typeof p[key] === 'string' && p[key]) parts.push(String(p[key]).slice(0, 80))
  }
  if (typeof p.timeout_minutes === 'number') parts.push(`timeout ${p.timeout_minutes} min`)
  return parts.join(' · ')
}

/** Walks the graph from the trigger so steps read top to bottom like the canvas. */
function ordered(pb: Playbook) {
  const { nodes, edges } = pb.graph
  const byId = new Map(nodes.map(n => [n.id, n]))
  const start = nodes.find(n => n.type === 'trigger') ?? nodes[0]
  const seen = new Set<string>()
  const out: { node: WfNode; branches: { output: string; to: WfNode }[] }[] = []
  const queue = start ? [start.id] : []
  while (queue.length) {
    const id = queue.shift()!
    if (seen.has(id)) continue
    seen.add(id)
    const node = byId.get(id)
    if (!node) continue
    const next = edges.filter(e => e.from === id)
    out.push({ node, branches: next.length > 1 ? next.map(e => ({ output: e.output, to: byId.get(e.to)! })).filter(b => b.to) : [] })
    for (const e of next) queue.push(e.to)
  }
  for (const node of nodes) if (!seen.has(node.id)) out.push({ node, branches: [] })
  return out
}

export default function SoarPage() {
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const canEdit = useAuthStore(s => s.hasRole('admin'))
  const playbooks = usePlaybooks()
  const waiting = useWaitingRuns()
  const create = useCreatePlaybook()
  const update = useUpdatePlaybook()
  const del = useDeletePlaybook()
  const decide = useDecideRun()
  const [newName, setNewName] = useState('')
  const [adding, setAdding] = useState(false)

  const list = playbooks.data ?? []
  const selected = list.find(pb => pb.id === params.get('wf')) ?? list[0] ?? null
  const runs = usePlaybookRuns(selected?.id)
  const steps = useMemo(() => selected ? ordered(selected) : [], [selected])
  const select = (id: string) => setParams(current => { const next = new URLSearchParams(current); next.set('wf', id); return next }, { replace: true })
  const runList = runs.data ?? []
  const counts = runList.reduce<Record<string, number>>((acc, run) => ({ ...acc, [run.status]: (acc[run.status] ?? 0) + 1 }), {})
  const pending = (waiting.data ?? [])
  const nameOf = (id: string) => list.find(p => p.id === id)?.name ?? 'workflow'

  const submit = () => {
    if (!newName.trim()) return
    create.mutate({ name: newName.trim(), graph: defaultGraph() }, { onSuccess: pb => navigate(`/soar/${pb.id}`) })
  }

  return (
    <CanvasPage>
      <CanvasHeader
        title={selected?.name ?? 'Automations'}
        crumb={<>Automations{selected ? ` / ${selected.name}` : ''}</>}
        sub={selected
          ? <span className="cv-row" style={{ gap: 8 }}>
            <Chip tone={selected.is_enabled ? 'good' : 'muted'}>{selected.is_enabled ? 'ENABLED' : 'DISABLED'}</Chip>
            <span>{EVENT_LABEL[selected.trigger_event] ?? selected.trigger_event} · {Math.max(0, selected.graph.nodes.length - 1)} steps{selected.updated_at ? ` · edited ${formatDistanceToNow(new Date(selected.updated_at), { addSuffix: true })}` : ''}</span>
            {selected.legacy && <Chip tone="warn">OLD EDITOR</Chip>}
          </span>
          : 'Workflows that run on alerts and cases: enrich, branch, ask the AI, wait for an analyst, act on the endpoint'}
        actions={selected && <>
          {canEdit && (
            <label className="cv-row cv-small" style={{ gap: 6, cursor: 'pointer' }}>
              <input type="checkbox" checked={selected.is_enabled} onChange={e => update.mutate({ id: selected.id, data: { is_enabled: e.target.checked } })} /> Enabled
            </label>
          )}
          {canEdit && <button type="button" className="cv-btn" disabled={del.isPending}
            onClick={() => { if (window.confirm(`Delete “${selected.name}” and its run history?`)) del.mutate(selected.id) }}>Delete</button>}
          <Link className="cv-btn" to={`/soar/${selected.id}`}>Test with an alert</Link>
          <Link className="cv-btn cv-btn--primary" to={`/soar/${selected.id}`}>{canEdit ? 'Open editor' : 'View workflow'}</Link>
        </>}
      />
      <div className="cv-split">
        <aside className="cv-list" aria-label="Workflows" style={{ flex: '1 1 280px', maxWidth: 320 }}>
          <div className="cv-list__tools">
            <div className="cv-row cv-row--between">
              <span className="cv-small cv-dim">Workflows · {list.length}</span>
              {canEdit && <button type="button" className="cv-btn cv-btn--sm" onClick={() => setAdding(v => !v)}>{adding ? 'Cancel' : '+ New'}</button>}
            </div>
            {adding && (
              <form className="cv-row" style={{ flexWrap: 'nowrap' }} onSubmit={e => { e.preventDefault(); submit() }}>
                <input autoFocus className="cv-input" style={{ flex: 1 }} aria-label="Workflow name" placeholder="e.g. Block brute-force IPs"
                  value={newName} onChange={e => setNewName(e.target.value)} />
                <button type="submit" className="cv-btn cv-btn--primary" disabled={!newName.trim() || create.isPending}>Create</button>
              </form>
            )}
          </div>
          {list.map(pb => (
            <button key={pb.id} type="button" className="cv-list__item" aria-current={pb.id === selected?.id} onClick={() => select(pb.id)}>
              <span className="cv-list__title">{pb.name}</span>
              <span className="cv-list__meta">
                <span className={pb.is_enabled ? 'cv-t-good' : 'cv-muted'}>{pb.is_enabled ? 'Enabled' : 'Disabled'}</span>
                <span>{EVENT_LABEL[pb.trigger_event] ?? pb.trigger_event}</span>
              </span>
            </button>
          ))}
          {playbooks.isLoading && <Empty>Loading…</Empty>}
          {!playbooks.isLoading && list.length === 0 && <Empty>No workflows yet.{canEdit ? ' Create one to start.' : ''}</Empty>}
        </aside>

        <section className="cv-pane" aria-label="Workflow steps">
          {pending.length > 0 && (
            <div className="cv-card cv-card--warn">
              <div className="cv-card__head"><h2 className="cv-t-warn">{pending.length} run{pending.length > 1 ? 's' : ''} waiting for approval</h2></div>
              {pending.map(r => (
                <div key={r.id} className="cv-row cv-row--between" style={{ borderTop: '1px solid #1E222B', paddingTop: 8 }}>
                  <div className="cv-stack">
                    <span>{r.approval?.message ?? 'Approval needed'}</span>
                    <span className="cv-muted cv-small">{nameOf(r.playbook_id)}{r.wait_until ? ` · times out ${formatDistanceToNow(new Date(r.wait_until), { addSuffix: true })}` : ''}</span>
                  </div>
                  <div className="cv-row">
                    <Link className="cv-btn cv-btn--sm" to={`/soar/${r.playbook_id}?run=${r.id}`}>Open</Link>
                    {canEdit && <>
                      <button type="button" className="cv-btn cv-btn--sm" disabled={decide.isPending} onClick={() => decide.mutate({ runId: r.id, decision: 'approved' })}>Approve</button>
                      <button type="button" className="cv-btn cv-btn--sm cv-btn--danger" disabled={decide.isPending} onClick={() => decide.mutate({ runId: r.id, decision: 'rejected' })}>Reject</button>
                    </>}
                  </div>
                </div>
              ))}
            </div>
          )}

          {selected ? (
            <ol className="cv-steps">
              {steps.map(({ node, branches }, index) => {
                const meta = NODE_META[node.type]
                return (
                  <li key={node.id}>
                    <div className="cv-steps__rail">
                      <span className="cv-steps__tag" style={{ color: meta?.color ?? '#9DB4FF' }}>{TAG[node.type] ?? node.type.slice(0, 4).toUpperCase()}</span>
                      {index < steps.length - 1 && <span className="cv-steps__line" />}
                    </div>
                    <div className="cv-card cv-steps__card">
                      <span className="cv-small cv-muted">{meta?.label ?? node.type}{node.type === 'approval' ? ' · needs approval' : ''}</span>
                      <strong>{node.type === 'trigger' ? EVENT_LABEL[selected.trigger_event] ?? node.label : node.label || meta?.label}</strong>
                      {summary(node) && <span className="cv-small cv-dim">{summary(node)}</span>}
                      {branches.length > 0 && (
                        <div className="cv-steps__branches">
                          {branches.map(branch => (
                            <span key={`${branch.output}-${branch.to.id}`}>
                              <Chip tone={branch.output === 'true' || branch.output === 'yes' || branch.output === 'approved' ? 'good' : branch.output === 'false' || branch.output === 'no' || branch.output === 'rejected' ? 'bad' : 'muted'}>{branch.output}</Chip>
                              {' '}→ {branch.to.label || NODE_META[branch.to.type]?.label}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </li>
                )
              })}
            </ol>
          ) : !playbooks.isLoading && <Empty>Select a workflow to see its steps.</Empty>}
          {selected && canEdit && (
            <Link to={`/soar/${selected.id}`} className="cv-dropzone" style={{ minHeight: 56, textDecoration: 'none' }}>+ Add step in the editor</Link>
          )}
        </section>

        <aside className="cv-list" aria-label="Run history" style={{ flex: '1 1 300px', maxWidth: 340, borderRight: 0, borderLeft: '1px solid #222733', padding: 16, gap: 12 }}>
          <h2 className="cv-h2">Recent runs · {runList.length}</h2>
          <div className="cv-row" style={{ gap: 14 }}>
            <span><strong>{counts.success ?? 0}</strong> <span className="cv-t-good cv-small">Succeeded</span></span>
            <span><strong>{counts.waiting ?? 0}</strong> <span className="cv-t-warn cv-small">Waiting</span></span>
            <span><strong>{counts.failed ?? 0}</strong> <span className="cv-t-bad cv-small">Failed</span></span>
          </div>
          {runList.slice(0, 12).map(run => (
            <Link key={run.id} to={`/soar/${run.playbook_id}?run=${run.id}`} className="cv-card cv-evidence" style={{ color: 'inherit' }}>
              <span className="cv-row cv-row--between">
                <span className="cv-mono">RUN-{run.id.replace(/-/g, '').slice(0, 5).toUpperCase()}</span>
                <Chip tone={RUN_TONE[run.status]}>{RUN_LABEL[run.status]}</Chip>
              </span>
              <span className="cv-small cv-dim">{run.error ? run.error.slice(0, 90) : run.alert_id ? `Alert ${run.alert_id.slice(0, 8)} · ${run.trigger_event}` : run.trigger_event}</span>
              <span className="cv-small cv-muted">
                {run.created_at ? format(new Date(run.created_at), 'dd MMM HH:mm') : ''}
                {run.created_at && run.finished_at ? ` · ${formatDistanceStrict(new Date(run.finished_at), new Date(run.created_at))}` : ''}
              </span>
            </Link>
          ))}
          {selected && !runs.isLoading && runList.length === 0 && <span className="cv-muted cv-small">This workflow has not run yet.</span>}
        </aside>
      </div>
    </CanvasPage>
  )
}
