import { useState } from 'react'
import { format } from 'date-fns'
import { Ban, CheckCircle2, Pin, PinOff, Plus, SkipForward } from 'lucide-react'
import type {
  InvestigationAction, InvestigationEvidence, InvestigationHypothesis, NewAction,
} from '@/hooks/useInvestigationLedger'
import { useInvestigationControls } from '@/hooks/useInvestigationLedger'

// Queue, evidence and hypotheses of an AI investigation (AiInvestigationPanel's tabs).

const mono: React.CSSProperties = { fontFamily: 'Share Tech Mono, monospace' }
const label: React.CSSProperties = {
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', letterSpacing: '1.5px',
  textTransform: 'uppercase', color: 'var(--text-muted)',
}
const btn: React.CSSProperties = {
  display: 'inline-flex', alignItems: 'center', gap: '5px', padding: '3px 9px', borderRadius: '4px',
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', letterSpacing: '1px', cursor: 'pointer',
  background: 'transparent',
}
const input: React.CSSProperties = {
  ...mono, fontSize: '12px', padding: '5px 8px', background: 'var(--bg-base)', color: 'var(--text-primary)',
  border: '1px solid var(--border)', borderRadius: '4px',
}
const box: React.CSSProperties = { border: '1px solid var(--border)', borderRadius: '4px', maxHeight: '360px', overflow: 'auto' }

const ACTION_COLOR: Record<string, string> = {
  queued: 'var(--text-muted)', running: 'var(--accent-cyan)', awaiting_approval: 'var(--accent-orange)',
  completed: 'var(--accent-green)', skipped: 'var(--text-muted)', failed: 'var(--accent-red)', cancelled: 'var(--text-muted)',
}
const HYPOTHESIS_COLOR: Record<string, string> = {
  open: 'var(--accent-cyan)', supported: 'var(--accent-red)', refuted: 'var(--accent-green)',
  inconclusive: 'var(--accent-yellow)', superseded: 'var(--text-muted)',
}
const TIER_LABEL = ['T0 query', 'T1 collect', 'T2 approval', 'T3 response']
// what an analyst can queue (server: investigation_ledger.ANALYST_TOOLS)
const ANALYST_TOOLS = [
  'run_artifact', 'search_events', 'aggregate_events', 'event_timeline', 'search_alerts', 'correlate_entity',
  'pivot_ioc', 'reconstruct_timeline', 'recent_fim_changes', 'agent_hygiene', 'search_knowledge', 'search_sop',
]

function Tag({ text, color }: { text: string; color: string }) {
  return (
    <span style={{ ...label, fontSize: '10px', letterSpacing: '1px', color, border: `1px solid ${color}`, padding: '0 5px', borderRadius: '3px', whiteSpace: 'nowrap' }}>
      {text.replace('_', ' ')}
    </span>
  )
}

function actionTitle(a: InvestigationAction): string {
  if (a.tool === 'run_artifact') return `${String(a.params.artifact ?? '?')} on ${a.target ?? '?'}`
  if (a.tool === 'run_command') return `${String(a.params.command ?? '')} ${(a.params.args as string[] | undefined)?.join(' ') ?? ''} on ${a.target ?? '?'}`
  if (a.tool === 'record_hypothesis') return String(a.params.statement || `update ${String(a.params.hypothesis_id ?? '').slice(0, 8)}`)
  const q = Object.entries(a.params).map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`).join(' ')
  return `${a.tool}${q ? ` · ${q}` : ''}`
}

/** Approval cards for actions the policy held (commands keep their own card). */
export function ActionApprovals({ caseId, invId, actions }: { caseId: string; invId: string; actions: InvestigationAction[] }) {
  const { decide } = useInvestigationControls(caseId, invId)
  const [notes, setNotes] = useState<Record<string, string>>({})
  const held = actions.filter(a => a.status === 'awaiting_approval' && a.kind !== 'command')
  return (
    <>
      {held.map(a => (
        <div key={a.id} style={{ border: '1px solid var(--accent-orange)', borderRadius: '4px', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <span style={{ ...label, color: 'var(--accent-orange)' }}>Approval needed</span>
            <span style={{ fontSize: '12px', color: 'var(--text-primary)' }}>#{a.ordinal} {actionTitle(a)}</span>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {a.approval_reason}{a.reason ? ` · AI's reason: ${a.reason}` : ''}
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            <input value={notes[a.id] ?? ''} onChange={e => setNotes({ ...notes, [a.id]: e.target.value })}
              placeholder="Note to the AI (optional)" maxLength={1000} style={{ ...input, flex: '1 1 200px' }} />
            <button disabled={decide.isPending} onClick={() => decide.mutate({ actionId: a.id, approve: true, note: notes[a.id] })}
              style={{ ...btn, border: '1px solid var(--accent-green)', color: 'var(--accent-green)' }}>
              <CheckCircle2 size={12} /> APPROVE
            </button>
            <button disabled={decide.isPending} onClick={() => decide.mutate({ actionId: a.id, approve: false, note: notes[a.id] })}
              style={{ ...btn, border: '1px solid var(--accent-red)', color: 'var(--accent-red)' }}>
              <Ban size={12} /> REJECT
            </button>
          </div>
        </div>
      ))}
    </>
  )
}

function AddAction({ onAdd, pending }: { onAdd: (body: NewAction) => void; pending: boolean }) {
  const [tool, setTool] = useState('run_artifact')
  const [artifact, setArtifact] = useState('')
  const [host, setHost] = useState('')
  const [params, setParams] = useState('')
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)

  const submit = () => {
    let parsed: Record<string, unknown> = {}
    if (params.trim()) {
      try {
        const v: unknown = JSON.parse(params)
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object')
        parsed = v as Record<string, unknown>
      } catch {
        setError('Parameters must be a JSON object, e.g. {"query": "event.action:logon-failed"}')
        return
      }
    }
    if (tool === 'run_artifact') parsed = { artifact: artifact.trim(), ...(Object.keys(parsed).length ? { params: parsed } : {}) }
    setError(null)
    onAdd({ tool, host: tool === 'run_artifact' ? host.trim() : undefined, params: parsed, reason })
    setParams('')
    setReason('')
  }

  return (
    <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center', padding: '8px 10px', borderTop: '1px solid var(--border)' }}>
      <select value={tool} onChange={e => setTool(e.target.value)} style={input}>
        {ANALYST_TOOLS.map(t => <option key={t} value={t}>{t}</option>)}
      </select>
      {tool === 'run_artifact' && (
        <>
          <input value={artifact} onChange={e => setArtifact(e.target.value)} placeholder="Artifact, e.g. Linux.Sys.Pslist" style={{ ...input, flex: '1 1 180px' }} />
          <input value={host} onChange={e => setHost(e.target.value)} placeholder="Host" style={{ ...input, flex: '0 1 140px' }} />
        </>
      )}
      <input value={params} onChange={e => setParams(e.target.value)}
        placeholder={tool === 'run_artifact' ? 'Artifact parameters (JSON, optional)' : 'Parameters (JSON)'} style={{ ...input, flex: '1 1 200px' }} />
      <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Why (the AI sees this)" maxLength={2000} style={{ ...input, flex: '1 1 160px' }} />
      <button onClick={submit} disabled={pending || (tool === 'run_artifact' && (!artifact.trim() || !host.trim()))}
        style={{ ...btn, border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)' }}>
        <Plus size={12} /> ADD
      </button>
      {error && <div style={{ ...mono, fontSize: '11px', color: 'var(--accent-red)', flexBasis: '100%' }}>{error}</div>}
    </div>
  )
}

export function QueueView({ caseId, invId, actions, active, artifactsToPromote }: {
  caseId: string; invId: string; actions: InvestigationAction[]; active: boolean; artifactsToPromote: string[]
}) {
  const { addAction, skip, promote } = useInvestigationControls(caseId, invId)
  return (
    <div style={box}>
      {actions.length === 0 && <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)', padding: '10px' }}>No actions yet</div>}
      {actions.map(a => (
        <div key={a.id} style={{ display: 'grid', gridTemplateColumns: '36px 1fr auto', gap: '8px', padding: '6px 10px', borderBottom: '1px solid var(--border)', alignItems: 'start' }}>
          <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', paddingTop: '2px' }}>#{a.ordinal}</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
              <Tag text={a.status} color={ACTION_COLOR[a.status] ?? 'var(--text-muted)'} />
              <Tag text={TIER_LABEL[a.risk_tier] ?? `T${a.risk_tier}`} color="var(--text-muted)" />
              {a.source === 'analyst' && <Tag text="analyst" color="var(--accent-purple, #a78bfa)" />}
              <span style={{ fontSize: '13px', color: 'var(--text-primary)', wordBreak: 'break-word' }}>{actionTitle(a)}</span>
            </div>
            <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', wordBreak: 'break-word' }}>
              {[
                a.reason,
                a.approval_reason && a.status === 'awaiting_approval' ? `held: ${a.approval_reason}` : null,
                a.error ? `error: ${a.error}` : null,
                a.decision_note ? `note: ${a.decision_note}` : null,
                a.result_ref.evidence_ids?.length ? `${a.result_ref.evidence_ids.length} evidence` : null,
                a.attempts > 1 ? `${a.attempts} attempts` : null,
              ].filter(Boolean).join(' · ')}
              {a.result_ref.flow_id && <> · <a href={`/live-response?flow=${a.result_ref.flow_id}`} style={{ color: 'var(--accent-cyan)' }}>flow</a></>}
            </div>
          </div>
          {active && (a.status === 'queued' || a.status === 'awaiting_approval') && (
            <button onClick={() => skip.mutate(a.id)} disabled={skip.isPending}
              style={{ ...btn, border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
              <SkipForward size={12} /> SKIP
            </button>
          )}
        </div>
      ))}
      {artifactsToPromote.map(name => (
        <div key={name} style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 10px', borderBottom: '1px solid var(--border)', fontSize: '12px', color: 'var(--text-muted)' }}>
          <span>AI artifact <b style={{ color: 'var(--text-primary)' }}>{name}</b> is only usable by this investigation.</span>
          <button onClick={() => promote.mutate(name)} disabled={promote.isPending}
            style={{ ...btn, marginLeft: 'auto', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)' }}>
            PROMOTE
          </button>
        </div>
      ))}
      {active && <AddAction onAdd={body => addAction.mutate(body)} pending={addAction.isPending} />}
    </div>
  )
}

export function EvidenceView({ caseId, invId, evidence }: { caseId: string; invId: string; evidence: InvestigationEvidence[] }) {
  const { pin } = useInvestigationControls(caseId, invId)
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div style={box}>
      {evidence.length === 0 && <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)', padding: '10px' }}>No evidence yet</div>}
      {evidence.map(e => (
        <div key={e.id} style={{ padding: '6px 10px', borderBottom: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
            <Tag text={e.evidence_type} color={e.evidence_type === 'knowledge_guidance' ? 'var(--accent-yellow)' : 'var(--accent-cyan)'} />
            {e.sensitivity !== 'normal' && <Tag text={e.sensitivity} color="var(--accent-orange)" />}
            <button onClick={() => setOpen(open === e.id ? null : e.id)} style={{ fontSize: '13px', color: 'var(--text-primary)', textAlign: 'left' }}>{e.title}</button>
            <span style={{ ...mono, fontSize: '10px', color: 'var(--text-muted)' }} title={e.id}>{e.id.slice(0, 8)}</span>
            <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', marginLeft: 'auto' }}>
              {e.observed_at ? format(new Date(e.observed_at), 'dd MMM HH:mm:ss') : ''}
            </span>
            <button onClick={() => pin.mutate({ evidenceId: e.id, pinned: !e.pinned })} title={e.pinned ? 'Unpin' : 'Pin'}
              style={{ color: e.pinned ? 'var(--accent-yellow)' : 'var(--text-muted)' }}>
              {e.pinned ? <Pin size={13} /> : <PinOff size={13} />}
            </button>
          </div>
          {open === e.id && e.summary && (
            <pre style={{ ...mono, fontSize: '11px', whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: '6px 0 0', padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', background: 'var(--bg-base)', color: 'var(--text-primary)' }}>
              {e.summary}
            </pre>
          )}
        </div>
      ))}
    </div>
  )
}

export function HypothesesView({ caseId, invId, hypotheses, evidence }: {
  caseId: string; invId: string; hypotheses: InvestigationHypothesis[]; evidence: InvestigationEvidence[]
}) {
  const { addHypothesis, setHypothesis } = useInvestigationControls(caseId, invId)
  const [statement, setStatement] = useState('')
  const titles = new Map(evidence.map(e => [e.id, e.title]))
  const evidenceList = (ids: string[]) => ids.map(id => titles.get(id) ?? id.slice(0, 8)).join('; ')
  return (
    <div style={box}>
      {hypotheses.length === 0 && <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)', padding: '10px' }}>No hypotheses yet</div>}
      {hypotheses.map(h => {
        const proposed = [...h.history].reverse().find(x => x.proposed_state)?.proposed_state
        return (
          <div key={h.id} style={{ padding: '6px 10px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
              <Tag text={h.state} color={HYPOTHESIS_COLOR[h.state] ?? 'var(--text-muted)'} />
              <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)' }}>{h.confidence}%</span>
              {h.source === 'analyst' && <Tag text="analyst" color="var(--accent-purple, #a78bfa)" />}
              <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>{h.statement}</span>
            </div>
            <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
              {h.supporting_evidence_ids.length > 0 && <div>for: {evidenceList(h.supporting_evidence_ids)}</div>}
              {h.contradicting_evidence_ids.length > 0 && <div>against: {evidenceList(h.contradicting_evidence_ids)}</div>}
              {h.open_questions.length > 0 && <div>open: {h.open_questions.join('; ')}</div>}
            </div>
            {h.source === 'analyst' && h.state === 'open' && (
              <div style={{ display: 'flex', gap: '6px', marginTop: '4px', alignItems: 'center' }}>
                {proposed && <span style={{ ...mono, fontSize: '11px', color: 'var(--accent-yellow)' }}>AI proposes: {proposed}</span>}
                {(['supported', 'refuted', 'inconclusive'] as const).map(s => {
                  // supported / refuted need linked evidence (the server enforces it too)
                  const missing = s === 'supported' ? !h.supporting_evidence_ids.length
                    : s === 'refuted' ? !h.contradicting_evidence_ids.length : false
                  return (
                    <button key={s} onClick={() => setHypothesis.mutate({ id: h.id, state: s })}
                      disabled={setHypothesis.isPending || missing} title={missing ? 'Needs linked evidence first' : undefined}
                      style={{ ...btn, border: `1px solid ${HYPOTHESIS_COLOR[s]}`, color: HYPOTHESIS_COLOR[s], opacity: missing ? 0.4 : 1 }}>
                      {s.toUpperCase()}
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        )
      })}
      <div style={{ display: 'flex', gap: '6px', padding: '8px 10px', borderTop: '1px solid var(--border)' }}>
        <input value={statement} onChange={e => setStatement(e.target.value)} placeholder="Add a hypothesis for the AI to test"
          maxLength={1000} style={{ ...input, flex: 1 }} />
        <button disabled={!statement.trim() || addHypothesis.isPending}
          onClick={() => { addHypothesis.mutate(statement.trim()); setStatement('') }}
          style={{ ...btn, border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)' }}>
          <Plus size={12} /> ADD
        </button>
      </div>
    </div>
  )
}
