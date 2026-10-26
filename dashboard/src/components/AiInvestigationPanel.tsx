import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format, formatDistanceStrict } from 'date-fns'
import {
  AlertTriangle, Ban, CheckCircle2, ChevronDown, ChevronRight, CircleStop, Clock, FileCode2, FileText,
  Lightbulb, Play, Search, Server, ShieldQuestion, Terminal, XCircle,
} from 'lucide-react'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import { useInvestigationControls, useInvestigationLedger } from '@/hooks/useInvestigationLedger'
import MarkdownNote from '@/components/MarkdownNote'
import { HashEnrichmentEvidence } from '@/components/HashEnrichmentEvidence'
import { ActionApprovals, EvidenceView, HypothesesView, QueueView } from '@/components/InvestigationLedger'
import MalwareDrafts from '@/components/MalwareDrafts'

interface Step {
  ts: string
  kind: string
  [key: string]: unknown
}

interface Command {
  id: string
  hostname: string | null
  command: string
  args: string[]
  timeout: number
  reason: string | null
  status: 'pending' | 'approved' | 'rejected' | 'expired'
  auto_approved: boolean
  flow_id: string | null
  created_at: string
}

interface Investigation {
  id: string
  case_id: string
  status: 'queued' | 'running' | 'finished' | 'error' | 'cancelled' | 'interrupted'
  phase: 'planning' | 'collecting' | 'analyzing' | 'reporting' | null
  model: string | null
  verdict: string | null
  report: string | null
  report_json: { citations_unchecked?: boolean; unverified_claims?: number; confidence?: number; verdict_downgraded_from?: string } | null
  budget_overrides: { flows?: number; raised_by?: string }
  error: string | null
  steps: Step[]
  commands: Command[]
  created_at: string
  finished_at: string | null
}

function commandLine(c: Pick<Command, 'command' | 'args'>): string {
  return [c.command, ...c.args.map(a => (a === '' || /[\s"]/.test(a) ? JSON.stringify(a) : a))].join(' ')
}

const ACTIVE = new Set(['queued', 'running'])

const STATUS_COLOR: Record<string, string> = {
  queued: 'var(--text-muted)', running: 'var(--accent-cyan)', finished: 'var(--accent-green)',
  error: 'var(--accent-red)', cancelled: 'var(--text-muted)', interrupted: 'var(--accent-orange)',
}
const VERDICT: Record<string, { label: string; color: string }> = {
  true_positive: { label: 'True positive', color: 'var(--accent-red)' },
  false_positive: { label: 'False positive', color: 'var(--accent-green)' },
  inconclusive: { label: 'Inconclusive', color: 'var(--accent-yellow)' },
}
// read-only SIEM tools, as plain verbs
const TOOL_LABEL: Record<string, string> = {
  list_hosts: 'Listed hosts', list_artifacts: 'Listed artifacts', get_flow_rows: 'Read flow rows',
  search_events: 'Searched events', aggregate_events: 'Aggregated events', event_timeline: 'Built event timeline',
  get_alert: 'Read alert', search_alerts: 'Searched alerts', get_case: 'Read case',
  correlate_entity: 'Correlated entity', reconstruct_timeline: 'Reconstructed timeline', pivot_ioc: 'Pivoted on IOC',
  recent_fim_changes: 'Checked file integrity changes', agent_hygiene: 'Checked host hygiene',
  ueba_top_risky_entities: 'Checked UEBA risk', search_sop: 'Searched SOPs',
  lookup_malwarebazaar: 'Looked up file hash in MalwareBazaar',
}

const mono: React.CSSProperties = { fontFamily: 'Share Tech Mono, monospace' }
const label: React.CSSProperties = {
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', letterSpacing: '1.5px',
  textTransform: 'uppercase', color: 'var(--text-muted)',
}

function detail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

function Pill({ text, color }: { text: string; color: string }) {
  return (
    <span style={{
      ...label, color, border: `1px solid ${color}`, background: 'transparent',
      padding: '1px 6px', borderRadius: '3px', fontSize: '10px', letterSpacing: '1px',
    }}>{text}</span>
  )
}

function argsText(args: unknown): string {
  if (!args || typeof args !== 'object') return ''
  return Object.entries(args as Record<string, unknown>)
    .filter(([, v]) => v !== '' && v != null)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join('  ')
}

type Row = { icon: React.ReactNode; title: React.ReactNode; detail?: React.ReactNode; tone?: string; extra?: React.ReactNode }

function describe(step: Step, open: boolean, toggle: () => void): Row | null {
  const s = step as Record<string, any>
  switch (step.kind) {
    case 'started':
      return { icon: <Play size={13} />, title: 'Started',
        detail: `by ${s.by} · ${s.model}${s.commands ? ' · commands need approval' : ''}` }
    case 'command':
      return {
        icon: <Terminal size={13} />, tone: 'var(--accent-orange)',
        title: <>{s.auto_approved ? 'Command (auto-approved)' : 'Asked to run'} on <b>{s.host}</b></>,
        detail: <>{s.command}{s.reason ? ` · ${s.reason}` : ''}</>,
      }
    case 'command_decision':
      return {
        icon: s.status === 'approved' ? <CheckCircle2 size={13} /> : <Ban size={13} />,
        tone: s.status === 'approved' ? 'var(--accent-green)' : 'var(--accent-red)',
        title: `Command ${s.status}`, detail: s.note ?? undefined,
      }
    case 'command_result':
      return {
        icon: <CheckCircle2 size={13} />, title: `Command ${s.status}`,
        detail: <>{s.exit ?? s.error ?? ''}{` · ${s.lines} lines · `}<a href={`/live-response?flow=${s.flow_id}`} style={{ color: 'var(--accent-cyan)' }}>output</a></>,
      }
    case 'context':
      return { icon: <FileText size={13} />, title: 'Read the case',
        detail: s.hosts?.length ? `hosts: ${s.hosts.join(', ')}` : 'no linked hosts' }
    case 'tool':
      return { icon: <Search size={13} />, title: TOOL_LABEL[s.tool] ?? s.tool, detail: argsText(s.args) }
    case 'enrichment':
      return { icon: <Search size={13} />, title: 'MalwareBazaar enrichment',
        extra: <HashEnrichmentEvidence result={step.result} reason={step.reason} /> }
    case 'flow':
      return {
        icon: <Server size={13} />, tone: 'var(--accent-cyan)',
        title: <>Ran <b>{s.artifact}</b> on <b>{s.host}</b></>,
        detail: <>{s.reason}{s.reason ? ' · ' : ''}<a href={`/live-response?flow=${s.flow_id}`} style={{ color: 'var(--accent-cyan)' }}>view flow</a></>,
      }
    case 'flow_result':
      return { icon: <CheckCircle2 size={13} />, title: `Flow ${s.status}`,
        detail: Object.entries(s.rows ?? {}).map(([src, n]) => `${src}: ${n} rows`).join(' · ') }
    case 'artifact':
      return {
        icon: <FileCode2 size={13} />, tone: 'var(--accent-purple, #a78bfa)',
        title: <>Created artifact <b>{s.name}</b></>,
        detail: <>{s.reason}{s.reason ? ' · ' : ''}<button onClick={toggle} style={{ color: 'var(--accent-cyan)' }}>{open ? 'hide YAML' : 'YAML'}</button></>,
        extra: open ? <pre style={{ ...mono, fontSize: '11px', whiteSpace: 'pre-wrap', margin: '6px 0 0', padding: '8px', border: '1px solid var(--border)', borderRadius: '4px', background: 'var(--bg-base)' }}>{s.yaml}</pre> : null,
      }
    case 'refused':
      return { icon: <Ban size={13} />, tone: 'var(--accent-red)', title: 'Refused', detail: s.reason }
    case 'approval_needed':
      return { icon: <ShieldQuestion size={13} />, tone: 'var(--accent-orange)',
        title: <>Waiting for approval: <b>{s.tool}</b>{s.host ? <> on <b>{s.host}</b></> : null}</>, detail: s.reason }
    case 'action_decision':
      return {
        icon: s.status === 'approved' ? <CheckCircle2 size={13} /> : <Ban size={13} />,
        tone: s.status === 'approved' ? 'var(--accent-green)' : 'var(--accent-red)',
        title: `Action ${s.status}`, detail: s.note ?? undefined,
      }
    case 'waiting':
      return { icon: <Clock size={13} />, title: 'Waiting for a free slot on the host', detail: s.reason }
    case 'resumed':
      return { icon: <Play size={13} />, tone: 'var(--accent-orange)', title: 'Resumed on another server',
        detail: `${s.replica} · after ${s.after_rounds} rounds; continued from the ledger` }
    case 'reconciled':
      return { icon: <CheckCircle2 size={13} />, title: `Picked up action #${s.ordinal}`,
        detail: `${s.tool}: finished what the previous server started, without re-running it` }
    case 'hypothesis':
      return { icon: <Lightbulb size={13} />, tone: 'var(--accent-yellow)',
        title: <>Hypothesis <b>{s.state}</b> ({s.confidence}%)</>, detail: `${s.statement}${s.reason ? ` · ${s.reason}` : ''}` }
    case 'report_check':
      return { icon: <AlertTriangle size={13} />, tone: 'var(--accent-yellow)', title: 'Report citations checked',
        detail: `${(s.problems ?? []).length} problems sent back to the model for one repair` }
    case 'warning':
      return { icon: <AlertTriangle size={13} />, tone: 'var(--accent-yellow)', title: 'Warning', detail: s.text }
    case 'finished':
      return { icon: <CheckCircle2 size={13} />, tone: 'var(--accent-green)', title: 'Finished',
        detail: `${s.flows} live-response runs · ${s.artifacts} new artifacts${s.commands ? ` · ${s.commands} commands` : ''}` }
    case 'cancelled':
      return { icon: <CircleStop size={13} />, title: 'Cancelled', detail: s.reason }
    case 'error':
      return { icon: <XCircle size={13} />, tone: 'var(--accent-red)', title: 'Error', detail: s.error }
    default:
      return null
  }
}

function Timeline({ steps, showReasoning }: { steps: Step[]; showReasoning: boolean }) {
  const [openIdx, setOpenIdx] = useState<number | null>(null)
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: '4px', maxHeight: '320px', overflow: 'auto' }}>
      {steps.length === 0 && <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)', padding: '10px' }}>Queued</div>}
      {steps.map((step, i) => {
        if (step.kind === 'thought') {
          if (!showReasoning) return null
          return (
            <div key={i} style={{ padding: '6px 10px 6px 92px', fontSize: '12px', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
              {String(step.text)}
            </div>
          )
        }
        const row = describe(step, openIdx === i, () => setOpenIdx(openIdx === i ? null : i))
        if (!row) return null
        return (
          <div key={i} style={{ display: 'grid', gridTemplateColumns: '64px 18px 1fr', gap: '6px', padding: '6px 10px', borderBottom: '1px solid var(--border)', alignItems: 'start' }}>
            <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', paddingTop: '1px' }}>{format(new Date(step.ts), 'HH:mm:ss')}</span>
            <span style={{ color: row.tone ?? 'var(--text-muted)', paddingTop: '2px' }}>{row.icon}</span>
            <div style={{ minWidth: 0 }}>
              <span style={{ fontSize: '13px', color: row.tone ?? 'var(--text-primary)' }}>{row.title}</span>
              {row.detail && <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', marginLeft: '8px', wordBreak: 'break-word' }}>{row.detail}</span>}
              {row.extra}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function PendingCommand({ cmd, onDecided }: { cmd: Command; onDecided: () => void }) {
  const [note, setNote] = useState('')
  const decide = useMutation({
    mutationFn: (approve: boolean) =>
      api.post(`/api/investigation-commands/${cmd.id}/decision`, { approve, note: note || null }).then(r => r.data),
    onSuccess: onDecided,
    onError: (e) => { emitToast(detail(e, 'Could not record the decision'), 'error'); onDecided() },
  })
  const btn: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '5px 12px', borderRadius: '4px',
    fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px', cursor: 'pointer',
  }
  return (
    <div style={{ border: '1px solid var(--accent-orange)', borderRadius: '4px', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <span style={{ ...label, color: 'var(--accent-orange)' }}>Approval needed</span>
        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
          runs on <b style={{ color: 'var(--text-primary)' }}>{cmd.hostname}</b> as root / SYSTEM, up to {cmd.timeout}s
        </span>
      </div>
      <pre style={{ ...mono, fontSize: '12px', margin: 0, padding: '8px', whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: '4px', color: 'var(--text-primary)' }}>
        {commandLine(cmd)}
      </pre>
      {cmd.reason && <div style={{ fontSize: '12px', color: 'var(--text-secondary, var(--text-muted))' }}>Reason: {cmd.reason}</div>}
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
        <input value={note} onChange={e => setNote(e.target.value)} placeholder="Note to the AI (optional)" maxLength={1000}
          style={{ ...mono, flex: '1 1 200px', fontSize: '12px', padding: '5px 8px', background: 'var(--bg-base)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: '4px' }} />
        <button onClick={() => decide.mutate(true)} disabled={decide.isPending}
          style={{ ...btn, border: '1px solid var(--accent-green)', background: 'transparent', color: 'var(--accent-green)' }}>
          <CheckCircle2 size={13} /> APPROVE
        </button>
        <button onClick={() => decide.mutate(false)} disabled={decide.isPending}
          style={{ ...btn, border: '1px solid var(--accent-red)', background: 'transparent', color: 'var(--accent-red)' }}>
          <Ban size={13} /> REJECT
        </button>
      </div>
    </div>
  )
}

export default function AiInvestigationPanel({ caseId }: { caseId: string }) {
  const qc = useQueryClient()
  const { data: runs = [] } = useQuery<Investigation[]>({
    queryKey: ['investigations', caseId],
    queryFn: () => api.get(`/api/cases/${caseId}/investigations`).then(r => r.data),
    refetchInterval: (q) => ((q.state.data as Investigation[] | undefined)?.some(r => ACTIVE.has(r.status)) ? 3000 : false),
  })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [showReasoning, setShowReasoning] = useState(false)
  const [tab, setTab] = useState<'activity' | 'queue' | 'evidence' | 'hypotheses'>('activity')
  const current = runs.find(r => r.id === selectedId) ?? runs[0]
  const active = current ? ACTIVE.has(current.status) : false
  const ledger = useInvestigationLedger(caseId, current?.id, active)
  const { raiseBudget } = useInvestigationControls(caseId, current?.id)
  // artifacts this run wrote: reusable by other runs only once promoted
  const written = current ? [...new Set(current.steps.filter(s => s.kind === 'artifact').map(s => String(s.name)))] : []

  // the report is added to the case as a note: refresh the case when a run ends
  const [wasActive, setWasActive] = useState(false)
  useEffect(() => {
    if (wasActive && !active) qc.invalidateQueries({ queryKey: ['case', caseId] })
    setWasActive(active)
  }, [active, wasActive, qc, caseId])

  const start = useMutation({
    mutationFn: () => api.post(`/api/cases/${caseId}/investigations`).then(r => r.data as Investigation),
    onSuccess: (inv) => {
      setSelectedId(inv.id)
      qc.invalidateQueries({ queryKey: ['investigations', caseId] })
    },
    onError: (e) => emitToast(detail(e, 'Could not start the investigation'), 'error'),
  })
  const cancel = useMutation({
    mutationFn: (id: string) => api.post(`/api/investigations/${id}/cancel`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['investigations', caseId] }),
  })

  const btn: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', borderRadius: '4px',
    fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px', cursor: 'pointer',
  }
  const thoughts = current?.steps.filter(s => s.kind === 'thought').length ?? 0
  const verdict = current?.verdict ? VERDICT[current.verdict] : null

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <button onClick={() => start.mutate()} disabled={active || start.isPending}
          style={{ ...btn, border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.08)', color: 'var(--accent-cyan)', opacity: active ? 0.5 : 1, cursor: active ? 'not-allowed' : 'pointer' }}>
          <Terminal size={13} /> {active ? 'INVESTIGATING' : 'INVESTIGATE'}
        </button>
        {active && current && (
          <button onClick={() => cancel.mutate(current.id)} disabled={cancel.isPending}
            style={{ ...btn, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)' }}>
            <CircleStop size={13} /> CANCEL
          </button>
        )}
        {active && current && !current.budget_overrides?.flows && (
          <button onClick={() => raiseBudget.mutate(6)} disabled={raiseBudget.isPending}
            title="Once per investigation: six more live-response runs"
            style={{ ...btn, border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-muted)' }}>
            +6 RUNS
          </button>
        )}
        {current && (
          <>
            <Pill text={current.status} color={STATUS_COLOR[current.status] ?? 'var(--text-muted)'} />
            {active && current.phase && <Pill text={current.phase} color="var(--accent-cyan)" />}
            {verdict && <Pill text={verdict.label} color={verdict.color} />}
            {current.report_json?.verdict_downgraded_from && <Pill text="downgraded: unverified" color="var(--accent-yellow)" />}
            {current.report_json?.citations_unchecked && <Pill text="citations unchecked" color="var(--accent-yellow)" />}
            <span style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)' }}>
              {current.model}
              {current.finished_at && ` · ${formatDistanceStrict(new Date(current.finished_at), new Date(current.created_at))}`}
            </span>
          </>
        )}
        {runs.length > 1 && (
          <select value={current?.id} onChange={e => setSelectedId(e.target.value)}
            style={{ ...mono, marginLeft: 'auto', fontSize: '11px', padding: '3px 6px', background: 'var(--bg-base)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: '4px' }}>
            {runs.map(r => (
              <option key={r.id} value={r.id}>
                {format(new Date(r.created_at), 'dd MMM HH:mm')} · {r.status}{r.verdict ? ` · ${VERDICT[r.verdict]?.label ?? r.verdict}` : ''}
              </option>
            ))}
          </select>
        )}
      </div>

      {!current && (
        <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
          Reads the case and its alerts, searches the logs, and collects evidence from the case&apos;s hosts with
          live-response artifacts (writing new ones if needed). When AI commands are enabled in Settings, it can
          also ask to run a program on a host — you approve each one here first. The findings are added to the case as a note.
          Response actions — isolate, kill, quarantine, block — are left to you.
        </div>
      )}

      {current && (
        <>
          {current.error && current.status !== 'finished' && (
            <div style={{ ...mono, fontSize: '12px', color: 'var(--accent-red)' }}>{current.error}</div>
          )}
          {(current.commands ?? []).filter(c => c.status === 'pending').map(c => (
            <PendingCommand key={c.id} cmd={c} onDecided={() => qc.invalidateQueries({ queryKey: ['investigations', caseId] })} />
          ))}
          <ActionApprovals caseId={caseId} invId={current.id} actions={ledger.actions} />
          <MalwareDrafts caseId={caseId} invId={current.id} />
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', borderBottom: '1px solid var(--border)' }}>
            {([
              ['activity', 'Activity'],
              ['queue', `Queue (${ledger.actions.length})`],
              ['evidence', `Evidence (${ledger.evidence.length})`],
              ['hypotheses', `Hypotheses (${ledger.hypotheses.length})`],
            ] as const).map(([key, text]) => (
              <button key={key} onClick={() => setTab(key)}
                style={{ ...label, padding: '4px 0', color: tab === key ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  borderBottom: tab === key ? '2px solid var(--accent-cyan)' : '2px solid transparent', marginBottom: '-1px' }}>
                {text}
              </button>
            ))}
            {tab === 'activity' && thoughts > 0 && (
              <button onClick={() => setShowReasoning(v => !v)}
                style={{ ...mono, marginLeft: 'auto', fontSize: '11px', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: '2px' }}>
                {showReasoning ? <ChevronDown size={12} /> : <ChevronRight size={12} />} reasoning ({thoughts})
              </button>
            )}
          </div>
          {tab === 'activity' && <Timeline steps={current.steps} showReasoning={showReasoning} />}
          {tab === 'queue' && (
            <QueueView caseId={caseId} invId={current.id} actions={ledger.actions} active={active}
              artifactsToPromote={active ? [] : written} />
          )}
          {tab === 'evidence' && <EvidenceView caseId={caseId} invId={current.id} evidence={ledger.evidence} />}
          {tab === 'hypotheses' && (
            <HypothesesView caseId={caseId} invId={current.id} hypotheses={ledger.hypotheses} evidence={ledger.evidence} />
          )}
          {current.report && (
            <>
              <span style={label}>Report</span>
              <div style={{ border: '1px solid var(--border)', borderRadius: '4px', padding: '12px 14px' }}>
                <MarkdownNote content={current.report}
                  style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '13px', color: 'var(--text-primary)' }} />
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
