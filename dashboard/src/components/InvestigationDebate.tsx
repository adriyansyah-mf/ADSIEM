import { CheckCircle2, MessagesSquare, XCircle } from 'lucide-react'

// The review panel's debate of the lead investigator's draft
// (server-api/app/services/investigation_debate.py).

export interface DebatePosition {
  role: string
  name: string
  error?: string
  verdict?: string
  confidence?: number
  agrees_with_draft?: boolean
  summary?: string
  challenges?: { claim: string; issue: string; evidence_ids: string[] }[]
  missing_evidence?: string[]
  responses?: { to: string; point: string }[]
}

export interface Debate {
  agents: string[]
  rounds: DebatePosition[][]
  tally: Record<string, number>
  consensus: string | null
  brief: string | null
}

interface Step {
  kind: string
  [key: string]: unknown
}

const mono: React.CSSProperties = { fontFamily: 'Share Tech Mono, monospace' }

const VERDICT_COLOR: Record<string, string> = {
  true_positive: 'var(--accent-red)', false_positive: 'var(--accent-green)', inconclusive: 'var(--accent-yellow)',
}

function verdictText(v?: string) {
  return (v ?? 'inconclusive').replace('_', ' ')
}

function Position({ p }: { p: DebatePosition }) {
  if (p.error) {
    return (
      <div style={{ padding: '6px 8px', border: '1px dashed var(--border)', borderRadius: '4px', fontSize: '12px' }}>
        <b>{p.name}</b> <span style={{ color: 'var(--text-muted)' }}>did not answer: {p.error}</span>
      </div>
    )
  }
  const color = VERDICT_COLOR[p.verdict ?? 'inconclusive'] ?? 'var(--text-muted)'
  return (
    <div style={{ padding: '8px 10px', border: '1px solid var(--border)', borderLeft: `3px solid ${color}`, borderRadius: '4px' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
        <b>{p.name}</b>
        <span style={{ ...mono, color }}>{verdictText(p.verdict)}{p.confidence != null ? ` ${p.confidence}%` : ''}</span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '3px', color: 'var(--text-muted)' }}>
          {p.agrees_with_draft ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
          {p.agrees_with_draft ? 'agrees with the draft' : 'disputes the draft'}
        </span>
      </div>
      {p.summary && <div style={{ fontSize: '12px', marginTop: '4px', lineHeight: 1.45 }}>{p.summary}</div>}
      {(p.challenges ?? []).map((c, i) => (
        <div key={`c${i}`} style={{ fontSize: '12px', marginTop: '4px', color: 'var(--text-secondary)' }}>
          ✗ <i>{c.claim}</i>: {c.issue}
          {c.evidence_ids.length > 0 && <span style={{ ...mono, color: 'var(--text-muted)' }}> [{c.evidence_ids.map(e => e.slice(0, 8)).join(', ')}]</span>}
        </div>
      ))}
      {(p.missing_evidence ?? []).map((m, i) => (
        <div key={`m${i}`} style={{ fontSize: '12px', marginTop: '4px', color: 'var(--accent-cyan)' }}>? {m}</div>
      ))}
      {(p.responses ?? []).map((r, i) => (
        <div key={`r${i}`} style={{ fontSize: '12px', marginTop: '4px', color: 'var(--text-secondary)' }}>
          ↳ to <b>{r.to}</b>: {r.point}
        </div>
      ))}
    </div>
  )
}

/** The finished debate (all detail) or, while it runs, the per-round summaries from the steps. */
export default function DebateView({ debate, steps }: { debate: Debate | null; steps: Step[] }) {
  const rounds: DebatePosition[][] = debate?.rounds ?? steps
    .filter(s => s.kind === 'debate_round')
    .map(s => ((s.positions as Record<string, unknown>[]) ?? []).map(p => ({
      role: String(p.name), name: String(p.name), error: p.error as string | undefined,
      verdict: p.verdict as string | undefined, confidence: p.confidence as number | undefined,
      agrees_with_draft: p.agrees as boolean | undefined, summary: p.summary as string | undefined,
    })))
  const started = steps.find(s => s.kind === 'debate_started')
  if (!debate && !started) {
    return (
      <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)', padding: '10px' }}>
        No review panel sat on this run. Set the number of reviewers in Settings → AI Investigation Review Panel.
      </div>
    )
  }
  const reviewers = debate?.agents ?? (started?.reviewers as string[] | undefined) ?? []
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '420px', overflow: 'auto' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
        <MessagesSquare size={13} />
        <span>{reviewers.length} reviewers: {reviewers.join(', ')}</span>
        {debate && Object.keys(debate.tally).length > 0 && (
          <span style={{ ...mono, color: 'var(--text-muted)' }}>
            final: {Object.entries(debate.tally).map(([v, n]) => `${n}× ${verdictText(v)}`).join(' · ')}
            {debate.consensus ? ' (consensus)' : ''}
          </span>
        )}
        {!debate && <span style={{ color: 'var(--accent-cyan)' }}>debating…</span>}
      </div>
      {rounds.map((positions, i) => (
        <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <span style={{ fontSize: '11px', letterSpacing: '0.5px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Round {i + 1}
          </span>
          {positions.map(p => <Position key={p.role} p={p} />)}
        </div>
      ))}
      {debate?.brief && (
        <details style={{ fontSize: '12px' }}>
          <summary style={{ cursor: 'pointer', color: 'var(--text-muted)' }}>What the lead investigator was told</summary>
          <pre style={{ ...mono, whiteSpace: 'pre-wrap', fontSize: '11px', margin: '6px 0 0' }}>{debate.brief}</pre>
        </details>
      )}
    </div>
  )
}
