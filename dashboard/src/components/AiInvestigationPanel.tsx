import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import MarkdownNote from '@/components/MarkdownNote'

interface Step {
  ts: string
  kind: string
  [key: string]: unknown
}

interface Investigation {
  id: string
  case_id: string
  status: 'queued' | 'running' | 'finished' | 'error' | 'cancelled' | 'interrupted'
  model: string | null
  verdict: string | null
  report: string | null
  error: string | null
  steps: Step[]
  created_at: string
  finished_at: string | null
}

const ACTIVE = new Set(['queued', 'running'])
const VERDICT_COLOR: Record<string, string> = {
  true_positive: 'var(--accent-red, #f87171)',
  false_positive: 'var(--accent-green, #4ade80)',
  inconclusive: 'var(--accent-yellow, #fbbf24)',
}

function detail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

function StepLine({ step }: { step: Step }) {
  const [open, setOpen] = useState(false)
  const time = format(new Date(step.ts), 'HH:mm:ss')
  let icon = '•'
  let text: React.ReactNode = step.kind
  switch (step.kind) {
    case 'started':
      icon = '▶'; text = `Started by ${step.by} (${step.model})`; break
    case 'context':
      icon = '📋'; text = `Read the case — hosts: ${(step.hosts as string[]).join(', ') || 'none linked'}`; break
    case 'thought':
      icon = '💭'; text = <span className="italic">{String(step.text)}</span>; break
    case 'tool':
      icon = '🔎'; text = <><span className="font-mono">{String(step.tool)}</span>{' '}
        <span className="text-muted-foreground font-mono">{JSON.stringify(step.args)}</span></>; break
    case 'flow':
      icon = '🖥'; text = <>Live response <b>{String(step.artifact)}</b> on <b>{String(step.host)}</b>
        {step.reason ? <span className="text-muted-foreground"> — {String(step.reason)}</span> : null}{' '}
        <a className="underline" href={`/live-response?flow=${step.flow_id}`}>open flow</a></>; break
    case 'flow_result':
      icon = '📥'; text = <>Flow {String(step.status)}: {Object.entries((step.rows as Record<string, number>) || {})
        .map(([s, n]) => `${s} ${n} rows`).join(', ')}</>; break
    case 'artifact':
      icon = '🧩'; text = <>Created artifact <b>{String(step.name)}</b>
        {step.reason ? <span className="text-muted-foreground"> — {String(step.reason)}</span> : null}{' '}
        <button className="underline" onClick={() => setOpen(o => !o)}>{open ? 'hide' : 'YAML'}</button></>; break
    case 'warning':
      icon = '⚠'; text = <span className="text-amber-400">{String(step.text)}</span>; break
    case 'refused':
      icon = '⛔'; text = <span className="text-destructive">Refused: {String(step.reason)}</span>; break
    case 'finished':
      icon = '✅'; text = `Finished — ${String(step.verdict).replace('_', ' ')}, ${step.flows} live-response runs, ${step.artifacts} new artifacts`; break
    case 'cancelled':
      icon = '⏹'; text = `Cancelled: ${String(step.reason)}`; break
    case 'error':
      icon = '⚠'; text = <span className="text-destructive">Error: {String(step.error)}</span>; break
  }
  return (
    <div className="text-xs py-0.5">
      <span className="text-muted-foreground font-mono mr-2">{time}</span>
      <span className="mr-1">{icon}</span>
      {text}
      {open && step.kind === 'artifact' && (
        <pre className="mt-1 ml-16 p-2 rounded border border-border bg-muted/30 font-mono whitespace-pre-wrap">{String(step.yaml)}</pre>
      )}
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
  const current = runs.find(r => r.id === selectedId) ?? runs[0]
  const active = current ? ACTIVE.has(current.status) : false

  // the report is added to the case as an AI note: refresh the case when a run ends
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

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={() => start.mutate()} disabled={active || start.isPending}
          className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
          {active ? 'Investigating…' : '🤖 Investigate with AI'}
        </button>
        {active && current && (
          <button onClick={() => cancel.mutate(current.id)} disabled={cancel.isPending}
            className="px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">Cancel</button>
        )}
        {runs.length > 1 && (
          <select value={current?.id} onChange={e => setSelectedId(e.target.value)}
            className="ml-auto px-2 py-1 rounded border border-border bg-background text-xs">
            {runs.map(r => (
              <option key={r.id} value={r.id}>
                {format(new Date(r.created_at), 'dd MMM HH:mm')} — {r.status}{r.verdict ? ` (${r.verdict.replace('_', ' ')})` : ''}
              </option>
            ))}
          </select>
        )}
      </div>
      {!current && (
        <p className="text-xs text-muted-foreground">
          The AI reads this case, searches the logs and runs live-response artifacts on the affected hosts
          (writing new ones when needed), then adds its findings to the case. It only collects — isolation,
          killing processes and other response actions stay with you.
        </p>
      )}
      {current && (
        <>
          <div className="flex items-center gap-2 text-xs">
            <span className="font-semibold uppercase">{current.status}</span>
            {current.verdict && (
              <span style={{ color: VERDICT_COLOR[current.verdict], border: `1px solid ${VERDICT_COLOR[current.verdict]}` }}
                className="px-1.5 rounded font-semibold uppercase">{current.verdict.replace('_', ' ')}</span>
            )}
            {current.model && <span className="text-muted-foreground">{current.model}</span>}
            {current.error && <span className="text-destructive">{current.error}</span>}
          </div>
          <div className="max-h-72 overflow-auto rounded border border-border p-2">
            {current.steps.length === 0 ? <div className="text-xs text-muted-foreground">Queued…</div>
              : current.steps.map((s, i) => <StepLine key={i} step={s} />)}
          </div>
          {current.report && (
            <div className="rounded border border-border p-3">
              <MarkdownNote content={current.report}
                style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '13px', color: 'var(--text-primary)' }} />
            </div>
          )}
        </>
      )}
    </div>
  )
}
