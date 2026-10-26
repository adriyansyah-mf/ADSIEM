import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

// An AI investigation's ledger (server-api services/investigation_ledger.py):
// the action queue, the evidence it collected, and the hypotheses it tests.

export type ActionStatus = 'queued' | 'running' | 'awaiting_approval' | 'completed' | 'skipped' | 'failed' | 'cancelled'

export interface InvestigationAction {
  id: string
  ordinal: number
  kind: 'siem_query' | 'artifact' | 'command' | 'authoring' | 'analysis'
  tool: string
  target: string | null
  params: Record<string, unknown>
  reason: string | null
  risk_tier: number
  approval_reason: string | null
  status: ActionStatus
  source: 'planner' | 'replanner' | 'analyst'
  dependencies: string[]
  result_ref: { flow_id?: string; command_id?: string; evidence_ids?: string[] }
  error: string | null
  attempts: number
  decision_note: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface InvestigationEvidence {
  id: string
  action_id: string | null
  evidence_type: string
  source_type: string
  source_id: string | null
  title: string
  summary: string | null
  observed_at: string | null
  entities: Record<string, string[]>
  sensitivity: 'normal' | 'sensitive' | 'restricted'
  pinned: boolean
  created_at: string
}

export interface InvestigationHypothesis {
  id: string
  ordinal: number
  statement: string
  state: 'open' | 'supported' | 'refuted' | 'inconclusive' | 'superseded'
  confidence: number
  supporting_evidence_ids: string[]
  contradicting_evidence_ids: string[]
  open_questions: string[]
  source: 'planner' | 'replanner' | 'analyst'
  history: { at: string; actor: string; state: string; confidence: number; reason?: string; proposed_state?: string }[]
  created_at: string
}

export interface NewAction {
  tool: string
  host?: string
  params: Record<string, unknown>
  reason: string
}

function detail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

const base = (caseId: string, invId: string) => `/api/cases/${caseId}/investigations/${invId}`

/** Queue, evidence and hypotheses of one run; polled while it is active. */
export function useInvestigationLedger(caseId: string, invId: string | undefined, active: boolean) {
  const opts = { enabled: !!invId, refetchInterval: active ? 3000 : (false as const) }
  const actions = useQuery<InvestigationAction[]>({
    queryKey: ['investigation', invId, 'actions'],
    queryFn: () => api.get(`${base(caseId, invId!)}/actions`).then(r => r.data),
    ...opts,
  })
  const evidence = useQuery<InvestigationEvidence[]>({
    queryKey: ['investigation', invId, 'evidence'],
    queryFn: () => api.get(`${base(caseId, invId!)}/evidence`).then(r => r.data),
    ...opts,
  })
  const hypotheses = useQuery<InvestigationHypothesis[]>({
    queryKey: ['investigation', invId, 'hypotheses'],
    queryFn: () => api.get(`${base(caseId, invId!)}/hypotheses`).then(r => r.data),
    ...opts,
  })
  return { actions: actions.data ?? [], evidence: evidence.data ?? [], hypotheses: hypotheses.data ?? [] }
}

/** Analyst controls on a run: add / skip / decide actions, pin evidence, state hypotheses, raise the budget. */
export function useInvestigationControls(caseId: string, invId: string | undefined) {
  const qc = useQueryClient()
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['investigation', invId] })
    qc.invalidateQueries({ queryKey: ['investigations', caseId] })
  }
  const fail = (fallback: string) => (e: unknown) => { emitToast(detail(e, fallback), 'error'); refresh() }
  return {
    addAction: useMutation({
      mutationFn: (body: NewAction) => api.post(`${base(caseId, invId!)}/actions`, body).then(r => r.data),
      onSuccess: () => { emitToast('Action queued; it runs at the next step', 'success'); refresh() },
      onError: fail('Could not queue the action'),
    }),
    skip: useMutation({
      mutationFn: (actionId: string) => api.post(`/api/investigation-actions/${actionId}/skip`).then(r => r.data),
      onSuccess: refresh, onError: fail('Could not skip the action'),
    }),
    decide: useMutation({
      mutationFn: ({ actionId, approve, note }: { actionId: string; approve: boolean; note?: string }) =>
        api.post(`/api/investigation-actions/${actionId}/decision`, { approve, note: note || null }).then(r => r.data),
      onSuccess: refresh, onError: fail('Could not record the decision'),
    }),
    pin: useMutation({
      mutationFn: ({ evidenceId, pinned }: { evidenceId: string; pinned: boolean }) =>
        api.post(`/api/investigation-evidence/${evidenceId}/pin`, { pinned }).then(r => r.data),
      onSuccess: refresh, onError: fail('Could not pin the evidence'),
    }),
    addHypothesis: useMutation({
      mutationFn: (statement: string) => api.post(`${base(caseId, invId!)}/hypotheses`, { statement }).then(r => r.data),
      onSuccess: refresh, onError: fail('Could not add the hypothesis'),
    }),
    setHypothesis: useMutation({
      mutationFn: ({ id, state }: { id: string; state: InvestigationHypothesis['state'] }) =>
        api.post(`/api/investigation-hypotheses/${id}`, { state }).then(r => r.data),
      onSuccess: refresh, onError: fail('Could not update the hypothesis'),
    }),
    raiseBudget: useMutation({
      mutationFn: (flows: number) => api.post(`/api/investigations/${invId}/budget`, { flows }).then(r => r.data),
      onSuccess: () => { emitToast('Live-response budget raised', 'success'); refresh() },
      onError: fail('Could not raise the budget'),
    }),
    promote: useMutation({
      mutationFn: (name: string) => api.post(`/api/flow-artifacts/${encodeURIComponent(name)}/promote`).then(r => r.data),
      onSuccess: (_d, name) => { emitToast(`${name} can now be reused by AI investigations`, 'success'); refresh() },
      onError: fail('Could not promote the artifact'),
    }),
  }
}
