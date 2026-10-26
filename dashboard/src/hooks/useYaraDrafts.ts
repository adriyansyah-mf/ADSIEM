import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

// Malware candidates of an AI investigation and the YARA drafts made from them
// (server-api routes/yara_drafts.py, services/yara_drafting.py).

export interface Support { kind: 'reputation' | 'yara' | 'mentioned' | 'analyst' | 'hypothesis'; evidence_id: string; detail: string }

export interface MalwareCandidate {
  sha256: string
  path: string
  host: string
  size: number | null
  type: string | null
  evidence_id: string
  support: Support[]
  eligible: boolean
  draft_id: string | null
  draft_status: string | null
}

export interface YaraDraft {
  id: string
  investigation_id: string
  case_id: string
  host: string | null
  path: string | null
  sha256: string
  status: 'collecting' | 'drafting' | 'draft' | 'failed' | 'dismissed'
  flow_id: string | null
  features: Record<string, unknown> | null
  support: Support[]
  rule_name: string | null
  rule_text: string | null
  rationale: { id: string; kind: string; value: string; why: string }[]
  limitations: string[]
  false_positives: string[]
  quality: { blocking?: string[]; warnings?: string[] }
  confidence: number | null
  mitre: string[]
  tags: string[]
  error: string | null
  yara_rule_id: string | null
  created_at: string
}

function detail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return d
  if (d && typeof d === 'object' && 'message' in d) {
    const o = d as { message: string; problems?: string[] }
    return [o.message, ...(o.problems ?? [])].join(' · ')
  }
  return fallback
}

const BUSY = new Set(['collecting', 'drafting'])

export function useMalware(caseId: string, invId: string | undefined) {
  const drafts = useQuery<YaraDraft[]>({
    queryKey: ['investigation', invId, 'yara-drafts'],
    queryFn: () => api.get(`/api/investigations/${invId}/yara-drafts`).then(r => r.data),
    enabled: !!invId,
    refetchInterval: q => ((q.state.data as YaraDraft[] | undefined)?.some(d => BUSY.has(d.status)) ? 3000 : 15000),
  })
  const candidates = useQuery<{ mode: string; mode_note: string | null; candidates: MalwareCandidate[] }>({
    queryKey: ['investigation', invId, 'malware-candidates'],
    queryFn: () => api.get(`/api/cases/${caseId}/investigations/${invId}/malware-candidates`).then(r => r.data),
    enabled: !!invId,
    refetchInterval: 15000,
  })
  return { drafts: drafts.data ?? [], ...(candidates.data ?? { mode: 'draft_only', mode_note: null, candidates: [] }) }
}

export function useMalwareActions(caseId: string, invId: string | undefined) {
  const qc = useQueryClient()
  const refresh = () => qc.invalidateQueries({ queryKey: ['investigation', invId] })
  const fail = (fallback: string) => (e: unknown) => { emitToast(detail(e, fallback), 'error'); refresh() }
  return {
    requestDraft: useMutation({
      mutationFn: (sha256: string) => api.post(`/api/investigations/${invId}/yara-drafts`, { sha256 }).then(r => r.data),
      onSuccess: () => { emitToast('Collecting the file’s features on its host…', 'info'); refresh() },
      onError: fail('Could not start the draft'),
    }),
    dismiss: useMutation({
      mutationFn: (sha256: string) => api.post(`/api/investigations/${invId}/malware-candidates/dismiss`, { sha256 }),
      onSuccess: refresh, onError: fail('Could not dismiss'),
    }),
    scanWithRules: useMutation({
      // an analyst action on the investigation queue (read-only YARA scan of that path)
      mutationFn: (c: MalwareCandidate) => api.post(`/api/cases/${caseId}/investigations/${invId}/actions`, {
        tool: 'run_artifact', host: c.host,
        params: { artifact: /^[A-Za-z]:\\|\\/.test(c.path) ? 'Windows.Detection.Yara' : 'Linux.Detection.Yara',
          params: { Path: c.path, Recursive: false } },
        reason: `Scan ${c.path} with the enabled YARA rules`,
      }),
      onSuccess: () => { emitToast('YARA scan queued on the investigation', 'success'); refresh() },
      onError: fail('Could not queue the scan'),
    }),
    edit: useMutation({
      mutationFn: ({ id, rule_text }: { id: string; rule_text: string }) =>
        api.put(`/api/yara-drafts/${id}`, { rule_text }).then(r => r.data as YaraDraft),
      onSuccess: refresh, onError: fail('Could not save the edit'),
    }),
    save: useMutation({
      mutationFn: (id: string) => api.post(`/api/yara-drafts/${id}/save`).then(r => r.data as YaraDraft),
      onSuccess: () => { emitToast('Saved to the YARA rules, disabled', 'success'); refresh() },
      onError: fail('Could not save the rule'),
    }),
  }
}
