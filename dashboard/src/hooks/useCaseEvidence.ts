import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { AgentTask } from '@/types'

export interface EvidenceAlert {
  readonly id: string
  readonly title: string
  readonly severity: string
  readonly hostname: string | null
  readonly agent_id: string | null
  readonly source_ip: string | null
  readonly created_at: string
  readonly status: 'linked' | 'suggested' | 'detached'
  readonly method: string
  readonly reason: string
  readonly confidence: number | null
  readonly indicators: readonly string[]
  readonly accounts: readonly string[]
}

interface Evidence {
  readonly alerts: readonly EvidenceAlert[]
  readonly blockable_ips: readonly string[]
}

export function useCaseEvidence(caseId: string) {
  return useQuery({
    queryKey: ['case-evidence', caseId],
    queryFn: async () => (await api.get<Evidence>(`/api/cases/${caseId}/evidence`)).data,
    refetchInterval: 15_000,
  })
}

export function useCaseMembership(caseId: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: async (selection: { alertId: string; status: 'linked' | 'detached' }) =>
      api.put(`/api/cases/${caseId}/alerts/${selection.alertId}`, { status: selection.status }),
    onSuccess: () => { void client.invalidateQueries() },
  })
}

export function useCaseRemediations(caseId: string) {
  return useQuery({
    queryKey: ['case-remediations', caseId],
    queryFn: async () => (await api.get<AgentTask[]>(`/api/cases/${caseId}/remediations`)).data,
    refetchInterval: 3000,
  })
}

export function useBlockCaseIps(caseId: string) {
  const client = useQueryClient()
  return useMutation({
    mutationFn: async (selection: {
      request_id: string; ips: string[]; agent_ids: string[]; duration_seconds: number
    }) => (await api.post<AgentTask[]>(`/api/cases/${caseId}/remediations`, selection)).data,
    onSuccess: () => { void client.invalidateQueries({ queryKey: ['case-remediations', caseId] }) },
  })
}
