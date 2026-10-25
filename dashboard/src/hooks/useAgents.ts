import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Agent, AgentEvidence, FirewallRule, LogSource, PaginatedResponse } from '@/types'

export function useAgentEvidence(agentId: string) {
  return useQuery<AgentEvidence>({
    queryKey: ['agent-evidence', agentId],
    queryFn: () => api.get(`/api/agents/${agentId}/evidence`).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useRetryEvidence(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (receiptId: string) => api.post(`/api/agents/${agentId}/evidence/${receiptId}/retry`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent-evidence', agentId] }),
  })
}

export function useAgents(page = 1, pageSize = 25, search = '', status = '') {
  return useQuery<PaginatedResponse<Agent>>({
    queryKey: ['agents', page, pageSize, search, status],
    queryFn: () => api.get('/api/agents', {
      params: { page, page_size: pageSize, search: search || undefined, status: status || undefined },
    }).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useAgent(agentId: string) {
  return useQuery<Agent>({
    queryKey: ['agent', agentId],
    queryFn: () => api.get(`/api/agents/${agentId}`).then(r => r.data),
  })
}

export function useLogSources(agentId: string) {
  return useQuery<LogSource[]>({
    queryKey: ['log-sources', agentId],
    queryFn: () => api.get(`/api/agents/${agentId}/log-sources`).then(r => r.data),
  })
}

export function useAddLogSource(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { path: string; log_type: string; is_enabled: boolean }) =>
      api.post(`/api/agents/${agentId}/log-sources`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources', agentId] }),
  })
}

export function useUpdateLogSource(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ sourceId, data }: { sourceId: string; data: Partial<LogSource> }) =>
      api.put(`/api/agents/${agentId}/log-sources/${sourceId}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources', agentId] }),
  })
}

export function useDeleteLogSource(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sourceId: string) =>
      api.delete(`/api/agents/${agentId}/log-sources/${sourceId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources', agentId] }),
  })
}

export function useFirewallRules(agentId: string) {
  return useQuery<FirewallRule[]>({
    queryKey: ['firewall', agentId],
    queryFn: () => api.get(`/api/agents/${agentId}/firewall`).then(r => r.data),
    enabled: !!agentId,
  })
}

export function useAddFirewallRule(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Omit<FirewallRule, 'id' | 'agent_id' | 'created_at'>) =>
      api.post(`/api/agents/${agentId}/firewall`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['firewall', agentId] }),
  })
}

export function useDeleteFirewallRule(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (ruleId: string) => api.delete(`/api/agents/${agentId}/firewall/${ruleId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['firewall', agentId] }),
  })
}