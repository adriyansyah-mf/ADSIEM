import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Agent, LogSource, PaginatedResponse } from '@/types'

export function useAgents(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Agent>>({
    queryKey: ['agents', page, pageSize],
    queryFn: () => api.get('/api/agents', { params: { page, page_size: pageSize } }).then(r => r.data),
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
