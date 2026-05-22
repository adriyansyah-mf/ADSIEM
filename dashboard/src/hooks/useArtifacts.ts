import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Artifact, AgentTask } from '@/types'

export function useArtifacts() {
  return useQuery<Artifact[]>({
    queryKey: ['artifacts'],
    queryFn: () => api.get('/api/artifacts').then(r => r.data),
  })
}

export function useBuiltinArtifacts() {
  return useQuery<{ name: string; description: string; task_type: string; default_params: Record<string, unknown> }[]>({
    queryKey: ['artifacts-builtins'],
    queryFn: () => api.get('/api/artifacts/builtins').then(r => r.data),
  })
}

export function useRunArtifact() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, agentIds, params }: { id: string; agentIds?: string[]; params?: Record<string, unknown> }) =>
      api.post(`/api/artifacts/${id}/run`, { agent_ids: agentIds, params }).then(r => r.data as AgentTask[]),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tasks'] }),
  })
}
