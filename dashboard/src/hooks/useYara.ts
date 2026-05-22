import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { YaraRule, AgentTask } from '@/types'

export function useYaraRules() {
  return useQuery<YaraRule[]>({
    queryKey: ['yara-rules'],
    queryFn: () => api.get('/api/yara-rules').then(r => r.data),
  })
}

export function useCreateYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; description?: string; content: string }) =>
      api.post('/api/yara-rules', data).then(r => r.data as YaraRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })
}

export function useUpdateYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string; name: string; description?: string; content: string }) =>
      api.put(`/api/yara-rules/${id}`, data).then(r => r.data as YaraRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })
}

export function useToggleYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.patch(`/api/yara-rules/${id}/toggle`).then(r => r.data as YaraRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })
}

export function useDeleteYaraRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/yara-rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })
}

export function useYaraScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { agent_id: string; path: string; recursive?: boolean; rule_ids?: string[] }) =>
      api.post('/api/yara-rules/scan', data).then(r => r.data as AgentTask),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tasks'] }),
  })
}

export function useSeedBuiltinRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post('/api/yara-rules/seed-builtins').then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['yara-rules'] }),
  })
}
