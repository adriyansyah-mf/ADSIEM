import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'

export type PreventionRuleType = 'hash' | 'path' | 'dir' | 'parent'
export type PreventionAction = 'detect' | 'block'

export interface PreventionRule {
  id: string
  name: string
  description: string | null
  rule_type: PreventionRuleType
  value: string
  parent: string
  action: PreventionAction
  is_enabled: boolean
  created_at: string
}

export type PreventionRuleInput = Pick<PreventionRule, 'name' | 'rule_type' | 'value' | 'parent' | 'action'> & {
  description?: string
}

const KEY = ['prevention-rules']

export function usePreventionRules() {
  return useQuery<PreventionRule[]>({
    queryKey: KEY,
    queryFn: () => api.get('/api/prevention-rules').then(r => r.data),
  })
}

export function useSavePreventionRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: PreventionRuleInput & { id?: string }) =>
      (id ? api.put(`/api/prevention-rules/${id}`, data) : api.post('/api/prevention-rules', data))
        .then(r => r.data as PreventionRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useTogglePreventionRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.patch(`/api/prevention-rules/${id}/toggle`).then(r => r.data as PreventionRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useDeletePreventionRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/prevention-rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}
