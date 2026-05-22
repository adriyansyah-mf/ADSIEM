import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, Rule } from '@/types'

export function useRules(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Rule>>({
    queryKey: ['rules', page, pageSize],
    queryFn: () => api.get('/api/rules', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}

export function useCreateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Rule>) => api.post('/api/rules', data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useUpdateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Rule> }) =>
      api.put(`/api/rules/${id}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useTestRule() {
  return useMutation({
    mutationFn: (data: { content: string; sample_event: Record<string, unknown> }) =>
      api.post('/api/rules/test', data).then(r => r.data),
  })
}
