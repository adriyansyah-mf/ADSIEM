import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Case, PaginatedResponse } from '@/types'

export function useCases(page = 1, status?: string) {
  return useQuery<PaginatedResponse<Case>>({
    queryKey: ['cases', page, status],
    queryFn: () => api.get('/api/cases', { params: { page, page_size: 25, status } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}

export function useCase(id: string) {
  return useQuery<Case>({
    queryKey: ['case', id],
    queryFn: () => api.get(`/api/cases/${id}`).then(r => r.data),
  })
}

export function useUpdateCase(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Case>) => api.put(`/api/cases/${id}`, data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      qc.invalidateQueries({ queryKey: ['case', id] })
    },
  })
}

export function useEscalateCase(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.post(`/api/cases/${id}/escalate`).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      qc.invalidateQueries({ queryKey: ['case', id] })
    },
  })
}

export function useAddCaseNote(id: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (content: string) => api.post(`/api/cases/${id}/notes`, { content }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['case', id] }),
  })
}
