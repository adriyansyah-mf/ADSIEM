import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { AiFeedback, Case, PaginatedResponse } from '@/types'

export interface CaseFilters {
  status?: string
  severity?: string
  hostname?: string
  search?: string
  start_time?: string
  end_time?: string
}

export function useCases(page = 1, filters: CaseFilters = {}) {
  const { status, severity, hostname, search, start_time, end_time } = filters
  return useQuery<PaginatedResponse<Case>>({
    queryKey: ['cases', page, status, severity, hostname, search, start_time, end_time],
    queryFn: () => api.get('/api/cases', {
      params: { page, page_size: 25, status, severity, hostname, search, start_time, end_time },
    }).then(r => r.data),
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

export function useCaseFeedback(caseId: string) {
  return useQuery<AiFeedback[]>({
    queryKey: ['case-feedback', caseId],
    queryFn: () => api.get(`/api/cases/${caseId}/feedback`).then(r => r.data),
  })
}

export function useSubmitCaseFeedback(caseId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { rating: 'correct' | 'incorrect'; correct_verdict?: string; note?: string }) =>
      api.post(`/api/cases/${caseId}/feedback`, body).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case-feedback', caseId] })
      emitToast('Feedback recorded — thanks!', 'success')
    },
    onError: () => emitToast('Failed to submit feedback', 'error'),
  })
}
