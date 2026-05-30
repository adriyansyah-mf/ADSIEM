import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { Alert, PaginatedResponse } from '@/types'

export function useAlerts(page = 1, pageSize = 25, status?: string, severity?: string) {
  return useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts', page, pageSize, status, severity],
    queryFn: () => api.get('/api/alerts', { params: { page, page_size: pageSize, status, severity } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}

export function useUpdateAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: { status?: string; assignee_id?: string } }) =>
      api.put(`/api/alerts/${id}`, data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      emitToast('Alert updated', 'success')
    },
    onError: () => emitToast('Failed to update alert', 'error'),
  })
}

export function useAddAlertNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, content }: { id: string; content: string }) =>
      api.post(`/api/alerts/${id}/notes`, { content }).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      emitToast('Note added', 'success')
    },
    onError: () => emitToast('Failed to add note', 'error'),
  })
}
