import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, Webhook } from '@/types'

export function useWebhooks(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Webhook>>({
    queryKey: ['webhooks', page, pageSize],
    queryFn: () => api.get('/api/webhooks', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}

export function useCreateWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Webhook>) => api.post('/api/webhooks', data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}

export function useDeleteWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/webhooks/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}
