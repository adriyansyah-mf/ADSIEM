import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { Decoder, PaginatedResponse } from '@/types'

export function useDecoders(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Decoder>>({
    queryKey: ['decoders', page, pageSize],
    queryFn: () => api.get('/api/decoders', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}

export function useCreateDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Decoder>) => api.post('/api/decoders', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['decoders'] })
      emitToast('Decoder created', 'success')
    },
    onError: () => emitToast('Failed to create decoder', 'error'),
  })
}

export function useUpdateDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Decoder> }) =>
      api.put(`/api/decoders/${id}`, data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['decoders'] })
      emitToast('Decoder saved', 'success')
    },
    onError: () => emitToast('Failed to save decoder', 'error'),
  })
}

export function useDeleteDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/decoders/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['decoders'] })
      emitToast('Decoder deleted', 'success')
    },
    onError: () => emitToast('Failed to delete decoder', 'error'),
  })
}

export function useTestDecoder() {
  return useMutation({
    mutationFn: (data: { content: string; raw_message: string }) =>
      api.post('/api/decoders/test', data).then(r => r.data),
    onError: () => emitToast('Decoder test failed', 'error'),
  })
}
