import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
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
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoders'] }),
  })
}

export function useUpdateDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Decoder> }) =>
      api.put(`/api/decoders/${id}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoders'] }),
  })
}

export function useDeleteDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/decoders/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoders'] }),
  })
}

export function useTestDecoder() {
  return useMutation({
    mutationFn: (data: { content: string; raw_message: string }) =>
      api.post('/api/decoders/test', data).then(r => r.data),
  })
}
