import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { FimEvent, FimWatchPath } from '@/types'

export function useFimEvents(params?: { agent_id?: string; event_type?: string; path_prefix?: string }) {
  return useQuery<FimEvent[]>({
    queryKey: ['fim', 'events', params],
    queryFn: () => api.get('/api/fim/events', { params }).then(r => r.data),
    refetchInterval: 15_000,
  })
}

export function useFimPaths() {
  return useQuery<FimWatchPath[]>({
    queryKey: ['fim', 'paths'],
    queryFn: () => api.get('/api/fim/paths').then(r => r.data),
  })
}

export function useAddFimPath() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (path: string) => api.post('/api/fim/paths', { path }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fim', 'paths'] }),
  })
}

export function useToggleFimPath() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.patch(`/api/fim/paths/${id}`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fim', 'paths'] }),
  })
}

export function useDeleteFimPath() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/fim/paths/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fim', 'paths'] }),
  })
}
