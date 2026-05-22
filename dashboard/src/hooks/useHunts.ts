import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { ThreatHunt } from '@/types'

export function useHunts() {
  return useQuery<ThreatHunt[]>({
    queryKey: ['hunts'],
    queryFn: () => api.get('/api/hunts').then(r => r.data),
    refetchInterval: 8_000,
  })
}

export function useHunt(id: string) {
  return useQuery<ThreatHunt>({
    queryKey: ['hunts', id],
    queryFn: () => api.get(`/api/hunts/${id}`).then(r => r.data),
    refetchInterval: q => q.state.data?.status === 'done' || q.state.data?.status === 'failed' ? false : 3_000,
  })
}

export function useStartHunt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { ioc_type: string; ioc_value: string }) =>
      api.post('/api/hunts', data).then(r => r.data as ThreatHunt),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['hunts'] }),
  })
}
