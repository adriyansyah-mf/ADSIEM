import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { UebaEntityScore, UebaEntityDetail, UebaStatus } from '@/types'

export function useUebaEntities(entityType: 'user' | 'ip' | 'all' = 'all', minRisk = 0) {
  return useQuery<UebaEntityScore[]>({
    queryKey: ['ueba', 'entities', entityType, minRisk],
    queryFn: () =>
      api.get('/api/ueba/entities', { params: { entity_type: entityType, min_risk: minRisk } })
        .then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useUebaEntityDetail(entityType: string, entityValue: string) {
  return useQuery<UebaEntityDetail>({
    queryKey: ['ueba', 'entity', entityType, entityValue],
    queryFn: () =>
      api.get(`/api/ueba/entity/${entityType}/${encodeURIComponent(entityValue)}`).then(r => r.data),
    enabled: !!entityType && !!entityValue,
    refetchInterval: 60_000,
  })
}

export function useUebaStatus() {
  return useQuery<UebaStatus>({
    queryKey: ['ueba', 'status'],
    queryFn: () => api.get('/api/ueba/status').then(r => r.data),
    refetchInterval: 60_000,
  })
}
