import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { UebaEntityScore, UebaEntityDetail, UebaStatus, UebaRiskPoint, UebaAnomaly } from '@/types'

export function useUebaEntities(entityType: 'user' | 'ip' | 'host' | 'all' = 'all', minRisk = 0) {
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

export function useUebaRiskHistory(entityType: string, entityValue: string, days = 7) {
  return useQuery<UebaRiskPoint[]>({
    queryKey: ['ueba', 'history', entityType, entityValue, days],
    queryFn: () =>
      api.get(`/api/ueba/entity/${entityType}/${encodeURIComponent(entityValue)}/history`, { params: { days } })
        .then(r => r.data),
    enabled: !!entityType && !!entityValue,
  })
}

export function useUebaAnomalies(params: {
  entity_type?: string
  ai_action?: string
  min_risk?: number
  hours?: number
  limit?: number
} = {}) {
  return useQuery<UebaAnomaly[]>({
    queryKey: ['ueba', 'anomalies', params],
    queryFn: () =>
      api.get('/api/ueba/anomalies', { params }).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useTriggerInvestigation() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ entityType, entityValue }: { entityType: string; entityValue: string }) =>
      api.post(`/api/ueba/entity/${entityType}/${encodeURIComponent(entityValue)}/investigate`).then(r => r.data),
    onSuccess: (_data, { entityType, entityValue }) => {
      qc.invalidateQueries({ queryKey: ['ueba', 'entity', entityType, entityValue] })
    },
  })
}
