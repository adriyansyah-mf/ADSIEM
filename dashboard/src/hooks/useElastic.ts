import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface VolumePoint {
  t: string
  total: number
  types: Record<string, number>
}

export interface TopValue {
  value: string
  count: number
}

export interface SecuritySignals {
  hours: number
  interval: string
  auth_failures: { t: string; count: number }[]
  action_mix: { action: string; count: number }[]
  unique_source_ips: number
}

export function useElasticStats() {
  return useQuery<{ docs: number; size: string }>({
    queryKey: ['elastic', 'stats'],
    queryFn: () => api.get('/api/elastic/stats').then(r => r.data),
    refetchInterval: 60_000,
  })
}

export function useElasticVolume(hours = 24, interval = '5m') {
  return useQuery<{ hours: number; interval: string; total: number; points: VolumePoint[] }>({
    queryKey: ['elastic', 'volume', hours, interval],
    queryFn: () => api.get('/api/elastic/volume', { params: { hours, interval } }).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useElasticTop(field: string, hours = 24, limit = 10) {
  return useQuery<{ field: string; hours: number; values: TopValue[] }>({
    queryKey: ['elastic', 'top', field, hours, limit],
    queryFn: () => api.get('/api/elastic/top', { params: { field, hours, limit } }).then(r => r.data),
    refetchInterval: 60_000,
  })
}

export function useSecuritySignals(hours = 24, interval = '1h') {
  return useQuery<SecuritySignals>({
    queryKey: ['elastic', 'security-signals', hours, interval],
    queryFn: () => api.get('/api/elastic/security-signals', { params: { hours, interval } }).then(r => r.data),
    refetchInterval: 60_000,
  })
}

export function useAgentsVolume(hours = 6, limit = 8) {
  return useQuery<{ hours: number; agents: { agent_id: string; count: number }[] }>({
    queryKey: ['elastic', 'agents-volume', hours, limit],
    queryFn: () => api.get('/api/elastic/agents-volume', { params: { hours, limit } }).then(r => r.data),
    refetchInterval: 60_000,
  })
}
