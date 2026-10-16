import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface SocrMetrics {
  period_days: number
  total_alerts: number
  open_cases: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  avg_ack_minutes: number | null
  avg_mttr_minutes: number | null
  false_positive_rate_pct: number
}

export interface TimeseriesPoint {
  t: string
  total: number
  critical?: number
  high?: number
  medium?: number
  low?: number
  info?: number
}

export interface TopSource {
  ip: string
  count: number
}

export interface MttrPoint {
  day: string
  avg_ack_minutes: number | null
  avg_mttr_minutes: number | null
}

export function useSocMetrics(days = 7) {
  return useQuery<SocrMetrics>({
    queryKey: ['metrics', 'soc', days],
    queryFn: () => api.get('/api/metrics/soc', { params: { days } }).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useSocTimeseries(days = 7) {
  return useQuery<{ period_days: number; points: TimeseriesPoint[] }>({
    queryKey: ['metrics', 'timeseries', days],
    queryFn: () => api.get('/api/metrics/soc/timeseries', { params: { days } }).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useTopSources(days = 7) {
  return useQuery<{ period_days: number; sources: TopSource[] }>({
    queryKey: ['metrics', 'top-sources', days],
    queryFn: () => api.get('/api/metrics/soc/top-sources', { params: { days } }).then(r => r.data),
    refetchInterval: 60_000,
  })
}

export function useMttrTrend(days = 30) {
  return useQuery<{ period_days: number; points: MttrPoint[] }>({
    queryKey: ['metrics', 'mttr-trend', days],
    queryFn: () => api.get('/api/metrics/soc/mttr-trend', { params: { days } }).then(r => r.data),
    refetchInterval: 60_000,
  })
}
