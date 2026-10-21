import { useMutation, useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Event, PaginatedResponse } from '@/types'

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

export interface WorkloadItem {
  readonly user_id: string
  readonly username: string
  readonly open_alerts: number
  readonly open_cases: number
  readonly total: number
}

export function useAnalystWorkload() {
  return useQuery<WorkloadItem[]>({
    queryKey: ['metrics', 'workload'],
    queryFn: () => api.get('/api/metrics/workload').then(response => response.data),
    refetchInterval: 60_000,
  })
}

export function useRecentEvents() {
  return useQuery<PaginatedResponse<Event>>({
    queryKey: ['events', 'dashboard-recent'],
    queryFn: () => api.get('/api/events', { params: { page_size: 5 } }).then(response => response.data),
    refetchInterval: 30_000,
  })
}

export function useQuickThreatLookup() {
  return useMutation<Record<string, unknown>, Error, { readonly ioc: string; readonly ioc_type: string }>({
    mutationFn: body => api.get('/api/metrics/ti/quick', { params: body }).then(response => response.data),
  })
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
