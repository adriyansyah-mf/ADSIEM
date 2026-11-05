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

export function useSocMetrics(days = 7, live = true) {
  return useQuery<SocrMetrics>({
    queryKey: ['metrics', 'soc', days],
    queryFn: () => api.get('/api/metrics/soc', { params: { days } }).then(r => r.data),
    refetchInterval: live ? 30_000 : false,
    refetchOnWindowFocus: live,
    refetchOnReconnect: live,
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

export type SeverityCounts = Partial<Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>> & Record<string, number | undefined>

export interface GeoLocation {
  readonly lat: number
  readonly lon: number
  readonly city: string | null
  readonly country: string | null
  readonly country_code: string | null
}

export interface GeoPoint extends GeoLocation {
  readonly ip: string
  readonly count: number
  readonly by_severity: SeverityCounts
  readonly max_severity: string
  readonly last_seen: string | null
}

export interface GeoCountry {
  readonly country: string
  readonly country_code: string | null
  readonly count: number
  readonly unique_ips: number
  readonly by_severity: SeverityCounts
  readonly max_severity: string
}

export interface GeoRecentAlert extends GeoLocation {
  readonly id: string
  readonly title: string
  readonly severity: string
  readonly status: string
  readonly source_ip: string
  readonly hostname: string | null
  readonly created_at: string | null
}

export interface SocGeo {
  readonly period_days: number
  readonly geoip_available: boolean
  readonly target: { readonly lat: number; readonly lon: number; readonly label: string } | null
  readonly distinct_source_ips: number
  readonly ip_scan_truncated: boolean
  readonly points: readonly GeoPoint[]
  readonly points_truncated: boolean
  readonly countries: readonly GeoCountry[]
  readonly located_alerts: number
  readonly unlocated_alerts: number
  readonly unlocated_ips: number
  readonly recent: readonly GeoRecentAlert[]
}

export interface SocPosture {
  readonly period_days: number
  readonly generated_at: string
  readonly backlog: {
    readonly open_total: number
    readonly unassigned: number
    readonly age_buckets: readonly ({ readonly bucket: 'lt_1h' | '1h_4h' | '4h_24h' | 'gt_24h' } & Record<string, number | string>)[]
    readonly sla_minutes: Record<string, number>
    readonly sla_breaches: Record<string, number>
    readonly sla_breaches_total: number
    readonly oldest_new_minutes: Record<string, number>
  }
  readonly top_hosts: readonly { readonly hostname: string; readonly count: number; readonly by_severity: SeverityCounts; readonly max_severity: string }[]
  readonly top_detections: readonly { readonly title: string; readonly count: number; readonly false_positives: number }[]
  readonly agents: { readonly total: number; readonly online: number; readonly offline: number; readonly isolated: number }
}

export function useSocGeo(days = 7, live = true) {
  return useQuery<SocGeo>({
    queryKey: ['metrics', 'soc-geo', days],
    queryFn: () => api.get('/api/metrics/soc/geo', { params: { days } }).then(r => r.data),
    refetchInterval: live ? 30_000 : false,
    refetchOnWindowFocus: live,
    refetchOnReconnect: live,
  })
}

export function useSocPosture(days = 7, live = true) {
  return useQuery<SocPosture>({
    queryKey: ['metrics', 'soc-posture', days],
    queryFn: () => api.get('/api/metrics/soc/posture', { params: { days } }).then(r => r.data),
    refetchInterval: live ? 30_000 : false,
    refetchOnWindowFocus: live,
    refetchOnReconnect: live,
  })
}

export function useMttrTrend(days = 30) {
  return useQuery<{ period_days: number; points: MttrPoint[] }>({
    queryKey: ['metrics', 'mttr-trend', days],
    queryFn: () => api.get('/api/metrics/soc/mttr-trend', { params: { days } }).then(r => r.data),
    refetchInterval: 60_000,
  })
}
