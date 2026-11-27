import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Event, PaginatedResponse, RawLog } from '@/types'

export interface TimeWindow {
  readonly since?: string
  readonly until?: string
}

export function useTelemetryRecords<T extends RawLog | Event>(
  kind: 'logs' | 'events', pageSize: number, after: string | null, search?: string, filterTree?: string,
  window: TimeWindow = {},
) {
  const { since, until } = window
  return useQuery<PaginatedResponse<T>>({
    queryKey: [kind, pageSize, after, search, filterTree, since, until],
    queryFn: ({ signal }) => api.get(`/api/${kind}`, {
      signal, params: { page_size: pageSize, after: after || undefined, search, filter_tree: filterTree, since, until },
    }).then(response => response.data),
    refetchInterval: 15_000,
    placeholderData: previous => previous,
  })
}

export interface TelemetryFacets {
  readonly total: number
  readonly took_ms: number
  readonly since: string
  readonly until: string
  readonly histogram: readonly { readonly t: string; readonly count: number }[]
  readonly facets: readonly { readonly field: string; readonly values: readonly { readonly value: string; readonly count: number }[] }[]
}

/** Histogram and top field values for the same query (server computes both in one aggregation). */
export function useTelemetryFacets(kind: 'logs' | 'events', search?: string, filterTree?: string, window: TimeWindow = {}) {
  const { since, until } = window
  return useQuery<TelemetryFacets>({
    queryKey: [kind, 'facets', search, filterTree, since, until],
    queryFn: ({ signal }) => api.get(`/api/${kind}/facets`, {
      signal, params: { search, filter_tree: filterTree, since, until },
    }).then(response => response.data),
    refetchInterval: 30_000,
    placeholderData: previous => previous,
  })
}
