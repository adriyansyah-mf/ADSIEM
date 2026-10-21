import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Event, PaginatedResponse, RawLog } from '@/types'

export function useTelemetryRecords<T extends RawLog | Event>(
  kind: 'logs' | 'events', pageSize: number, after: string | null, search?: string, filterTree?: string,
) {
  return useQuery<PaginatedResponse<T>>({
    queryKey: [kind, pageSize, after, search, filterTree],
    queryFn: ({ signal }) => api.get(`/api/${kind}`, {
      signal, params: { page_size: pageSize, after: after || undefined, search, filter_tree: filterTree },
    }).then(response => response.data),
    refetchInterval: 15_000,
    placeholderData: previous => previous,
  })
}
