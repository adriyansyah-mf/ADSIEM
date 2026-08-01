import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Event, PaginatedResponse } from '@/types'

export function useEvents(pageSize = 25, after: string | null, source_ip?: string) {
  return useQuery<PaginatedResponse<Event>>({
    queryKey: ['events', pageSize, after, source_ip],
    queryFn: () => api.get('/api/events', { params: { page_size: pageSize, after: after || undefined, source_ip } }).then(r => r.data),
    refetchInterval: 15_000,
    placeholderData: (prev) => prev,
  })
}
