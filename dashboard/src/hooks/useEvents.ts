import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Event, PaginatedResponse } from '@/types'

export function useEvents(page = 1, pageSize = 25, source_ip?: string) {
  return useQuery<PaginatedResponse<Event>>({
    queryKey: ['events', page, pageSize, source_ip],
    queryFn: () => api.get('/api/events', { params: { page, page_size: pageSize, source_ip } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}
