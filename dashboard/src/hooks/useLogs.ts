import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, RawLog } from '@/types'

export function useLogs(pageSize = 25, after: string | null, search?: string) {
  return useQuery<PaginatedResponse<RawLog>>({
    queryKey: ['logs', pageSize, after, search],
    queryFn: () => api.get('/api/logs', { params: { page_size: pageSize, after: after || undefined, search } }).then(r => r.data),
    refetchInterval: 15_000,
    placeholderData: (prev) => prev,
  })
}
