import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, RawLog } from '@/types'

export function useLogs(page = 1, pageSize = 25, search?: string) {
  return useQuery<PaginatedResponse<RawLog>>({
    queryKey: ['logs', page, pageSize, search],
    queryFn: () => api.get('/api/logs', { params: { page, page_size: pageSize, search } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}
