import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { api } from '@/api/client'

export interface HuntScheduleInput {
  name: string
  ioc_type: string
  ioc_value: string
  interval_hours: number
}

export interface HuntSchedule extends HuntScheduleInput {
  id: string
  group_id: string
  is_enabled: boolean
  last_run_at: string | null
  created_at: string | null
}

export function huntError(error: unknown): string {
  if (isAxiosError<{ detail?: unknown }>(error) && typeof error.response?.data?.detail === 'string') return error.response.data.detail
  return 'Could not complete this request. Check your connection and permissions, then try again.'
}

export function useHuntSchedules() {
  return useQuery<HuntSchedule[]>({
    queryKey: ['hunt-schedules'],
    queryFn: ({ signal }) => api.get('/api/hunt-schedules', { signal }).then(response => response.data),
    refetchInterval: 30_000,
  })
}

export function useCreateHuntSchedule() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (body: HuntScheduleInput) => api.post('/api/hunt-schedules', body),
    onSuccess: () => client.invalidateQueries({ queryKey: ['hunt-schedules'] }),
  })
}

export function useHuntScheduleAction(action: 'toggle' | 'delete') {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => action === 'toggle' ? api.patch(`/api/hunt-schedules/${id}/toggle`)
      : api.delete(`/api/hunt-schedules/${id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ['hunt-schedules'] }),
  })
}
