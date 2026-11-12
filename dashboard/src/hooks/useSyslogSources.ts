import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

export interface SyslogSource {
  id: string
  name: string
  group_id: string
  cidr: string
  log_type: string
  enabled: boolean
  message_count: number
  last_seen_at: string | null
  created_at: string | null
}

export interface UnknownSender {
  ip: string
  count: number
  last_seen: string | null
  proto: string | null
  sample: string
}

export type SyslogSourceInput = Pick<SyslogSource, 'name' | 'cidr' | 'log_type'> & { enabled?: boolean }

function errorDetail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d[0]?.msg) return String(d[0].msg).replace(/^Value error, /, '')
  return fallback
}

export function useSyslogSources() {
  return useQuery<SyslogSource[]>({
    queryKey: ['syslog-sources'],
    queryFn: () => api.get('/api/syslog-sources').then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useUnknownSyslogSenders(enabled: boolean) {
  return useQuery<UnknownSender[]>({
    queryKey: ['syslog-sources', 'unknown'],
    queryFn: () => api.get('/api/syslog-sources/unknown').then(r => r.data),
    enabled,
    refetchInterval: 30_000,
  })
}

export function useCreateSyslogSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: SyslogSourceInput) => api.post('/api/syslog-sources', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['syslog-sources'] })
      emitToast('Syslog device registered', 'success')
    },
    onError: (err) => emitToast(errorDetail(err, 'Failed to register syslog device'), 'error'),
  })
}

export function useUpdateSyslogSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<SyslogSourceInput> & { id: string }) =>
      api.put(`/api/syslog-sources/${id}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['syslog-sources'] }),
    onError: (err) => emitToast(errorDetail(err, 'Failed to update syslog device'), 'error'),
  })
}

export function useDeleteSyslogSource() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/syslog-sources/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['syslog-sources'] })
      emitToast('Syslog device removed', 'success')
    },
    onError: (err) => emitToast(errorDetail(err, 'Failed to remove syslog device'), 'error'),
  })
}
