import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { Flow, FlowArtifact, FlowDetail, FlowLog, FlowResults } from '@/types'

const ACTIVE = new Set(['scheduled', 'running'])

function apiError(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export function useFlowArtifacts() {
  return useQuery<FlowArtifact[]>({
    queryKey: ['flow-artifacts'],
    queryFn: () => api.get('/api/flow-artifacts').then(r => r.data),
  })
}

export function useSaveFlowArtifact() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ name, content }: { name?: string; content: string }) =>
      (name
        ? api.put(`/api/flow-artifacts/${encodeURIComponent(name)}`, { content })
        : api.post('/api/flow-artifacts', { content })
      ).then(r => r.data as FlowArtifact),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ['flow-artifacts'] })
      emitToast(`Artifact ${a.name} saved`, 'success')
    },
    onError: (e) => emitToast(apiError(e, 'Failed to save artifact'), 'error'),
  })
}

export function useDeleteFlowArtifact() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => api.delete(`/api/flow-artifacts/${encodeURIComponent(name)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['flow-artifacts'] }),
    onError: (e) => emitToast(apiError(e, 'Failed to delete artifact'), 'error'),
  })
}

export function useFlows(agentId?: string) {
  return useQuery<Flow[]>({
    queryKey: ['flows', agentId],
    queryFn: () => api.get('/api/flows', { params: { agent_id: agentId || undefined, limit: 100 } }).then(r => r.data),
    refetchInterval: q => (q.state.data ?? []).some(f => ACTIVE.has(f.status)) ? 2000 : 10000,
  })
}

export function useFlow(id: string | null) {
  return useQuery<FlowDetail>({
    queryKey: ['flow', id],
    queryFn: () => api.get(`/api/flows/${id}`).then(r => r.data),
    enabled: !!id,
    refetchInterval: q => q.state.data && ACTIVE.has(q.state.data.status) ? 2000 : false,
  })
}

export function useFlowResults(id: string | null, source: string | undefined, offset: number, active: boolean) {
  return useQuery<FlowResults>({
    queryKey: ['flow-results', id, source, offset],
    queryFn: () => api.get(`/api/flows/${id}/results`, { params: { source, offset, limit: 500 } }).then(r => r.data),
    enabled: !!id && !!source,
    refetchInterval: active ? 2000 : false,
  })
}

export function useFlowLogs(id: string | null, active: boolean) {
  return useQuery<FlowLog[]>({
    queryKey: ['flow-logs', id],
    queryFn: () => api.get(`/api/flows/${id}/logs`).then(r => r.data),
    enabled: !!id,
    refetchInterval: active ? 2000 : false,
  })
}

export function useCreateFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { agent_id: string; artifact: string; params: Record<string, unknown>; timeout?: number; max_rows?: number }) =>
      api.post('/api/flows', data).then(r => r.data as Flow),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['flows'] }),
    onError: (e) => emitToast(apiError(e, 'Failed to start collection'), 'error'),
  })
}

export function useCancelFlow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/api/flows/${id}/cancel`).then(r => r.data as Flow),
    onSuccess: (f) => {
      qc.invalidateQueries({ queryKey: ['flows'] })
      qc.invalidateQueries({ queryKey: ['flow', f.id] })
    },
    onError: (e) => emitToast(apiError(e, 'Failed to cancel'), 'error'),
  })
}

export async function downloadFlowResults(id: string, source: string, format: 'json' | 'csv') {
  const r = await api.get(`/api/flows/${id}/results/download`, { params: { source, format }, responseType: 'blob' })
  const disposition = String(r.headers['content-disposition'] ?? '')
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? `${source}.${format}`
  const url = URL.createObjectURL(r.data as Blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  URL.revokeObjectURL(url)
}
