import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { Catalog, CurlParseResult, Graph, Playbook, Run, RunDetail } from '@/types/soar'

const ACTIVE: Run['status'][] = ['queued', 'running', 'resume']

/** The API's 422 for a bad workflow carries every problem in detail.errors. */
export function apiErrors(err: unknown): string[] {
  if (isAxiosError(err)) {
    const detail = err.response?.data?.detail
    if (detail && typeof detail === 'object' && Array.isArray(detail.errors)) return detail.errors.map(String)
    if (typeof detail === 'string') return [detail]
    if (err.response?.status === 403) return ['You need the agents:manage permission for this.']
  }
  return [err instanceof Error ? err.message : 'Request failed']
}

export function useSoarCatalog() {
  return useQuery<Catalog>({
    queryKey: ['soar', 'catalog'],
    queryFn: () => api.get('/api/soar/catalog').then(r => r.data),
    staleTime: Infinity,
  })
}

export function usePlaybooks() {
  return useQuery<Playbook[]>({
    queryKey: ['soar', 'playbooks'],
    queryFn: () => api.get('/api/soar/playbooks').then(r => r.data),
  })
}

export function usePlaybook(id: string | undefined) {
  return useQuery<Playbook>({
    queryKey: ['soar', 'playbook', id],
    queryFn: () => api.get(`/api/soar/playbooks/${id}`).then(r => r.data),
    enabled: !!id,
  })
}

export function useCreatePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { name: string; description?: string; graph: Graph }) =>
      api.post<Playbook>('/api/soar/playbooks', body).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar', 'playbooks'] }),
    onError: (e) => emitToast(apiErrors(e)[0], 'error'),
  })
}

export function useUpdatePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name?: string; description?: string | null; is_enabled?: boolean } }) =>
      api.patch(`/api/soar/playbooks/${id}`, data).then(r => r.data),
    onSuccess: (_d, v) => {
      qc.invalidateQueries({ queryKey: ['soar', 'playbooks'] })
      qc.invalidateQueries({ queryKey: ['soar', 'playbook', v.id] })
    },
    onError: (e) => emitToast(apiErrors(e)[0], 'error'),
  })
}

export function useDeletePlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/soar/playbooks/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['soar', 'playbooks'] })
      emitToast('Playbook deleted', 'success')
    },
    onError: (e) => emitToast(apiErrors(e)[0], 'error'),
  })
}

/** Errors are returned to the caller (the editor lists them), not toasted. */
export function useSaveGraph() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, graph }: { id: string; graph: Graph }) =>
      api.put<Playbook>(`/api/soar/playbooks/${id}/graph`, { graph }).then(r => r.data),
    onSuccess: (pb) => {
      qc.setQueryData(['soar', 'playbook', pb.id], pb)
      qc.invalidateQueries({ queryKey: ['soar', 'playbooks'] })
    },
  })
}

export function useValidateGraph() {
  return useMutation({
    mutationFn: (graph: Graph) =>
      api.post<{ ok: boolean; errors: string[] }>('/api/soar/validate', { graph }).then(r => r.data),
  })
}

export function useParseCurl() {
  return useMutation({
    mutationFn: (command: string) => api.post<CurlParseResult>('/api/soar/parse-curl', { command }).then(r => r.data),
  })
}

export function useRunPlaybook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, alert_id }: { id: string; alert_id?: string }) =>
      api.post<Run>(`/api/soar/playbooks/${id}/run`, alert_id ? { alert_id } : {}).then(r => r.data),
    onSuccess: (run) => qc.invalidateQueries({ queryKey: ['soar', 'runs', run.playbook_id] }),
    onError: (e) => emitToast(apiErrors(e)[0], 'error'),
  })
}

export function usePlaybookRuns(id: string | undefined) {
  return useQuery<Run[]>({
    queryKey: ['soar', 'runs', id],
    queryFn: () => api.get(`/api/soar/playbooks/${id}/runs`, { params: { limit: 30 } }).then(r => r.data),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data?.some(r => ACTIVE.includes(r.status)) ? 2000 : 15_000),
  })
}

export function useRun(runId: string | null) {
  return useQuery<RunDetail>({
    queryKey: ['soar', 'run', runId],
    queryFn: () => api.get(`/api/soar/runs/${runId}`).then(r => r.data),
    enabled: !!runId,
    refetchInterval: (q) => (q.state.data && !ACTIVE.includes(q.state.data.status) ? false : 1500),
  })
}

export function useWaitingRuns() {
  return useQuery<Run[]>({
    queryKey: ['soar', 'runs', 'waiting'],
    queryFn: () => api.get('/api/soar/runs', { params: { status: 'waiting', limit: 50 } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}

export function useDecideRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ runId, decision, comment }: { runId: string; decision: 'approved' | 'rejected'; comment?: string }) =>
      api.post(`/api/soar/runs/${runId}/decision`, { decision, comment }).then(r => r.data),
    onSuccess: (_d, v) => {
      qc.invalidateQueries({ queryKey: ['soar', 'runs'] })
      qc.invalidateQueries({ queryKey: ['soar', 'run', v.runId] })
      emitToast(v.decision === 'approved' ? 'Approved — the run continues' : 'Rejected', 'success')
    },
    onError: (e) => emitToast(apiErrors(e)[0], 'error'),
  })
}

export function useCancelRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (runId: string) => api.post(`/api/soar/runs/${runId}/cancel`).then(r => r.data),
    onSuccess: (_d, runId) => {
      qc.invalidateQueries({ queryKey: ['soar', 'runs'] })
      qc.invalidateQueries({ queryKey: ['soar', 'run', runId] })
    },
    onError: (e) => emitToast(apiErrors(e)[0], 'error'),
  })
}
