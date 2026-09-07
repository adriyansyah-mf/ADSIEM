import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { PaginatedResponse, Rule } from '@/types'

export function useRules(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Rule>>({
    queryKey: ['rules', page, pageSize],
    queryFn: () => api.get('/api/rules', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}

export function useCreateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Rule>) => api.post('/api/rules', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      emitToast('Rule created', 'success')
    },
    onError: () => emitToast('Failed to create rule', 'error'),
  })
}

export function useUpdateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Rule> }) =>
      api.put(`/api/rules/${id}`, data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      emitToast('Rule saved', 'success')
    },
    onError: () => emitToast('Failed to save rule', 'error'),
  })
}

export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/rules/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      emitToast('Rule deleted', 'success')
    },
    onError: () => emitToast('Failed to delete rule', 'error'),
  })
}

export function useTestRule() {
  return useMutation({
    mutationFn: (data: { content: string; sample_event: Record<string, unknown> }) =>
      api.post('/api/rules/test', data).then(r => r.data),
    onError: () => emitToast('Rule test failed', 'error'),
  })
}

export function useImportRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (content: string) => api.post('/api/rules/import', { content }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useImportRulesFromRepository() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (url: string) => api.post('/api/rules/import/repository', { url }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useExportRule() {
  return useMutation({
    mutationFn: async (id: string) => {
      const response = await api.get(`/api/rules/${id}/export`, { responseType: 'blob' })
      const url = URL.createObjectURL(response.data)
      const link = document.createElement('a')
      link.href = url
      link.download = `sigma-rule-${id}.yml`
      link.click()
      URL.revokeObjectURL(url)
    },
  })
}

export function useApproveRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post(`/api/rules/${id}/approve`).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}

export function useRuleQuality() {
  return useMutation({
    mutationFn: (id: string) => api.get(`/api/rules/${id}/quality`).then(r => r.data as { score: number; recommendation: string }),
    onSuccess: result => emitToast(`Rule quality: ${result.score}/100`, result.score >= 80 ? 'success' : 'error'),
  })
}

export function useRollbackRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, version }: { id: string; version: number }) => api.post(`/api/rules/${id}/rollback/${version}`).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      emitToast('Rule rolled back as a new version', 'success')
    },
  })
}

export function useRuleRevisions(id: string | null) {
  return useQuery<Array<{ version: number; content: string; created_at: string }> >({
    queryKey: ['rule-revisions', id],
    queryFn: () => api.get(`/api/rules/${id}/revisions`).then(r => r.data),
    enabled: Boolean(id),
  })
}

export function useRuleDiff() {
  return useMutation({
    mutationFn: ({ id, fromVersion, toVersion }: { id: string; fromVersion: number; toVersion: number }) =>
      api.get(`/api/rules/${id}/diff`, { params: { from_version: fromVersion, to_version: toVersion } }).then(r => r.data as { diff: string }),
  })
}
