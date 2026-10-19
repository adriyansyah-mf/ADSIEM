import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { PaginatedResponse, Rule, RuleTestResult, SigmaHQImportResult } from '@/types'

export interface RuleFilters {
  q?: string
  source?: string
  enabled?: boolean
  level?: string
}

function detail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

export function useRules(page = 1, pageSize = 25, filters: RuleFilters = {}) {
  return useQuery<PaginatedResponse<Rule>>({
    queryKey: ['rules', page, pageSize, filters],
    queryFn: () => api.get('/api/rules', {
      params: { page, page_size: pageSize, ...Object.fromEntries(
        Object.entries(filters).filter(([, v]) => v !== undefined && v !== '')) },
    }).then(r => r.data),
    placeholderData: keepPreviousData,
  })
}

export function useRuleStats() {
  return useQuery<Record<string, { enabled: number; disabled: number }>>({
    queryKey: ['rules', 'stats'],
    queryFn: () => api.get('/api/rules/stats').then(r => r.data),
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
    onError: (e) => emitToast(detail(e, 'Failed to create rule'), 'error'),
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
    onError: (e) => emitToast(detail(e, 'Failed to save rule'), 'error'),
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

export function useBulkRules() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { is_enabled: boolean; ids?: string[]; q?: string; source?: string; level?: string }) =>
      api.post('/api/rules/bulk', data).then(r => r.data as { updated: number }),
    onSuccess: (r, v) => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      emitToast(`${r.updated} rule(s) ${v.is_enabled ? 'enabled' : 'disabled'}`, 'success')
    },
    onError: (e) => emitToast(detail(e, 'Bulk update failed'), 'error'),
  })
}

export function useTestRule() {
  return useMutation({
    mutationFn: (data: { content: string; sample_event: Record<string, unknown> }) =>
      api.post('/api/rules/test', data).then(r => r.data as RuleTestResult),
    onError: () => emitToast('Rule test failed', 'error'),
  })
}

export function useImportSigmaHQ() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { ruleset: string; enable_levels: string[]; enable_statuses: string[] }) =>
      api.post('/api/rules/sigmahq/import', data, { timeout: 300_000 }).then(r => r.data as SigmaHQImportResult),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
    onError: (e) => emitToast(detail(e, 'SigmaHQ import failed'), 'error'),
  })
}

export function useUploadSigmaHQ() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ file, enable_levels, enable_statuses }: { file: File; enable_levels: string[]; enable_statuses: string[] }) => {
      const form = new FormData()
      form.append('file', file)
      form.append('enable_levels', enable_levels.join(','))
      form.append('enable_statuses', enable_statuses.join(','))
      return api.post('/api/rules/sigmahq/upload', form, {
        headers: { 'Content-Type': 'multipart/form-data' }, timeout: 300_000,
      }).then(r => r.data as SigmaHQImportResult)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
    onError: (e) => emitToast(detail(e, 'SigmaHQ upload failed'), 'error'),
  })
}
