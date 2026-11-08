import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface WebBlock {
  id: string
  domain: string
  group_id: string
  source: 'manual' | 'alert' | 'urlhaus' | 'phishtank'
  status: 'active' | 'removed' | 'suppressed'
  reason: string
  sample_url: string | null
  alert_id: string | null
  created_at: string | null
  expires_at: string | null
}

export interface AllowRule {
  id: string
  group_id: string
  domain: string
  include_subdomains: boolean
  builtin: boolean
  enabled: boolean
}

export interface WebPolicy {
  group_id: string
  enabled: boolean
  feed_enabled: boolean
  alert_enabled: boolean
  alert_block_days: number
  max_entries: number
  page_html: string
  contact: string
  custom_page: boolean
}

export interface AgentWebHealth {
  enabled: boolean
  entries: number
  version: string
  group: string
  ca_installed: boolean
  ca_fingerprint: string
  page_server: string
  hosts_tampered: boolean
  last_error: string
}

export interface AgentHealthRow {
  agent_id: string
  hostname: string
  group_id: string
  online: boolean
  health: AgentWebHealth | null
  health_at: string | null
}

export interface BlockFilter { q: string; source: string; status: string; offset: number }
export const BLOCK_PAGE = 50
const KEY = ['web-protection']

export function apiError(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(d => (d as { msg?: string }).msg ?? String(d)).join('; ')
  return fallback
}

export function useWebBlocks(f: BlockFilter) {
  return useQuery<{ total: number; items: WebBlock[] }>({
    queryKey: [...KEY, 'blocks', f],
    queryFn: () => api.get('/api/web-blocks', {
      params: { q: f.q || undefined, source: f.source || undefined, status: f.status, limit: BLOCK_PAGE, offset: f.offset },
    }).then(r => r.data),
    placeholderData: keepPreviousData,
  })
}

export function useBlockWeb() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { value: string; reason?: string; expires_at?: string | null; group_id?: string }) =>
      api.post('/api/web-blocks', body).then(r => r.data as WebBlock),
    onSuccess: () => { qc.invalidateQueries({ queryKey: KEY }); qc.invalidateQueries({ queryKey: ['iocs'] }) },
  })
}

export function useUnblockWeb() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/web-blocks/${id}`).then(r => r.data as { status: string }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: KEY }); qc.invalidateQueries({ queryKey: ['iocs'] }) },
  })
}

export function useAllowlist() {
  return useQuery<{ items: AllowRule[] }>({
    queryKey: [...KEY, 'allowlist'],
    queryFn: () => api.get('/api/web-allowlist').then(r => r.data),
  })
}

export function useAddAllowRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { domain: string; include_subdomains: boolean; group_id?: string }) =>
      api.post('/api/web-allowlist', body).then(r => r.data as AllowRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useUpdateAllowRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...body }: { id: string; enabled?: boolean; include_subdomains?: boolean }) =>
      api.patch(`/api/web-allowlist/${id}`, body).then(r => r.data as AllowRule),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useDeleteAllowRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/web-allowlist/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useWebPolicy(group: string) {
  return useQuery<WebPolicy>({
    queryKey: [...KEY, 'policy', group],
    queryFn: () => api.get(`/api/web-block-policies/${encodeURIComponent(group)}`).then(r => r.data),
    enabled: !!group,
  })
}

export function useSaveWebPolicy(group: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: Omit<WebPolicy, 'group_id' | 'custom_page' | 'page_html'> & { page_html: string | null }) =>
      api.put(`/api/web-block-policies/${encodeURIComponent(group)}`, body).then(r => r.data as WebPolicy),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function usePreviewPage(group: string) {
  return useMutation({
    mutationFn: (page_html: string | null) =>
      api.post(`/api/web-block-policies/${encodeURIComponent(group)}/preview`, { page_html })
        .then(r => (r.data as { html: string }).html),
  })
}

export function useAgentWebHealth() {
  return useQuery<{ items: AgentHealthRow[] }>({
    queryKey: [...KEY, 'agents'],
    queryFn: () => api.get('/api/web-blocks/agents').then(r => r.data),
    refetchInterval: 30_000,
  })
}

export interface FeedStatus {
  name: 'urlhaus' | 'phishtank'
  enabled_key_present: boolean
  status: string
  last_success: string | null
  last_attempt: string | null
  entries: number | null
  suppressed: number | null
  removed: number | null
  error: string
}

export function useWebFeeds() {
  return useQuery<{ feeds: FeedStatus[] }>({
    queryKey: [...KEY, 'feeds'],
    queryFn: () => api.get('/api/web-blocks/feeds').then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useSyncFeed() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => api.post(`/api/web-blocks/feeds/${name}/sync`).then(r => r.data as { status: string }),
    onSuccess: () => qc.invalidateQueries({ queryKey: [...KEY, 'feeds'] }),
  })
}
