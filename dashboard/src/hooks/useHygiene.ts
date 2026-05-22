import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { HygieneSnapshot, HygieneVulnReport } from '@/types'

export function useHygieneLatest() {
  return useQuery<HygieneSnapshot[]>({
    queryKey: ['hygiene', 'latest'],
    queryFn: () => api.get('/api/hygiene/latest').then(r => r.data),
    refetchInterval: 5 * 60_000,
  })
}

export function useAgentHygiene(agentId: string) {
  return useQuery<HygieneSnapshot[]>({
    queryKey: ['hygiene', agentId],
    queryFn: () => api.get(`/api/hygiene/${agentId}`).then(r => r.data),
    enabled: !!agentId,
  })
}

export function useAgentVulns(agentId: string, enabled: boolean) {
  return useQuery<HygieneVulnReport>({
    queryKey: ['hygiene', agentId, 'vulns'],
    queryFn: () => api.get(`/api/hygiene/${agentId}/vulns`).then(r => r.data),
    enabled: enabled && !!agentId,
    staleTime: 10 * 60_000,
  })
}
