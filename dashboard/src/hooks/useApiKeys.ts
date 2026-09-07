import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { ApiKey, ApiKeyCreated } from '@/types'

export function useApiKeys() {
  return useQuery<ApiKey[]>({
    queryKey: ['api-keys'],
    queryFn: () => api.get('/api/api-keys').then(r => r.data),
  })
}

export function useCreateApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; permissions: string[]; expires_at?: string | null }) =>
      api.post<ApiKeyCreated>('/api/api-keys', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
    onError: () => emitToast('Failed to create API key', 'error'),
  })
}

export function useRevokeApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/api-keys/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
      emitToast('API key revoked', 'success')
    },
    onError: () => emitToast('Failed to revoke API key', 'error'),
  })
}
