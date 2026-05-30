import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import type { PaginatedResponse, User } from '@/types'

export function useUsers(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<User>>({
    queryKey: ['users', page, pageSize],
    queryFn: () => api.get('/api/users', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { username: string; email: string; password: string; role_id: number; group_id: string }) =>
      api.post('/api/users', data).then(r => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      emitToast('User created', 'success')
    },
    onError: () => emitToast('Failed to create user', 'error'),
  })
}

export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/users/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      emitToast('User deleted', 'success')
    },
    onError: () => emitToast('Failed to delete user', 'error'),
  })
}
