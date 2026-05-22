import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { AgentTask, FleetHunt } from '@/types'

export function useTasks(agentId?: string, status?: string) {
  return useQuery<AgentTask[]>({
    queryKey: ['tasks', agentId, status],
    queryFn: () => api.get('/api/tasks', { params: { agent_id: agentId, status, limit: 100 } }).then(r => r.data),
    refetchInterval: 3000,
  })
}

export function useTask(id: string) {
  return useQuery<AgentTask>({
    queryKey: ['tasks', id],
    queryFn: () => api.get(`/api/tasks/${id}`).then(r => r.data),
    refetchInterval: q => {
      const status = q.state.data?.status
      return status === 'done' || status === 'failed' ? false : 2000
    },
  })
}

export function useCreateTask() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { agent_id: string; task_type: string; params?: Record<string, unknown> }) =>
      api.post('/api/tasks', data).then(r => r.data as AgentTask),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tasks'] }),
  })
}

export function useFleetHunts() {
  return useQuery<FleetHunt[]>({
    queryKey: ['fleet-hunts'],
    queryFn: () => api.get('/api/fleet-hunts').then(r => r.data),
    refetchInterval: 5000,
  })
}

export function useCreateFleetHunt() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; task_type: string; params?: Record<string, unknown>; agent_ids?: string[] }) =>
      api.post('/api/fleet-hunts', data).then(r => r.data as FleetHunt),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fleet-hunts'] }),
  })
}

export function useFleetHuntTasks(huntId: string) {
  return useQuery<AgentTask[]>({
    queryKey: ['fleet-hunts', huntId, 'tasks'],
    queryFn: () => api.get(`/api/fleet-hunts/${huntId}/tasks`).then(r => r.data),
    refetchInterval: 3000,
  })
}
