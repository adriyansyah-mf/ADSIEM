import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
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

export function useBlockIp() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { agent_id: string; ip: string; duration_seconds?: number }) =>
      api.post('/api/tasks', {
        agent_id: data.agent_id,
        task_type: 'block_ip',
        params: { ip: data.ip, duration_seconds: data.duration_seconds ?? 3600 },
      }).then(r => r.data as AgentTask),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tasks'] })
      emitToast('Block IP task sent to agent', 'success')
    },
    onError: () => emitToast('Failed to send block IP task', 'error'),
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
