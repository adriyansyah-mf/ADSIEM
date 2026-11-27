import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

export interface CaseTask {
  readonly id: string
  readonly case_id: string
  readonly title: string
  readonly done: boolean
  readonly assignee_id: string | null
  readonly due_at: string | null
  readonly created_by: string | null
  readonly created_at: string | null
  readonly completed_at: string | null
}

export interface CaseTaskChange {
  readonly title?: string
  readonly done?: boolean
  readonly assignee_id?: string
  readonly due_at?: string
  readonly clear_assignee?: boolean
  readonly clear_due?: boolean
}

const key = (caseId: string) => ['case-tasks', caseId] as const

export function useCaseTasks(caseId: string) {
  return useQuery<CaseTask[]>({
    queryKey: key(caseId),
    queryFn: () => api.get(`/api/cases/${caseId}/tasks`).then(r => r.data),
    enabled: Boolean(caseId),
  })
}

export function useCreateCaseTask(caseId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { title: string; assignee_id?: string; due_at?: string }) =>
      api.post(`/api/cases/${caseId}/tasks`, body).then(r => r.data as CaseTask),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: key(caseId) }) },
    onError: () => emitToast('Could not add the task', 'error'),
  })
}

export function useUpdateCaseTask(caseId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, change }: { id: string; change: CaseTaskChange }) =>
      api.put(`/api/cases/${caseId}/tasks/${id}`, change).then(r => r.data as CaseTask),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: key(caseId) }) },
    onError: () => emitToast('Could not update the task', 'error'),
  })
}

export function useDeleteCaseTask(caseId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/cases/${caseId}/tasks/${id}`),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: key(caseId) }) },
    onError: () => emitToast('Could not delete the task', 'error'),
  })
}
