import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'

export interface NodeTypeMeta {
  node_type: string
  label: string
  category: string
  config_schema: { type?: string; required?: string[]; properties?: Record<string, JsonSchemaField> }
  handles: string[]
  is_destructive: boolean
}

export interface JsonSchemaField {
  type?: string
  enum?: string[]
  minimum?: number
  items?: { enum?: string[]; type?: string }
}

export interface WorkflowNode {
  id: string
  node_type: string
  name: string
  config: Record<string, unknown>
  pos_x: number
  pos_y: number
}

export interface WorkflowEdge {
  id?: string
  source_node_id: string
  source_handle: string
  target_node_id: string
}

export interface WorkflowSummary {
  id: string
  name: string
  description: string | null
  is_enabled: boolean
}

export interface WorkflowDetail extends WorkflowSummary {
  nodes: WorkflowNode[]
  edges: WorkflowEdge[]
}

export interface WorkflowSavePayload {
  name: string
  description?: string | null
  is_enabled: boolean
  nodes: Array<Omit<WorkflowNode, 'id'> & { id?: string }>
  edges: Array<Omit<WorkflowEdge, 'id'>>
}

/** The node catalogue is a deployment-level constant — it only changes when the
 *  server ships new node types, so it never needs refetching mid-session. */
export function useNodeTypes() {
  return useQuery<NodeTypeMeta[]>({
    queryKey: ['soar', 'node-types'],
    queryFn: () => api.get('/api/soar/node-types').then((r) => r.data),
    staleTime: Infinity,
  })
}

export function useWorkflows() {
  return useQuery<WorkflowSummary[]>({
    queryKey: ['soar', 'workflows'],
    queryFn: () => api.get('/api/soar/workflows').then((r) => r.data),
  })
}

export function useWorkflow(id: string | undefined) {
  return useQuery<WorkflowDetail>({
    queryKey: ['soar', 'workflow', id],
    queryFn: () => api.get(`/api/soar/workflows/${id}`).then((r) => r.data),
    enabled: Boolean(id),
  })
}

export function useCreateWorkflow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: WorkflowSavePayload) =>
      api.post('/api/soar/workflows', body).then((r) => r.data as WorkflowDetail),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar', 'workflows'] }),
  })
}

export function useSaveWorkflow(id: string | undefined) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: WorkflowSavePayload) =>
      api.put(`/api/soar/workflows/${id}`, body).then((r) => r.data as WorkflowDetail),
    onSuccess: (data) => {
      qc.setQueryData(['soar', 'workflow', id], data)
      qc.invalidateQueries({ queryKey: ['soar', 'workflows'] })
    },
  })
}

export function useDeleteWorkflow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/soar/workflows/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar', 'workflows'] }),
  })
}

/** The server returns a 422 with `detail` for every authoring mistake — an
 *  unknown node type, a cycle, a reconverging graph, a duplicate name. Surface
 *  that text verbatim: it is the only place the author learns what is wrong. */
export function saveErrorMessage(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  return 'Could not save the workflow.'
}
