// SOAR workflow types — mirror worker/worker/soar/graph.py and server-api/app/api/routes/soar.py

export type NodeType =
  | 'trigger' | 'if' | 'enrich' | 'ai_decide' | 'approval'
  | 'response' | 'case' | 'notify' | 'http'

export type Params = Record<string, unknown>

export interface Condition {
  field: string
  operator: string
  value?: unknown
}

export interface WfNode {
  id: string
  type: NodeType
  label: string
  position: [number, number]
  params: Params
  retry: number
  continue_on_error: boolean
}

export interface WfEdge {
  from: string
  output: string
  to: string
}

export interface Graph {
  nodes: WfNode[]
  edges: WfEdge[]
}

export interface Playbook {
  id: string
  name: string
  description: string | null
  trigger_event: string
  is_enabled: boolean
  group_id: string
  legacy: boolean
  graph: Graph
  created_at: string | null
  updated_at: string | null
}

export interface Catalog {
  node_types: Record<NodeType, { outputs: string[]; label: string }>
  events: string[]
  operators: string[]
  response_operations: string[]
  case_operations: string[]
  alert_statuses: string[]
  http_methods: string[]
  body_types: string[]
  notify_channels: string[]
  trigger_fields: string[]
}

export type RunStatus = 'queued' | 'running' | 'waiting' | 'resume' | 'success' | 'failed' | 'cancelled'

export interface RunStep {
  id: string
  node_id: string
  node_type: NodeType
  status: 'success' | 'error' | 'waiting'
  output_name: string | null
  input: unknown
  output: unknown
  error: string | null
  attempts: number
  duration_ms: number | null
  started_at: string | null
}

export interface Run {
  id: string
  playbook_id: string
  status: RunStatus
  trigger_event: string
  alert_id: string | null
  waiting_node: string | null
  wait_until: string | null
  error: string | null
  created_at: string | null
  finished_at: string | null
  approval?: { message?: string; timeout_minutes?: number } | null
}

export interface RunDetail extends Run {
  graph: Graph
  trigger: Record<string, unknown>
  steps: RunStep[]
}

export interface CurlParseResult {
  params: Params
  ignored: string[]
}
