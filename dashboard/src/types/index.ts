export interface User {
  id: string
  username: string
  email: string
  role: string
  group_id: string
  is_active: boolean
  created_at: string
}

export interface Agent {
  id: string
  name: string
  hostname: string
  group_id: string
  version: string | null
  status: 'online' | 'offline'
  last_seen_at: string | null
  enrolled_at: string
  log_sources: LogSource[]
}

export interface LogSource {
  id: string
  path: string
  log_type: string
  is_enabled: boolean
}

export interface RawLog {
  id: string
  agent_id: string | null
  log_type: string | null
  raw_message: string
  received_at: string
}

export interface Event {
  id: string
  agent_id: string | null
  group_id: string
  decoded_fields: Record<string, unknown>
  event_category: string | null
  event_action: string | null
  source_ip: string | null
  user_name: string | null
  created_at: string
}

export interface Alert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'new' | 'in_progress' | 'resolved' | 'false_positive'
  rule_id: string | null
  event_id: string | null
  agent_id: string | null
  group_id: string
  source_ip: string | null
  hostname: string | null
  assignee_id: string | null
  created_at: string
  updated_at: string
  notes: AlertNote[]
}

export interface AlertNote {
  id: string
  author_id: string | null
  content: string
  created_at: string
}

export interface Rule {
  id: string
  title: string
  description: string | null
  content: string
  level: string
  tags: string[]
  mitre_tags: string[]
  version: number
  is_enabled: boolean
  group_id: string | null
  created_at: string
  updated_at: string
}

export interface Decoder {
  id: string
  name: string
  log_type: string
  content: string
  priority: number
  is_enabled: boolean
  created_at: string
  updated_at: string
}

export interface Webhook {
  id: string
  name: string
  url: string
  is_enabled: boolean
  group_id: string | null
  created_at: string
}

export interface CaseNote {
  id: string
  case_id: string
  author_id: string | null
  content: string
  is_ai_generated: boolean
  created_at: string
}

export interface Case {
  id: string
  title: string
  description: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'open' | 'in_review' | 'escalated' | 'resolved' | 'closed'
  alert_id: string | null
  assignee_id: string | null
  ai_reasoning: string | null
  ioc_data: Record<string, unknown>
  search_intel: { results?: Array<{title: string; url: string; content: string}> }
  created_by_ai: boolean
  escalated_at: string | null
  group_id: string
  created_at: string
  updated_at: string
  notes: CaseNote[]
}

export interface PaginatedResponse<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export type Role = 'superadmin' | 'admin' | 'analyst' | 'viewer'

export const ROLE_HIERARCHY: Record<Role, number> = {
  superadmin: 4, admin: 3, analyst: 2, viewer: 1,
}
