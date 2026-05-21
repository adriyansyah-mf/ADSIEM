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

export interface HygieneIssue {
  severity: 'critical' | 'high' | 'medium' | 'low'
  category: string
  message: string
}

export interface DiskPartition {
  mount: string
  total_mb: number
  used_mb: number
  use_pct: number
}

export interface OpenPort {
  port: number
  proto: string
  state: string
}

export interface LocalUser {
  name: string
  shell: string
  uid: number
}

export interface HygieneSnapshot {
  id: string
  agent_id: string
  hostname: string | null
  group_id: string
  os_name: string | null
  os_version: string | null
  kernel: string | null
  arch: string | null
  uptime_seconds: number | null
  cpu_count: number | null
  mem_total_mb: number | null
  mem_used_mb: number | null
  disk_partitions: DiskPartition[]
  open_ports: OpenPort[]
  users: LocalUser[]
  hygiene_score: number
  issues: HygieneIssue[]
  collected_at: string
}

export interface Setting {
  key: string
  value: string
  is_secret: boolean
  description: string | null
  updated_at: string | null
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

export interface UebaEntityScore {
  entity_type: 'user' | 'ip'
  entity_value: string
  group_id: string
  risk_score: number
  anomaly_count: number
  last_anomaly_at: string | null
  last_seen_at: string | null
  updated_at: string
}

export interface UebaAnomaly {
  id: string
  entity_type: string
  entity_value: string
  anomaly_score: number
  risk_score: number
  features: Record<string, number>
  alert_id: string | null
  detected_at: string
}

export interface UebaEntityDetail {
  score: UebaEntityScore
  anomalies: UebaAnomaly[]
}

export interface UebaStatus {
  status: 'cold' | 'ready'
  trained_at: string | null
  user_snapshot_count: number
  ip_snapshot_count: number
}
