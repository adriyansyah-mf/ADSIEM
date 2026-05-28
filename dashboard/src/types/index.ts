export interface User {
  id: string
  username: string
  email: string
  role: string
  group_id: string
  is_active: boolean
  created_at: string
}

export interface AgentPackage {
  filename: string
  type: 'deb' | 'rpm'
  size_bytes: number
}

export interface Agent {
  id: string
  name: string
  hostname: string
  group_id: string
  version: string | null
  status: 'online' | 'offline'
  is_isolated: boolean
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

export interface InstalledPackage {
  name: string
  version: string
  source: string
}

export interface PackageVuln {
  id: string
  summary: string
  severity: string
}

export interface VulnerablePackage {
  package: InstalledPackage
  vulns: PackageVuln[]
  vuln_count: number
}

export interface HygieneVulnReport {
  agent_id: string
  package_count: number
  vulnerable_count: number
  vulnerable: VulnerablePackage[]
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
  packages: InstalledPackage[]
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
  entity_type: 'user' | 'ip' | 'host'
  entity_value: string
  group_id: string
  risk_score: number
  anomaly_count: number
  last_anomaly_at: string | null
  last_seen_at: string | null
  updated_at: string
  feature_profile: Record<string, { mean: number; std: number }>
}

export interface HashTiHit {
  hash: string
  ioc_type: string
  score: number
  bullets: string[]
  cached_at: string
}

export interface DomainTiHit {
  domain: string
  score: number
  bullets: string[]
  cached_at: string
}

export interface UrlTiHit {
  url: string
  score: number
  bullets: string[]
  cached_at: string
}

export interface IpTiHit {
  ip: string
  score: number
  bullets: string[]
  cached_at: string
}

export interface PowershellHit {
  command: string
  decoded: string | null
  score: number
  flags: string[]
  secondary_iocs: string[]
}

export interface CommandHit {
  command: string
  score: number
  flags: string[]
  secondary_iocs: string[]
}

export interface UebaAnomaly {
  id: string
  entity_type: string
  entity_value: string
  anomaly_score: number
  risk_score: number
  features: Record<string, number>
  alert_id: string | null
  mitre_techniques: Array<{ id: string; name: string }>
  ai_narrative: string | null
  ai_action: string | null
  case_id: string | null
  hash_ti_hits: HashTiHit[]
  domain_ti_hits: DomainTiHit[]
  url_ti_hits: UrlTiHit[]
  ip_ti_hits: IpTiHit[]
  powershell_hits: PowershellHit[]
  command_hits: CommandHit[]
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
  host_snapshot_count: number
}

export interface UebaRiskPoint {
  snapshot_hour: string
  risk_score: number
}

export interface ThreatHunt {
  id: string
  ioc_type: 'ip' | 'hostname' | 'user' | 'hash'
  ioc_value: string
  status: 'pending' | 'running' | 'done' | 'failed'
  group_id: string
  alert_count: number
  event_count: number
  fim_count: number
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'unknown' | null
  timeline: Array<{
    time: string; type: 'alert' | 'event'
    severity?: string; title?: string
    category?: string; action?: string
    source_ip?: string; hostname?: string; user?: string
    id: string
  }> | null
  analysis: string | null
  related_alert_ids: string[] | null
  created_at: string
  completed_at: string | null
}

export interface FimWatchPath {
  id: string
  path: string
  is_enabled: boolean
  created_at: string
}

export interface FimEvent {
  id: string
  agent_id: string
  group_id: string
  path: string
  event_type: 'CREATE' | 'MODIFY' | 'DELETE' | 'RENAME'
  sha256: string | null
  size_bytes: number | null
  detected_at: string
}

export interface AgentTask {
  id: string
  agent_id: string | null
  fleet_hunt_id: string | null
  task_type: string
  params: Record<string, unknown>
  status: 'pending' | 'dispatched' | 'running' | 'done' | 'failed'
  result: unknown | null
  error: string | null
  created_at: string
  completed_at: string | null
}

export interface FleetHunt {
  id: string
  name: string
  description: string | null
  task_type: string
  params: Record<string, unknown>
  status: string
  total_agents: number
  completed_agents: number
  created_at: string
}

export interface Artifact {
  id: string
  name: string
  description: string | null
  task_type: string
  default_params: Record<string, unknown>
  is_enabled: boolean
  created_at: string
}

export interface YaraRule {
  id: string
  name: string
  description: string | null
  content: string
  is_enabled: boolean
  created_at: string
}
