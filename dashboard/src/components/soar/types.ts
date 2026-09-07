export interface Condition {
  id: string
  field: string
  operator: string
  value: string | string[] | null
}

export interface TriggerConditions {
  match: 'all' | 'any'
  conditions: Condition[]
}

export interface Action {
  id: string
  action_type: string
  order_index: number
  params: Record<string, string>
}

export interface Playbook {
  id: string
  name: string
  description: string | null
  trigger_conditions: TriggerConditions
  is_enabled: boolean
  group_id: string
  created_at: string
  actions: Action[]
}

export interface SoarStep {
  id: string
  action_type: string
  status: string
  is_destructive: boolean
  is_reversible: boolean
  idempotency_key: string
  output: Record<string, string> | null
}

export interface SoarExecution {
  id: string
  status: string
  trigger_type: string
  started_at: string
  steps: SoarStep[]
}

export const emptyTrigger = (): TriggerConditions => ({ match: 'all', conditions: [] })

export const generateId = (): string => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16)
  })
}

export const TRIGGER_FIELDS = ['severity', 'rule_title', 'source_ip', 'hostname', 'user_name', 'tags', 'mitre_tags']
export const OPERATORS = ['eq', 'neq', 'contains', 'in', 'not_null']
export const ACTION_TYPES = ['enrich_ioc', 'send_webhook', 'create_case', 'suppress_alert', 'add_note', 'isolate_agent', 'block_ip']
