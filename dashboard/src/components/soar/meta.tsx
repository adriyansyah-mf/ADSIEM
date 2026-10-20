import {
  Brain, Briefcase, Globe, GitBranch, Hand, Megaphone, Search, ShieldAlert, Zap,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { Graph, NodeType, Params, WfNode } from '@/types/soar'

export interface NodeMeta {
  label: string
  color: string
  icon: LucideIcon
  outputs: string[]
  help: string
  defaults: () => Params
}

export const NODE_META: Record<NodeType, NodeMeta> = {
  trigger: {
    label: 'Trigger', color: '#00d4ff', icon: Zap, outputs: ['main'],
    help: 'When the workflow starts: on a new alert, after AI triage, or only when run by hand.',
    defaults: () => ({ event: 'alert.triaged', match: 'all', conditions: [] }),
  },
  if: {
    label: 'If', color: '#a78bfa', icon: GitBranch, outputs: ['true', 'false'],
    help: 'Branch on the alert or on any earlier node’s output.',
    defaults: () => ({ match: 'all', conditions: [{ field: 'trigger.severity', operator: 'eq', value: 'critical' }] }),
  },
  enrich: {
    label: 'Enrich (TI)', color: '#38bdf8', icon: Search, outputs: ['main', 'error'],
    help: 'Threat-intel lookup of an IP, domain or hash. Gives risk (0–1) and findings.',
    defaults: () => ({ indicator: '{{ trigger.source_ip }}', add_note: true }),
  },
  ai_decide: {
    label: 'AI Decide', color: '#f472b6', icon: Brain, outputs: ['yes', 'no', 'error'],
    help: 'Ask the AI a yes/no question about this alert and everything gathered so far.',
    defaults: () => ({ question: 'Is this activity malicious rather than an admin or scanner we know?', min_confidence: 0.7 }),
  },
  approval: {
    label: 'Approval', color: '#ffd700', icon: Hand, outputs: ['approved', 'rejected'],
    help: 'Pause until an analyst approves or rejects. Times out as rejected.',
    defaults: () => ({ message: 'Approve containment for {{ trigger.hostname }}?', timeout_minutes: 60 }),
  },
  response: {
    label: 'Response', color: '#ff2244', icon: ShieldAlert, outputs: ['main', 'error'],
    help: 'Act on the agent: isolate, block an IP, kill a process, quarantine a file.',
    defaults: () => ({ operation: 'block_ip', ip: '{{ trigger.source_ip }}', duration_seconds: 3600 }),
  },
  case: {
    label: 'Case & Alert', color: '#00ff88', icon: Briefcase, outputs: ['main', 'error'],
    help: 'Open a case, add a note, change the alert status, or suppress noise.',
    defaults: () => ({ operation: 'add_note', content: 'SOAR: {{ trigger.rule_title }}' }),
  },
  notify: {
    label: 'Notify', color: '#ff6b00', icon: Megaphone, outputs: ['main', 'error'],
    help: 'Send a message to a webhook, Discord or Slack.',
    defaults: () => ({ channel: 'discord', url: '', message: '[{{ trigger.severity }}] {{ trigger.rule_title }} on {{ trigger.hostname }}' }),
  },
  http: {
    label: 'HTTP Request', color: '#22d3ee', icon: Globe, outputs: ['main', 'error'],
    help: 'Call any API, curl-style. Later nodes read the response as {{ steps.<id>.body… }}.',
    defaults: () => ({ method: 'GET', url: 'https://', query: {}, headers: {}, body_type: 'none', body: null,
      timeout: 15, fail_on_status: true, extract: {} }),
  },
}

export const PALETTE: NodeType[] = ['if', 'enrich', 'ai_decide', 'approval', 'response', 'case', 'notify', 'http']

const str = (v: unknown) => (v === undefined || v === null ? '' : String(v))

/** One line under the node title so the canvas reads without opening each node. */
export function summary(node: Pick<WfNode, 'type' | 'params'>): string {
  const p = node.params
  switch (node.type) {
    case 'trigger': {
      const n = Array.isArray(p.conditions) ? p.conditions.length : 0
      return `${str(p.event)}${n ? ` · ${n} condition${n > 1 ? 's' : ''}` : ''}`
    }
    case 'if': {
      const c = Array.isArray(p.conditions) ? (p.conditions[0] as { field?: string; operator?: string; value?: unknown }) : undefined
      const more = Array.isArray(p.conditions) && p.conditions.length > 1 ? ` +${p.conditions.length - 1}` : ''
      return c ? `${str(c.field)} ${str(c.operator)} ${str(c.value)}${more}` : 'no conditions'
    }
    case 'enrich': return str(p.indicator)
    case 'ai_decide': return str(p.question)
    case 'approval': return `${str(p.timeout_minutes)} min · ${str(p.message)}`
    case 'response': return `${str(p.operation)}${p.ip ? ` ${str(p.ip)}` : ''}${p.path ? ` ${str(p.path)}` : ''}`
    case 'case': return str(p.operation)
    case 'notify': return `${str(p.channel)} ${str(p.url).replace(/^https?:\/\//, '').slice(0, 30)}`
    case 'http': return `${str(p.method)} ${str(p.url).replace(/^https?:\/\//, '')}`
  }
}

export function newNodeId(type: NodeType, graph: Graph): string {
  const taken = new Set(graph.nodes.map(n => n.id))
  for (let i = 1; ; i++) {
    const id = `${type}_${i}`
    if (!taken.has(id)) return id
  }
}

export function defaultGraph(): Graph {
  return {
    nodes: [{ id: 'trigger', type: 'trigger', label: 'Trigger', position: [0, 0], params: NODE_META.trigger.defaults(),
      retry: 0, continue_on_error: false }],
    edges: [],
  }
}

/** Ids of nodes that always run before nodeId — the only ones its templates may use. */
export function upstream(nodeId: string, graph: Graph): string[] {
  const parents = new Map<string, string[]>()
  graph.edges.forEach(e => parents.set(e.to, [...(parents.get(e.to) ?? []), e.from]))
  const seen = new Set<string>()
  const stack = [nodeId]
  while (stack.length) {
    for (const p of parents.get(stack.pop() as string) ?? []) {
      if (!seen.has(p)) { seen.add(p); stack.push(p) }
    }
  }
  return graph.nodes.filter(n => seen.has(n.id) && n.type !== 'trigger').map(n => n.id)
}

/** Paths a node's output exposes, for the "available data" helper. */
export const OUTPUT_PATHS: Record<NodeType, string[]> = {
  trigger: [],
  if: ['result'],
  enrich: ['risk', 'bullets', 'indicator'],
  ai_decide: ['answer', 'confidence', 'reason'],
  approval: ['decision', 'by_name', 'comment'],
  response: ['task_id', 'hostname', 'operation'],
  case: ['case_id', 'created'],
  notify: ['status'],
  http: ['status', 'body', 'data.<extract name>', 'headers', 'error'],
}
