// Groups alerts into "attacks": two alerts belong together when they share a
// host, user, file hash or IP within WINDOW_MS of each other (transitively).
// Pure and view-only: no alert changes status because it was grouped.
import type { Alert } from '@/types'

export const WINDOW_MS = 6 * 3_600_000
const SEVERITY_RANK: Readonly<Record<Alert['severity'], number>> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

type EntityKind = 'host' | 'user' | 'hash' | 'ip'
const LINK_LABEL: Readonly<Record<EntityKind, string>> = { host: 'same host', user: 'same user', hash: 'same SHA-256', ip: 'same IP' }
const USER_FIELDS = ['user.name', 'user.target', 'winlog.event_data.TargetUserName', 'TargetUserName', 'SubjectUserName', 'User', 'srcuser', 'dstuser']
const HASH_FIELDS = ['file.hash.sha256', 'hash.sha256', 'sha256', 'SHA256', 'Hashes', 'process.hash.sha256']
const IGNORED_USERS = new Set(['system', 'local service', 'network service', '-', 'n/a', 'root'])

export interface AttackMember { readonly alert: Alert; readonly link: string }
export interface Attack {
  readonly id: string
  readonly title: string
  readonly members: readonly AttackMember[]
  readonly top: Alert['severity']
  readonly hosts: readonly string[]
  readonly users: readonly string[]
  readonly tactics: readonly string[]
  readonly start: number
  readonly end: number
  readonly owners: readonly (string | null)[]
}

function text(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined
  const s = String(value).trim()
  return s ? s : undefined
}

function sha256Of(value: string): string | undefined {
  const match = /(?:SHA256=)?([a-fA-F0-9]{64})/.exec(value)
  return match ? match[1].toLowerCase() : undefined
}

/** The host, user, hash and IP an alert names, as "kind:value" keys. */
export function entitiesOf(alert: Alert): readonly [EntityKind, string][] {
  const out: [EntityKind, string][] = []
  if (alert.hostname) out.push(['host', alert.hostname.toLowerCase()])
  if (alert.source_ip) out.push(['ip', alert.source_ip])
  const fields = alert.context?.matched_fields ?? {}
  for (const name of USER_FIELDS) {
    const user = text(fields[name])
    if (user && !IGNORED_USERS.has(user.toLowerCase()) && !user.endsWith('$')) { out.push(['user', user.toLowerCase()]); break }
  }
  for (const name of HASH_FIELDS) {
    const raw = text(fields[name])
    const hash = raw && sha256Of(raw)
    if (hash) { out.push(['hash', hash]); break }
  }
  return out
}

function userOf(alert: Alert): string | undefined {
  const fields = alert.context?.matched_fields ?? {}
  for (const name of USER_FIELDS) {
    const user = text(fields[name])
    if (user && !IGNORED_USERS.has(user.toLowerCase()) && !user.endsWith('$')) return user
  }
  return undefined
}

export function groupAttacks(alerts: readonly Alert[]): { readonly attacks: readonly Attack[]; readonly ungrouped: readonly Alert[] } {
  const sorted = [...alerts].sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at))
  const parent = sorted.map((_, i) => i)
  const find = (i: number): number => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i] } return i }
  const linkedBy = new Map<number, EntityKind>()

  // Per entity, chain alerts that follow each other within the window.
  const byEntity = new Map<string, number[]>()
  sorted.forEach((alert, i) => {
    for (const [kind, value] of entitiesOf(alert)) {
      const key = `${kind}:${value}`
      byEntity.set(key, [...(byEntity.get(key) ?? []), i])
    }
  })
  for (const [key, indexes] of byEntity) {
    const kind = key.slice(0, key.indexOf(':')) as EntityKind
    for (let n = 1; n < indexes.length; n++) {
      const prev = indexes[n - 1], cur = indexes[n]
      if (Date.parse(sorted[cur].created_at) - Date.parse(sorted[prev].created_at) > WINDOW_MS) continue
      const a = find(prev), b = find(cur)
      if (!linkedBy.has(cur)) linkedBy.set(cur, kind)
      if (a !== b) parent[Math.max(a, b)] = Math.min(a, b)
    }
  }

  const sets = new Map<number, number[]>()
  sorted.forEach((_, i) => { const root = find(i); sets.set(root, [...(sets.get(root) ?? []), i]) })
  const attacks: Attack[] = []
  const ungrouped: Alert[] = []
  for (const indexes of sets.values()) {
    if (indexes.length < 2) { ungrouped.push(sorted[indexes[0]]); continue }
    const members = indexes.map((i, n) => ({ alert: sorted[i], link: n === 0 ? 'first alert' : LINK_LABEL[linkedBy.get(i) ?? 'host'] }))
    const items = members.map(m => m.alert)
    const lead = items.reduce((best, a) => SEVERITY_RANK[a.severity] > SEVERITY_RANK[best.severity] ? a : best, items[0])
    const hosts = [...new Set(items.map(a => a.hostname).filter((h): h is string => Boolean(h)))]
    const tactics = [...new Set(items.map(a => a.kill_chain_stage).filter((t): t is string => Boolean(t)))]
    const where = hosts.length ? ` on ${hosts[0]}${hosts.length > 1 ? ` and ${hosts.length - 1} more host${hosts.length > 2 ? 's' : ''}` : ''}` : ''
    attacks.push({
      id: `ATK-${items[0].id.replace(/-/g, '').slice(0, 4).toUpperCase()}`,
      title: `${lead.title}${where}`,
      members,
      top: lead.severity,
      hosts,
      users: [...new Set(items.map(userOf).filter((u): u is string => Boolean(u)))],
      tactics,
      start: Date.parse(items[0].created_at),
      end: Date.parse(items[items.length - 1].created_at),
      owners: [...new Set(items.map(a => a.assignee_id))],
    })
  }
  attacks.sort((a, b) => SEVERITY_RANK[b.top] - SEVERITY_RANK[a.top] || b.end - a.end)
  ungrouped.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))
  return { attacks, ungrouped }
}

/** Highest-severity, earliest alert first: the case's primary alert. */
export function primaryAlert(attack: Attack): Alert {
  return attack.members.map(m => m.alert)
    .reduce((best, a) => SEVERITY_RANK[a.severity] > SEVERITY_RANK[best.severity] ? a : best)
}
