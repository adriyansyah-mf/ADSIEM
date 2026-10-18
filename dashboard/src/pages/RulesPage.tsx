import { useState } from 'react'
import DataTable from '@/components/DataTable'
import YamlEditor from '@/components/YamlEditor'
import SeverityBadge from '@/components/SeverityBadge'
import {
  useRules, useRuleStats, useCreateRule, useUpdateRule, useDeleteRule, useTestRule, useBulkRules, type RuleFilters,
} from '@/hooks/useRules'
import SigmaHQImportModal from '@/components/SigmaHQImportModal'
import { Plus, Pencil, Trash2, Download, Search } from 'lucide-react'
import type { Rule, RuleTestResult } from '@/types'

const DEFAULT_RULE = `title: New Rule
id: rule-new
description: Detect suspicious activity
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
tags: []
`

const BRUTE_FORCE_EXAMPLE = `title: SSH Brute Force
id: rule-ssh-brute
description: Multiple failed SSH logins from the same IP
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
threshold:
  count: 5
  timewindow: 300
  group_by: source.ip
  cooldown: 600
level: high
tags:
  - attack.credential_access
  - attack.T1110
`

interface CorrelationCfg {
  count: number
  timewindow: number
  group_by: string
  cooldown: number
}

const DEFAULT_CORR: CorrelationCfg = { count: 5, timewindow: 300, group_by: 'source.ip', cooldown: 600 }

const COMMON_GROUP_BY = [
  { value: 'source.ip', label: 'Source IP' },
  { value: 'user.name', label: 'Username' },
  { value: 'hostname', label: 'Hostname' },
  { value: 'event.action', label: 'Event Action' },
]

function parseThreshold(content: string): CorrelationCfg | null {
  const lines = content.split('\n')
  const start = lines.findIndex(l => /^threshold:\s*$/.test(l))
  if (start === -1) return null
  const cfg = { ...DEFAULT_CORR }
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i]
    if (line.trim() === '') continue
    if (!/^\s/.test(line)) break
    const m = line.match(/^\s+(\w+):\s*(.+)$/)
    if (!m) continue
    if (m[1] === 'count') cfg.count = parseInt(m[2]) || 5
    if (m[1] === 'timewindow') cfg.timewindow = parseInt(m[2]) || 300
    if (m[1] === 'group_by') cfg.group_by = m[2].trim()
    if (m[1] === 'cooldown') cfg.cooldown = parseInt(m[2]) || 600
  }
  return cfg
}

function stripThreshold(content: string): string {
  const lines = content.split('\n')
  const start = lines.findIndex(l => /^threshold:/.test(l))
  if (start === -1) return content
  let end = start + 1
  while (end < lines.length && (/^\s/.test(lines[end]) || lines[end].trim() === '')) end++
  return [...lines.slice(0, start), ...lines.slice(end)].join('\n')
}

function injectThreshold(content: string, cfg: CorrelationCfg): string {
  const cleaned = stripThreshold(content)
  const block = `threshold:\n  count: ${cfg.count}\n  timewindow: ${cfg.timewindow}\n  group_by: ${cfg.group_by}\n  cooldown: ${cfg.cooldown}`
  return cleaned.trimEnd() + '\n' + block + '\n'
}

function CorrelationPanel({
  yamlContent,
  onYamlChange,
}: {
  yamlContent: string
  onYamlChange: (v: string) => void
}) {
  const existing = parseThreshold(yamlContent)
  const [enabled, setEnabled] = useState(existing !== null)
  const [cfg, setCfg] = useState<CorrelationCfg>(existing ?? DEFAULT_CORR)
  const [customGroupBy, setCustomGroupBy] = useState(
    COMMON_GROUP_BY.some(o => o.value === cfg.group_by) ? '' : cfg.group_by
  )

  const toggle = () => {
    if (!enabled) {
      const next = injectThreshold(yamlContent, cfg)
      onYamlChange(next)
      setEnabled(true)
    } else {
      onYamlChange(stripThreshold(yamlContent))
      setEnabled(false)
    }
  }

  const apply = (newCfg: CorrelationCfg) => {
    onYamlChange(injectThreshold(yamlContent, newCfg))
  }

  const update = (patch: Partial<CorrelationCfg>) => {
    const next = { ...cfg, ...patch }
    setCfg(next)
    if (enabled) apply(next)
  }

  const isCustom = !COMMON_GROUP_BY.some(o => o.value === cfg.group_by)

  return (
    <div style={{
      borderTop: '1px solid var(--border)',
      background: enabled ? 'rgba(0,212,255,0.03)' : 'transparent',
      padding: '10px 16px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span style={{
          fontFamily: 'Rajdhani, sans-serif',
          fontWeight: 700,
          fontSize: '10px',
          letterSpacing: '2px',
          color: 'var(--text-muted)',
        }}>CORRELATION</span>
        <button
          onClick={toggle}
          style={{
            padding: '2px 10px',
            borderRadius: '3px',
            border: `1px solid ${enabled ? 'var(--accent-cyan)' : 'var(--border)'}`,
            background: enabled ? 'rgba(0,212,255,0.15)' : 'transparent',
            color: enabled ? 'var(--accent-cyan)' : 'var(--text-muted)',
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 700,
            fontSize: '10px',
            letterSpacing: '1px',
            cursor: 'pointer',
          }}
        >
          {enabled ? 'ENABLED' : 'DISABLED'}
        </button>
        {!enabled && (
          <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace' }}>
            Count events over a time window — fire alert when threshold crossed
          </span>
        )}
        {enabled && (
          <button
            onClick={() => onYamlChange(BRUTE_FORCE_EXAMPLE)}
            style={{
              marginLeft: 'auto',
              padding: '2px 8px',
              borderRadius: '3px',
              border: '1px solid var(--border)',
              background: 'transparent',
              color: 'var(--text-muted)',
              fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 600,
              fontSize: '9px',
              letterSpacing: '1px',
              cursor: 'pointer',
            }}
          >
            LOAD BRUTE FORCE EXAMPLE
          </button>
        )}
      </div>

      {enabled && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: '10px', marginTop: '10px' }}>
          {/* Group By */}
          <div>
            <label style={{ display: 'block', fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: '9px', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: '4px' }}>
              GROUP BY
            </label>
            <select
              value={isCustom ? '__custom__' : cfg.group_by}
              onChange={e => {
                if (e.target.value === '__custom__') {
                  update({ group_by: customGroupBy || 'source.ip' })
                } else {
                  update({ group_by: e.target.value })
                  setCustomGroupBy('')
                }
              }}
              style={inputStyle}
            >
              {COMMON_GROUP_BY.map(o => (
                <option key={o.value} value={o.value}>{o.label}</option>
              ))}
              <option value="__custom__">Custom...</option>
            </select>
            {isCustom && (
              <input
                value={customGroupBy}
                onChange={e => { setCustomGroupBy(e.target.value); update({ group_by: e.target.value }) }}
                placeholder="event.field"
                style={{ ...inputStyle, marginTop: '4px' }}
              />
            )}
          </div>

          {/* Threshold count */}
          <div>
            <label style={labelStyle}>THRESHOLD (events)</label>
            <input
              type="number"
              min={1}
              value={cfg.count}
              onChange={e => update({ count: parseInt(e.target.value) || 1 })}
              style={inputStyle}
            />
            <div style={hintStyle}>fire after N matches</div>
          </div>

          {/* Timeframe */}
          <div>
            <label style={labelStyle}>TIMEFRAME (seconds)</label>
            <input
              type="number"
              min={10}
              value={cfg.timewindow}
              onChange={e => update({ timewindow: parseInt(e.target.value) || 60 })}
              style={inputStyle}
            />
            <div style={hintStyle}>sliding window</div>
          </div>

          {/* Cooldown */}
          <div>
            <label style={labelStyle}>COOLDOWN (seconds)</label>
            <input
              type="number"
              min={0}
              value={cfg.cooldown}
              onChange={e => update({ cooldown: parseInt(e.target.value) || 0 })}
              style={inputStyle}
            />
            <div style={hintStyle}>suppress re-alerts</div>
          </div>
        </div>
      )}

      {enabled && (
        <div style={{ marginTop: '8px', fontFamily: 'Share Tech Mono, monospace', fontSize: '9px', color: 'var(--text-muted)', padding: '4px 8px', background: 'var(--bg-base)', borderRadius: '3px', border: '1px solid var(--border)' }}>
          Alert fires when {cfg.count}+ events{cfg.group_by !== '_all' ? ` per ${cfg.group_by}` : ''} detected within {cfg.timewindow}s · cooldown {cfg.cooldown}s · stored in Redis (survives restart)
        </div>
      )}
    </div>
  )
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '4px 8px',
  background: 'var(--bg-base)',
  border: '1px solid var(--border)',
  borderRadius: '3px',
  color: 'var(--text-primary)',
  fontFamily: 'Share Tech Mono, monospace',
  fontSize: '11px',
}

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontFamily: 'Rajdhani, sans-serif',
  fontWeight: 600,
  fontSize: '9px',
  letterSpacing: '1px',
  color: 'var(--text-muted)',
  marginBottom: '4px',
}

const hintStyle: React.CSSProperties = {
  marginTop: '3px',
  fontFamily: 'Share Tech Mono, monospace',
  fontSize: '9px',
  color: 'var(--text-muted)',
}

const SAMPLE_EVENT = `{
  "log_type": "windows_sysmon",
  "raw_message": "EventID=1 Channel=\\"Microsoft-Windows-Sysmon/Operational\\" Image=\\"C:\\\\Windows\\\\System32\\\\whoami.exe\\" CommandLine=\\"whoami /all\\""
}`

function RuleTestPanel({ content }: { content: string }) {
  const testRule = useTestRule()
  const [sample, setSample] = useState(SAMPLE_EVENT)
  const [result, setResult] = useState<RuleTestResult | null>(null)
  const [parseError, setParseError] = useState('')

  const run = () => {
    let event: Record<string, unknown>
    const text = sample.trim()
    try {
      event = text.startsWith('{') ? JSON.parse(text) : { raw_message: text }
    } catch (e) {
      setParseError(`Invalid JSON: ${(e as Error).message}`)
      return
    }
    setParseError('')
    testRule.mutate({ content, sample_event: event }, { onSuccess: setResult })
  }

  return (
    <div style={{ borderTop: '1px solid var(--border)', padding: '10px 16px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
        <span style={{ ...labelStyle, marginBottom: 0 }}>TEST EVENT — decoded fields as JSON (add log_type + raw_message to check logsource), or a raw log line</span>
        <button onClick={run} disabled={testRule.isPending}
          className="px-3 py-1 rounded border border-border text-xs hover:bg-muted disabled:opacity-50">
          {testRule.isPending ? 'Testing…' : 'Run test'}
        </button>
      </div>
      <textarea value={sample} onChange={e => setSample(e.target.value)} rows={4} spellCheck={false}
        style={{ ...inputStyle, resize: 'vertical' }} />
      {(parseError || result) && (
        <div style={{ ...hintStyle, fontSize: '11px', marginTop: '6px' }}>
          {parseError ? <span className="text-destructive">{parseError}</span>
            : result?.error ? <span className="text-destructive">✗ {result.error}</span>
            : result?.matched ? <span className="text-green-400">✓ Matched{result.rule_title ? ` — ${result.rule_title}` : ''}</span>
            : <span>✗ No match{result?.logsource_applies === false ? ' — the rule\'s logsource does not cover this log_type' : ''}</span>}
        </div>
      )}
    </div>
  )
}

const badge = (color: string): React.CSSProperties => ({
  padding: '1px 5px',
  borderRadius: '3px',
  fontSize: '9px',
  fontFamily: 'Rajdhani, sans-serif',
  fontWeight: 700,
  letterSpacing: '0.5px',
  border: `1px solid ${color}66`,
  color,
  background: `${color}14`,
  whiteSpace: 'nowrap',
})

function logsourceLabel(r: Rule): string {
  const ls = r.logsource ?? {}
  return [ls.product, ls.service, ls.category].filter(Boolean).join(' / ') || '—'
}

export default function RulesPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [filters, setFilters] = useState<RuleFilters>({})
  const [search, setSearch] = useState('')
  const { data, isLoading } = useRules(page, pageSize, filters)
  const { data: stats } = useRuleStats()
  const createRule = useCreateRule()
  const updateRule = useUpdateRule()
  const deleteRule = useDeleteRule()
  const bulk = useBulkRules()
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)
  const [importing, setImporting] = useState(false)
  const [yamlContent, setYamlContent] = useState('')

  const setFilter = (patch: RuleFilters) => { setFilters(f => ({ ...f, ...patch })); setPage(1) }
  const closeEditor = () => { setEditing(null); setCreating(false) }

  const handleSave = () => {
    // keep the editor open on a rejected rule so the error can be fixed
    if (editing) {
      updateRule.mutate({ id: editing.id, data: { content: yamlContent } }, { onSuccess: closeEditor })
    } else {
      createRule.mutate({ content: yamlContent, title: 'New Rule' }, { onSuccess: closeEditor })
    }
  }

  const hasFilter = Boolean(filters.q || filters.source || filters.level)
  const bulkSet = (is_enabled: boolean) => {
    const n = data?.total ?? 0
    if (!window.confirm(`${is_enabled ? 'Enable' : 'Disable'} all ${n} rule(s) matching the current filters?`)) return
    bulk.mutate({ is_enabled, q: filters.q, source: filters.source, level: filters.level })
  }

  const hasCorrelation = (r: Rule) => r.content.includes('\nthreshold:') || r.content.includes('\ncorrelation:')

  const columns = [
    { key: 'title', header: 'Title', render: (r: Rule) => (
      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
        {r.title}
        {r.source === 'sigmahq' && <span style={badge('#a78bfa')} title={`SigmaHQ ${r.external_id ?? ''}`}>SIGMAHQ{r.sigma_status ? ` · ${r.sigma_status.toUpperCase()}` : ''}</span>}
        {hasCorrelation(r) && <span style={badge('#00d4ff')}>CORR</span>}
        {r.modified_locally && <span style={badge('#fbbf24')} title="Edited here — SigmaHQ updates won't overwrite it">EDITED</span>}
        {r.collected === false && <span style={badge('#94a3b8')} title="No log source on this platform feeds this rule's logsource">NOT COLLECTED</span>}
      </div>
    )},
    { key: 'logsource', header: 'Log source', render: (r: Rule) => (
      <span className="text-muted-foreground text-xs font-mono">{logsourceLabel(r)}</span>
    )},
    { key: 'level', header: 'Level', render: (r: Rule) => <SeverityBadge severity={r.level} /> },
    { key: 'enabled', header: 'Enabled', render: (r: Rule) => (
      <button onClick={(e) => { e.stopPropagation(); updateRule.mutate({ id: r.id, data: { is_enabled: !r.is_enabled } }) }}
        title="Toggle" className={r.is_enabled ? 'text-green-400' : 'text-muted-foreground'}>
        {r.is_enabled ? 'Yes' : 'No'}
      </button>
    )},
    { key: 'version', header: 'Version', render: (r: Rule) => `v${r.version}` },
    { key: 'actions', header: '', render: (r: Rule) => (
      <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => { setEditing(r); setYamlContent(r.content) }}
          className="text-muted-foreground hover:text-foreground"><Pencil size={14} /></button>
        <button onClick={() => deleteRule.mutate(r.id)} className="text-destructive hover:opacity-70">
          <Trash2 size={14} /></button>
      </div>
    )},
  ]

  const sel = 'px-2 py-1 rounded border border-border bg-background text-sm'
  const sigma = stats?.sigmahq
  const custom = stats?.custom

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold">Rules</h1>
          {stats && (
            <div className="text-xs text-muted-foreground mt-1">
              Custom {custom ? `${custom.enabled}/${custom.enabled + custom.disabled}` : '0'} enabled
              {' · '}SigmaHQ {sigma ? `${sigma.enabled}/${sigma.enabled + sigma.disabled}` : 'not imported'}{sigma ? ' enabled' : ''}
            </div>
          )}
        </div>
        <div className="flex gap-2">
          <button onClick={() => setImporting(true)}
            className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
            <Download size={14} /> Import SigmaHQ
          </button>
          <button onClick={() => { setCreating(true); setYamlContent(DEFAULT_RULE) }}
            className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
            <Plus size={14} /> New Rule
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 mb-4">
        <form onSubmit={(e) => { e.preventDefault(); setFilter({ q: search.trim() || undefined }) }} className="flex items-center gap-1">
          <div className="relative">
            <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search title, id, content…"
              className="pl-7 pr-2 py-1 rounded border border-border bg-background text-sm w-64" />
          </div>
        </form>
        <select value={filters.source ?? ''} onChange={e => setFilter({ source: e.target.value || undefined })} className={sel}>
          <option value="">All sources</option>
          <option value="custom">Custom</option>
          <option value="sigmahq">SigmaHQ</option>
        </select>
        <select value={filters.enabled === undefined ? '' : String(filters.enabled)}
          onChange={e => setFilter({ enabled: e.target.value === '' ? undefined : e.target.value === 'true' })} className={sel}>
          <option value="">Enabled & disabled</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </select>
        <select value={filters.level ?? ''} onChange={e => setFilter({ level: e.target.value || undefined })} className={sel}>
          <option value="">All levels</option>
          {['critical', 'high', 'medium', 'low', 'informational'].map(l => <option key={l} value={l}>{l}</option>)}
        </select>
        {hasFilter && (
          <div className="flex gap-1 ml-auto">
            <button onClick={() => bulkSet(true)} disabled={bulk.isPending}
              className="px-2 py-1 rounded border border-border text-xs hover:bg-muted">Enable all matching</button>
            <button onClick={() => bulkSet(false)} disabled={bulk.isPending}
              className="px-2 py-1 rounded border border-border text-xs hover:bg-muted">Disable all matching</button>
          </div>
        )}
      </div>

      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={pageSize} onPageChange={setPage}
          onPageSizeChange={(s) => { setPageSize(s); setPage(1) }} />
      )}
      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.title}` : 'New Rule'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={closeEditor}
          footer={
            <>
              <CorrelationPanel
                key={editing?.id ?? 'new'}
                yamlContent={yamlContent}
                onYamlChange={setYamlContent}
              />
              <RuleTestPanel content={yamlContent} />
            </>
          }
        />
      )}
      {importing && <SigmaHQImportModal onClose={() => setImporting(false)} />}
    </div>
  )
}
