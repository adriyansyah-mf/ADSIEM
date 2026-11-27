import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { CanvasHeader, CanvasPage, Chip, Empty } from '@/components/canvas/Canvas'
import YamlEditor from '@/components/YamlEditor'
import {
  useRules, useRuleStats, useCreateRule, useUpdateRule, useDeleteRule, useTestRule, useBulkRules, type RuleFilters,
} from '@/hooks/useRules'
import SigmaHQImportModal from '@/components/SigmaHQImportModal'
import { Search } from 'lucide-react'
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
      background: enabled ? 'rgba(141, 176, 255,0.03)' : 'transparent',
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
            background: enabled ? 'rgba(141, 176, 255,0.15)' : 'transparent',
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

interface QualityItem { rule_id: string; alerts: number; fp_rate: number | null; advice: string[]; last_alert_at: string | null }

function healthOf(r: Rule, q: QualityItem | undefined): { text: string; warn: boolean } {
  if (q?.advice.length) return { text: `Noisy · ${q.advice[0].split(':')[0]}`, warn: true }
  if (r.collected === false) return { text: 'Log source not connected', warn: true }
  if (r.is_enabled && !q) return { text: 'No alerts in 7 days', warn: false }
  return { text: 'Healthy', warn: false }
}

export default function RulesPage() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [filters, setFilters] = useState<RuleFilters>(() => ({ q: params.get('q') ?? undefined }))
  const [search, setSearch] = useState(params.get('q') ?? '')
  const [attention, setAttention] = useState(false)
  const { data, isLoading } = useRules(page, pageSize, filters)
  const { data: stats } = useRuleStats()
  const quality = useQuery<{ items: QualityItem[] }>({
    queryKey: ['rule-quality', 7],
    queryFn: () => api.get('/api/rule-quality', { params: { days: 7, limit: 1000 } }).then(r => r.data),
    retry: false,
    staleTime: 60_000,
  })
  const decoders = useQuery<number>({
    queryKey: ['decoders', 'count'],
    queryFn: () => api.get('/api/decoders', { params: { page: 1, page_size: 1 } }).then(r => Number(r.data.total) || 0),
    retry: false,
    staleTime: 5 * 60_000,
  })
  const createRule = useCreateRule()
  const updateRule = useUpdateRule()
  const deleteRule = useDeleteRule()
  const bulk = useBulkRules()
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)
  const [importing, setImporting] = useState(params.get('import') === '1')
  const [yamlContent, setYamlContent] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  // /rules?new=1&query=… comes from "Save as rule" on Search and "Promote to detection rule" on Hunts.
  useEffect(() => {
    if (params.get('new') !== '1') return
    const query = params.get('query')
    setYamlContent(query ? `# From search: ${query}\n${DEFAULT_RULE}` : DEFAULT_RULE)
    setCreating(true)
    setParams(current => { const next = new URLSearchParams(current); next.delete('new'); next.delete('query'); return next }, { replace: true })
  }, [params, setParams])

  const setFilter = (patch: RuleFilters) => { setFilters(f => ({ ...f, ...patch })); setPage(1) }
  const closeEditor = () => { setEditing(null); setCreating(false) }
  const handleSave = () => {
    // keep the editor open on a rejected rule so the error can be fixed
    if (editing) updateRule.mutate({ id: editing.id, data: { content: yamlContent } }, { onSuccess: closeEditor })
    else createRule.mutate({ content: yamlContent, title: 'New Rule' }, { onSuccess: closeEditor })
  }
  const hasFilter = Boolean(filters.q || filters.source || filters.level)
  const bulkSet = (is_enabled: boolean) => {
    const n = data?.total ?? 0
    if (!window.confirm(`${is_enabled ? 'Enable' : 'Disable'} all ${n} rule(s) matching the current filters?`)) return
    bulk.mutate({ is_enabled, q: filters.q, source: filters.source, level: filters.level })
  }
  const hasCorrelation = (r: Rule) => r.content.includes('\nthreshold:') || r.content.includes('\ncorrelation:')

  const byRule = new Map((quality.data?.items ?? []).map(item => [item.rule_id, item]))
  const items = (data?.items ?? []).filter(r => !attention || healthOf(r, byRule.get(r.id)).warn)
  const noisy = (quality.data?.items ?? []).filter(item => item.advice.length).length
  const selected = items.find(r => r.id === selectedId) ?? items[0] ?? null
  const sigma = stats?.sigmahq
  const custom = stats?.custom
  const enabled = (sigma?.enabled ?? 0) + (custom?.enabled ?? 0)
  const disabled = (sigma?.disabled ?? 0) + (custom?.disabled ?? 0)

  return (
    <CanvasPage>
      <CanvasHeader
        title="Detection rules"
        sub={stats ? `${enabled.toLocaleString('en-US')} enabled · ${disabled.toLocaleString('en-US')} disabled · custom ${custom ? custom.enabled + custom.disabled : 0}, SigmaHQ ${sigma ? sigma.enabled + sigma.disabled : 'not imported'}` : 'Sigma and native rules'}
        counts={{ '/rule-quality': noisy || null, '/decoders': decoders.data ?? null }}
        actions={<>
          <button type="button" className="cv-btn" onClick={() => setImporting(true)}>Import from SigmaHQ</button>
          <button type="button" className="cv-btn cv-btn--primary" onClick={() => { setCreating(true); setYamlContent(DEFAULT_RULE) }}>New rule</button>
        </>}
      />
      <div className="cv-split">
        <section className="cv-pane" aria-label="Rules">
          <div className="cv-row">
            <form className="cv-search" style={{ flex: '1 1 240px', maxWidth: 320 }} onSubmit={e => { e.preventDefault(); setFilter({ q: search.trim() || undefined }) }}>
              <Search size={14} aria-hidden="true" />
              <label htmlFor="rule-search" className="sr-only">Search rules</label>
              <input id="rule-search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Name, technique, id, content" />
            </form>
            <select className="cv-select" aria-label="Source" value={filters.source ?? ''} onChange={e => setFilter({ source: e.target.value || undefined })}>
              <option value="">Source: all</option><option value="custom">Custom</option><option value="sigmahq">SigmaHQ</option>
            </select>
            <select className="cv-select" aria-label="Status" value={filters.enabled === undefined ? '' : String(filters.enabled)}
              onChange={e => setFilter({ enabled: e.target.value === '' ? undefined : e.target.value === 'true' })}>
              <option value="">Status: all</option><option value="true">Enabled</option><option value="false">Disabled</option>
            </select>
            <select className="cv-select" aria-label="Level" value={filters.level ?? ''} onChange={e => setFilter({ level: e.target.value || undefined })}>
              <option value="">Level: all</option>
              {['critical', 'high', 'medium', 'low', 'informational'].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
            <button type="button" className="cv-btn" aria-pressed={attention} style={attention ? { background: '#262E45', color: '#E8ECF2' } : undefined}
              onClick={() => setAttention(v => !v)}>Needs attention</button>
            {hasFilter && <>
              <button type="button" className="cv-btn cv-btn--sm" onClick={() => bulkSet(true)} disabled={bulk.isPending}>Enable all matching</button>
              <button type="button" className="cv-btn cv-btn--sm" onClick={() => bulkSet(false)} disabled={bulk.isPending}>Disable all matching</button>
            </>}
          </div>
          <div className="cv-tablewrap">
            <table className="cv-table" style={{ minWidth: 720 }}>
              <thead><tr><th>Rule</th><th>Status</th><th className="is-num">Alerts, 7d</th><th>False positive rate</th><th>Health</th></tr></thead>
              <tbody>
                {items.map(r => {
                  const q = byRule.get(r.id)
                  const health = healthOf(r, q)
                  const fp = q?.fp_rate != null ? Math.round(q.fp_rate * 100) : null
                  const level = r.level_override ?? r.level
                  return (
                    <tr key={r.id} className={selected?.id === r.id ? 'is-active' : undefined} style={{ cursor: 'pointer' }} onClick={() => setSelectedId(r.id)}>
                      <td>
                        <div className="cv-stack">
                          <span className="cv-row" style={{ gap: 6 }}>
                            <button type="button" className="cv-rowlink" onClick={() => setSelectedId(r.id)}>{r.title}</button>
                            {r.source === 'sigmahq' && <Chip tone="info">SigmaHQ{r.sigma_status ? ` · ${r.sigma_status}` : ''}</Chip>}
                            {hasCorrelation(r) && <Chip>Correlation</Chip>}
                            {r.modified_locally && <Chip tone="warn">Edited</Chip>}
                          </span>
                          <span className="cv-muted cv-small">
                            {[r.mitre_tags.map(t => t.replace(/^attack\./, '')).filter(t => /^t\d/i.test(t)).map(t => t.toUpperCase())[0], logsourceLabel(r), level].filter(Boolean).join(' · ')}
                          </span>
                        </div>
                      </td>
                      <td>
                        <button type="button" className="cv-rowlink" title={r.is_enabled ? 'Disable' : 'Enable'} onClick={e => { e.stopPropagation(); updateRule.mutate({ id: r.id, data: { is_enabled: !r.is_enabled } }) }}>
                          <Chip tone={r.is_enabled ? (r.sigma_status === 'test' || r.sigma_status === 'experimental' ? 'info' : 'good') : 'muted'}>
                            {r.is_enabled ? (r.sigma_status === 'test' || r.sigma_status === 'experimental' ? 'Testing' : 'Enabled') : 'Disabled'}
                          </Chip>
                        </button>
                      </td>
                      <td className="is-num">{q?.alerts ?? 0}</td>
                      <td>{fp == null ? <span className="cv-muted">—</span> : <span className={fp >= 50 ? 'cv-t-bad' : fp >= 20 ? 'cv-t-warn' : 'cv-t-good'}>{fp}%</span>}</td>
                      <td className={health.warn ? 'cv-t-warn' : 'cv-muted'}>{health.text}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {isLoading && <Empty>Loading rules…</Empty>}
            {!isLoading && items.length === 0 && <Empty>{attention ? 'No rule on this page needs attention.' : 'No rules match.'}</Empty>}
          </div>
          {(data?.total ?? 0) > pageSize && (
            <div className="cv-row cv-small">
              <button type="button" className="cv-btn cv-btn--sm" disabled={page === 1} onClick={() => setPage(p => p - 1)}>Previous</button>
              <span className="cv-muted">Page {page} of {Math.ceil((data?.total ?? 0) / pageSize)} · {(data?.total ?? 0).toLocaleString('en-US')} rules</span>
              <button type="button" className="cv-btn cv-btn--sm" disabled={page * pageSize >= (data?.total ?? 0)} onClick={() => setPage(p => p + 1)}>Next</button>
              <select className="cv-select cv-btn--sm" aria-label="Rules per page" value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}>
                {[25, 50, 100].map(n => <option key={n} value={n}>{n} / page</option>)}
              </select>
            </div>
          )}
        </section>

        <aside className="cv-list" aria-label="Rule detail" style={{ flex: '1 1 380px', maxWidth: 460, borderRight: 0, borderLeft: '1px solid #222733', padding: 16, gap: 12 }}>
          {selected ? <>
            <span className="cv-eyebrow">{selected.source === 'sigmahq' ? 'SigmaHQ' : 'Custom'} · v{selected.version}</span>
            <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>{selected.title}</h2>
            {selected.description && <p className="cv-dim cv-small" style={{ margin: 0 }}>{selected.description}</p>}
            <pre className="cv-pre" style={{ maxHeight: 360, overflow: 'auto' }}>{selected.content}</pre>
            {byRule.get(selected.id)?.advice.map(a => <p key={a} className="cv-t-warn cv-small" style={{ margin: 0 }}>{a}</p>)}
            <div className="cv-row">
              <button type="button" className="cv-btn cv-btn--primary" onClick={() => { setEditing(selected); setYamlContent(selected.content) }}>Edit and test</button>
              <button type="button" className="cv-btn" onClick={() => updateRule.mutate({ id: selected.id, data: { is_enabled: !selected.is_enabled } })}>{selected.is_enabled ? 'Disable' : 'Enable'}</button>
              <Link className="cv-btn" to={`/alerts?view=all&q=${encodeURIComponent(selected.title)}`}>Alerts</Link>
              <button type="button" className="cv-btn cv-btn--danger" onClick={() => { if (window.confirm(`Delete rule “${selected.title}”?`)) deleteRule.mutate(selected.id) }}>Delete</button>
            </div>
          </> : <Empty>Select a rule to see its definition.</Empty>}
        </aside>
      </div>

      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.title}` : 'New Rule'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={closeEditor}
          footer={
            <>
              <CorrelationPanel key={editing?.id ?? 'new'} yamlContent={yamlContent} onYamlChange={setYamlContent} />
              <RuleTestPanel content={yamlContent} />
            </>
          }
        />
      )}
      {importing && <SigmaHQImportModal onClose={() => setImporting(false)} />}
    </CanvasPage>
  )
}
