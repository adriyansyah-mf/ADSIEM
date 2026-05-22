import { useState } from 'react'
import { format } from 'date-fns'
import { Shield, Plus, Trash2, Edit2, Play, CheckCircle, XCircle, Loader2, ToggleLeft, ToggleRight, Download } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import { useYaraRules, useCreateYaraRule, useUpdateYaraRule, useToggleYaraRule, useDeleteYaraRule, useYaraScan, useSeedBuiltinRules } from '@/hooks/useYara'
import { useTask } from '@/hooks/useTasks'
import type { Agent, YaraRule } from '@/types'

const DEFAULT_RULE = `rule new_rule {
    meta:
        description = "My custom rule"
    strings:
        $s1 = "suspicious string"
        $s2 = /regex_pattern/
    condition:
        any of them
}`

function ScanResultView({ taskId }: { taskId: string }) {
  const { data: task } = useTask(taskId)
  if (!task) return <Loader2 size={14} className="animate-spin" />
  if (task.status === 'failed') return <p className="text-xs text-destructive">{task.error}</p>
  if (task.status !== 'done') return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <Loader2 size={12} className="animate-spin" /> Scanning…
    </div>
  )
  const result = task.result as { scanned_files: number; matches: Array<{ rule_name: string; file: string; matched_strings: string[] }> } | null
  if (!result) return null
  return (
    <div className="space-y-2 mt-2">
      <p className="text-xs text-muted-foreground">Scanned {result.scanned_files} files · {result.matches?.length ?? 0} matches</p>
      {(result.matches ?? []).length === 0
        ? <p className="text-xs text-emerald-400">No matches found.</p>
        : (result.matches ?? []).map((m, i) => (
            <div key={i} className="rounded border border-red-700 bg-red-900/20 p-2 text-xs font-mono">
              <div className="font-bold text-red-400">{m.rule_name}</div>
              <div className="text-muted-foreground">{m.file}</div>
              {m.matched_strings?.map((s, j) => <div key={j} className="text-yellow-400">{s}</div>)}
            </div>
          ))}
    </div>
  )
}

export default function YaraPage() {
  const { data: rules = [], isLoading } = useYaraRules()
  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents-all'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 100 } }).then(r => r.data.items),
  })
  const createRule = useCreateYaraRule()
  const updateRule = useUpdateYaraRule()
  const toggleRule = useToggleYaraRule()
  const deleteRule = useDeleteYaraRule()
  const scan = useYaraScan()
  const seedBuiltins = useSeedBuiltinRules()

  const [showForm, setShowForm] = useState(false)
  const [editTarget, setEditTarget] = useState<YaraRule | null>(null)
  const [formName, setFormName] = useState('')
  const [formDesc, setFormDesc] = useState('')
  const [formContent, setFormContent] = useState(DEFAULT_RULE)
  const [scanAgent, setScanAgent] = useState('')
  const [scanPath, setScanPath] = useState('/tmp')
  const [scanRecursive, setScanRecursive] = useState(true)
  const [lastTaskId, setLastTaskId] = useState<string | null>(null)

  const openForm = (rule?: YaraRule) => {
    if (rule) {
      setEditTarget(rule); setFormName(rule.name); setFormDesc(rule.description ?? ''); setFormContent(rule.content)
    } else {
      setEditTarget(null); setFormName(''); setFormDesc(''); setFormContent(DEFAULT_RULE)
    }
    setShowForm(true)
  }

  const saveRule = async () => {
    if (!formName || !formContent) return
    if (editTarget) {
      await updateRule.mutateAsync({ id: editTarget.id, name: formName, description: formDesc || undefined, content: formContent })
    } else {
      await createRule.mutateAsync({ name: formName, description: formDesc || undefined, content: formContent })
    }
    setShowForm(false)
  }

  const handleScan = async () => {
    if (!scanAgent) return
    const t = await scan.mutateAsync({ agent_id: scanAgent, path: scanPath, recursive: scanRecursive })
    setLastTaskId(t.id)
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={18} />
          <h1 className="text-xl font-bold">YARA Rules</h1>
        </div>
        <div className="flex gap-2">
          <button onClick={() => seedBuiltins.mutate()} disabled={seedBuiltins.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border hover:border-primary text-sm disabled:opacity-50">
            <Download size={13} /> Seed Built-ins
          </button>
          <button onClick={() => openForm()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
            <Plus size={13} /> New Rule
          </button>
        </div>
      </div>

      {/* Scan panel */}
      <div className="rounded-lg border border-border bg-card p-4 space-y-3">
        <p className="text-xs text-muted-foreground uppercase font-semibold">Run Scan</p>
        <div className="flex gap-3 flex-wrap items-end">
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Agent</p>
            <select value={scanAgent} onChange={e => setScanAgent(e.target.value)}
              className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary min-w-[180px]">
              <option value="">Select agent…</option>
              {agents.filter(a => a.status === 'online').map(a => <option key={a.id} value={a.id}>{a.hostname}</option>)}
            </select>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground">Path</p>
            <input value={scanPath} onChange={e => setScanPath(e.target.value)}
              className="bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary w-40" />
          </div>
          <label className="flex items-center gap-1.5 text-sm cursor-pointer select-none">
            <input type="checkbox" checked={scanRecursive} onChange={e => setScanRecursive(e.target.checked)} className="rounded" />
            Recursive
          </label>
          <button onClick={handleScan} disabled={!scanAgent || scan.isPending}
            className="flex items-center gap-1.5 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
            {scan.isPending ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            Scan
          </button>
        </div>
        {lastTaskId && <ScanResultView taskId={lastTaskId} />}
      </div>

      {/* Rule editor modal */}
      {showForm && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-card border border-border rounded-lg w-full max-w-2xl space-y-4 p-5">
            <h2 className="font-bold">{editTarget ? 'Edit Rule' : 'New YARA Rule'}</h2>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-xs text-muted-foreground mb-1">Name *</p>
                <input value={formName} onChange={e => setFormName(e.target.value)}
                  className="w-full bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary" />
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Description</p>
                <input value={formDesc} onChange={e => setFormDesc(e.target.value)}
                  className="w-full bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary" />
              </div>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-1">Rule Content *</p>
              <textarea value={formContent} onChange={e => setFormContent(e.target.value)} rows={14}
                className="w-full bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary resize-y" />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowForm(false)} className="px-4 py-2 rounded border border-border text-sm hover:bg-muted">Cancel</button>
              <button onClick={saveRule} disabled={!formName || !formContent || createRule.isPending || updateRule.isPending}
                className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50">
                {createRule.isPending || updateRule.isPending ? 'Saving…' : 'Save Rule'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rules list */}
      {isLoading ? <div className="text-muted-foreground text-sm">Loading…</div> : (
        <div className="space-y-2">
          {rules.length === 0 && (
            <div className="rounded-lg border border-border p-8 text-center text-muted-foreground text-sm">
              No YARA rules yet. Add one or seed built-ins.
            </div>
          )}
          {rules.map(rule => (
            <div key={rule.id} className={`rounded-lg border bg-card p-4 space-y-2 ${rule.is_enabled ? 'border-border' : 'border-border/40 opacity-60'}`}>
              <div className="flex items-center gap-2">
                <Shield size={14} className={rule.is_enabled ? 'text-primary' : 'text-muted-foreground'} />
                <span className="font-semibold text-sm">{rule.name}</span>
                {rule.description && <span className="text-xs text-muted-foreground">— {rule.description}</span>}
                <div className="flex gap-1 ml-auto">
                  <button onClick={() => toggleRule.mutate(rule.id)} title={rule.is_enabled ? 'Disable' : 'Enable'}
                    className="p-1 rounded hover:bg-muted transition-colors">
                    {rule.is_enabled ? <ToggleRight size={16} className="text-primary" /> : <ToggleLeft size={16} className="text-muted-foreground" />}
                  </button>
                  <button onClick={() => openForm(rule)} className="p-1 rounded hover:bg-muted transition-colors">
                    <Edit2 size={14} />
                  </button>
                  <button onClick={() => deleteRule.mutate(rule.id)} className="p-1 rounded hover:bg-muted text-destructive transition-colors">
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
              <details>
                <summary className="text-xs text-muted-foreground cursor-pointer">View rule · created {format(new Date(rule.created_at), 'yyyy-MM-dd')}</summary>
                <pre className="text-xs font-mono bg-muted/20 p-2 mt-2 rounded max-h-40 overflow-auto whitespace-pre">{rule.content}</pre>
              </details>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
