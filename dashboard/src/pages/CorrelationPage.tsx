import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from 'react-query'
import { GitMerge, Plus, Trash2, Pencil, X, Check } from 'lucide-react'
import { api } from '@/api/client'

interface CorrelationRule {
  id: string
  title: string
  description: string | null
  match_field: string
  min_count: number
  timewindow: number
  severity_filter: string | null
  output_severity: string
  output_title: string
  is_enabled: boolean
  group_id: string | null
  created_at: string
}

const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const MATCH_FIELDS = ['source_ip', 'destination_ip', 'user', 'hostname', 'rule_title']

const defaultForm = {
  title: '',
  description: '',
  match_field: 'source_ip',
  min_count: 5,
  timewindow: 300,
  severity_filter: '',
  output_severity: 'high',
  output_title: '[Correlated] {count} alerts from {match_value}',
  is_enabled: true,
}

export default function CorrelationPage() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState(defaultForm)
  const [editId, setEditId] = useState<string | null>(null)

  const { data: rules = [], isLoading } = useQuery<CorrelationRule[]>(
    'correlation-rules',
    () => api.get('/api/correlation-rules').then(r => r.data),
    { refetchInterval: 30000 }
  )

  const createRule = useMutation(
    (body: typeof defaultForm) => api.post('/api/correlation-rules', body),
    {
      onSuccess: () => {
        qc.invalidateQueries('correlation-rules')
        setShowForm(false)
        setForm(defaultForm)
      },
    }
  )

  const updateRule = useMutation(
    ({ id, body }: { id: string; body: Partial<typeof defaultForm> }) =>
      api.patch(`/api/correlation-rules/${id}`, body),
    { onSuccess: () => { qc.invalidateQueries('correlation-rules'); setEditId(null) } }
  )

  const deleteRule = useMutation(
    (id: string) => api.delete(`/api/correlation-rules/${id}`),
    { onSuccess: () => qc.invalidateQueries('correlation-rules') }
  )

  const toggleRule = (rule: CorrelationRule) =>
    updateRule.mutate({ id: rule.id, body: { is_enabled: !rule.is_enabled } })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const payload = { ...form, severity_filter: form.severity_filter || null }
    if (editId) {
      updateRule.mutate({ id: editId, body: payload })
    } else {
      createRule.mutate(payload as typeof defaultForm)
    }
  }

  const startEdit = (rule: CorrelationRule) => {
    setEditId(rule.id)
    setForm({
      title: rule.title,
      description: rule.description ?? '',
      match_field: rule.match_field,
      min_count: rule.min_count,
      timewindow: rule.timewindow,
      severity_filter: rule.severity_filter ?? '',
      output_severity: rule.output_severity,
      output_title: rule.output_title,
      is_enabled: rule.is_enabled,
    })
    setShowForm(true)
  }

  const cancelForm = () => {
    setShowForm(false)
    setEditId(null)
    setForm(defaultForm)
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GitMerge size={20} />
          <h1 className="text-xl font-semibold">Correlation Rules</h1>
        </div>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="flex items-center gap-1 px-3 py-1.5 bg-primary text-primary-foreground rounded text-sm"
          >
            <Plus size={14} /> New Rule
          </button>
        )}
      </div>

      {showForm && (
        <form onSubmit={handleSubmit} className="bg-card border border-border rounded p-4 space-y-3">
          <div className="font-medium text-sm">{editId ? 'Edit Rule' : 'New Correlation Rule'}</div>
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className="text-xs text-muted-foreground">Title</label>
              <input
                required
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.title}
                onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Match Field</label>
              <select
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.match_field}
                onChange={e => setForm(f => ({ ...f, match_field: e.target.value }))}
              >
                {MATCH_FIELDS.map(f => <option key={f}>{f}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Severity Filter (optional)</label>
              <select
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.severity_filter}
                onChange={e => setForm(f => ({ ...f, severity_filter: e.target.value }))}
              >
                <option value="">Any severity</option>
                {SEVERITIES.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Min Count</label>
              <input
                type="number" min={2}
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.min_count}
                onChange={e => setForm(f => ({ ...f, min_count: +e.target.value }))}
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Time Window (seconds)</label>
              <input
                type="number" min={60}
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.timewindow}
                onChange={e => setForm(f => ({ ...f, timewindow: +e.target.value }))}
              />
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Output Severity</label>
              <select
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.output_severity}
                onChange={e => setForm(f => ({ ...f, output_severity: e.target.value }))}
              >
                {SEVERITIES.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground">Enabled</label>
              <select
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.is_enabled ? 'true' : 'false'}
                onChange={e => setForm(f => ({ ...f, is_enabled: e.target.value === 'true' }))}
              >
                <option value="true">Yes</option>
                <option value="false">No</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="text-xs text-muted-foreground">Output Title (use {'{count}'} and {'{match_value}'})</label>
              <input
                required
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.output_title}
                onChange={e => setForm(f => ({ ...f, output_title: e.target.value }))}
              />
            </div>
            <div className="col-span-2">
              <label className="text-xs text-muted-foreground">Description</label>
              <textarea
                rows={2}
                className="w-full mt-1 px-2 py-1 text-sm bg-background border border-border rounded"
                value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              />
            </div>
          </div>
          <div className="flex gap-2">
            <button type="submit" className="flex items-center gap-1 px-3 py-1.5 bg-primary text-primary-foreground rounded text-sm">
              <Check size={14} /> {editId ? 'Update' : 'Create'}
            </button>
            <button type="button" onClick={cancelForm} className="flex items-center gap-1 px-3 py-1.5 border border-border rounded text-sm">
              <X size={14} /> Cancel
            </button>
          </div>
        </form>
      )}

      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading...</div>
      ) : rules.length === 0 ? (
        <div className="text-sm text-muted-foreground">No correlation rules yet.</div>
      ) : (
        <div className="border border-border rounded overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                <th className="text-left px-3 py-2">Title</th>
                <th className="text-left px-3 py-2">Match</th>
                <th className="text-left px-3 py-2">Threshold</th>
                <th className="text-left px-3 py-2">Window</th>
                <th className="text-left px-3 py-2">Output Sev.</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule.id} className="border-t border-border hover:bg-muted/30">
                  <td className="px-3 py-2 font-medium">{rule.title}</td>
                  <td className="px-3 py-2 text-muted-foreground">{rule.match_field}</td>
                  <td className="px-3 py-2">{rule.min_count} alerts</td>
                  <td className="px-3 py-2">{rule.timewindow}s</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${
                      rule.output_severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      rule.output_severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      rule.output_severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>{rule.output_severity}</span>
                  </td>
                  <td className="px-3 py-2">
                    <button
                      onClick={() => toggleRule(rule)}
                      className={`px-2 py-0.5 rounded text-xs ${rule.is_enabled ? 'bg-green-500/20 text-green-400' : 'bg-muted text-muted-foreground'}`}
                    >
                      {rule.is_enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => startEdit(rule)} className="text-muted-foreground hover:text-foreground">
                        <Pencil size={14} />
                      </button>
                      <button onClick={() => deleteRule.mutate(rule.id)} className="text-muted-foreground hover:text-destructive">
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
