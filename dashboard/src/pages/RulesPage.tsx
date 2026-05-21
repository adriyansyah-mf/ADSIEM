import { useState } from 'react'
import DataTable from '@/components/DataTable'
import YamlEditor from '@/components/YamlEditor'
import SeverityBadge from '@/components/SeverityBadge'
import { useRules, useCreateRule, useUpdateRule, useDeleteRule, useTestRule } from '@/hooks/useRules'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import type { Rule } from '@/types'

const DEFAULT_RULE = `title: New Rule
id: rule-new
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
tags: []
`

export default function RulesPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useRules(page)
  const createRule = useCreateRule()
  const updateRule = useUpdateRule()
  const deleteRule = useDeleteRule()
  const testRule = useTestRule()
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)
  const [yamlContent, setYamlContent] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)

  const handleSave = () => {
    if (editing) {
      updateRule.mutate({ id: editing.id, data: { content: yamlContent } })
    } else {
      createRule.mutate({ content: yamlContent, title: 'New Rule' })
    }
    setEditing(null)
    setCreating(false)
  }

  const handleTest = () => {
    testRule.mutate(
      { content: yamlContent, sample_event: { 'event.action': 'login_failed' } },
      { onSuccess: (r) => setTestResult(r.matched ? '✓ Matched' : '✗ No match') }
    )
  }

  const columns = [
    { key: 'title', header: 'Title', render: (r: Rule) => r.title },
    { key: 'level', header: 'Level', render: (r: Rule) => <SeverityBadge severity={r.level} /> },
    { key: 'enabled', header: 'Enabled', render: (r: Rule) => (
      <span className={r.is_enabled ? 'text-green-400' : 'text-muted-foreground'}>
        {r.is_enabled ? 'Yes' : 'No'}
      </span>
    )},
    { key: 'version', header: 'Version', render: (r: Rule) => `v${r.version}` },
    { key: 'actions', header: '', render: (r: Rule) => (
      <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => { setEditing(r); setYamlContent(r.content); setTestResult(null) }}
          className="text-muted-foreground hover:text-foreground"><Pencil size={14} /></button>
        <button onClick={() => deleteRule.mutate(r.id)} className="text-destructive hover:opacity-70">
          <Trash2 size={14} /></button>
      </div>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Rules</h1>
        <button onClick={() => { setCreating(true); setYamlContent(DEFAULT_RULE); setTestResult(null) }}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Rule
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.title}` : 'New Rule'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={() => { setEditing(null); setCreating(false) }}
          extraAction={{ label: testResult ?? 'Test Rule', onClick: handleTest }}
        />
      )}
    </div>
  )
}
