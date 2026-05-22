import { useState } from 'react'
import DataTable from '@/components/DataTable'
import YamlEditor from '@/components/YamlEditor'
import { useDecoders, useCreateDecoder, useUpdateDecoder, useDeleteDecoder, useTestDecoder } from '@/hooks/useDecoders'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import type { Decoder } from '@/types'

const DEFAULT_DECODER = `name: new_decoder
log_type: linux_auth
type: regex
priority: 100
enabled: true
pattern: 'Failed password for (?P<user>\\S+) from (?P<src_ip>\\S+)'
fields:
  event.category: authentication
  event.action: login_failed
  user.name: user
  source.ip: src_ip
`

export default function DecodersPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useDecoders(page)
  const createDecoder = useCreateDecoder()
  const updateDecoder = useUpdateDecoder()
  const deleteDecoder = useDeleteDecoder()
  const testDecoder = useTestDecoder()
  const [editing, setEditing] = useState<Decoder | null>(null)
  const [creating, setCreating] = useState(false)
  const [yamlContent, setYamlContent] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)

  const handleSave = () => {
    if (editing) {
      updateDecoder.mutate({ id: editing.id, data: { content: yamlContent } })
    } else {
      createDecoder.mutate({ content: yamlContent, name: 'new', log_type: 'unknown' })
    }
    setEditing(null); setCreating(false)
  }

  const handleTest = () => {
    const raw = prompt('Enter a raw log line to test:') ?? ''
    if (!raw) return
    testDecoder.mutate(
      { content: yamlContent, raw_message: raw },
      { onSuccess: (r) => setTestResult(r.matched ? `✓ ${JSON.stringify(r.decoded_fields)}` : '✗ No match') }
    )
  }

  const columns = [
    { key: 'name', header: 'Name', render: (r: Decoder) => r.name },
    { key: 'log_type', header: 'Log Type', render: (r: Decoder) => <span className="font-mono text-xs">{r.log_type}</span> },
    { key: 'priority', header: 'Priority', render: (r: Decoder) => r.priority },
    { key: 'enabled', header: 'Enabled', render: (r: Decoder) => (
      <span className={r.is_enabled ? 'text-green-400' : 'text-muted-foreground'}>{r.is_enabled ? 'Yes' : 'No'}</span>
    )},
    { key: 'actions', header: '', render: (r: Decoder) => (
      <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => { setEditing(r); setYamlContent(r.content); setTestResult(null) }}
          className="text-muted-foreground hover:text-foreground"><Pencil size={14} /></button>
        <button onClick={() => deleteDecoder.mutate(r.id)} className="text-destructive hover:opacity-70">
          <Trash2 size={14} /></button>
      </div>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Decoders</h1>
        <button onClick={() => { setCreating(true); setYamlContent(DEFAULT_DECODER); setTestResult(null) }}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Decoder
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.name}` : 'New Decoder'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={() => { setEditing(null); setCreating(false) }}
          extraAction={{ label: testResult ?? 'Test Decoder', onClick: handleTest }}
        />
      )}
    </div>
  )
}
