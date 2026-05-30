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

function DecoderTestPanel({
  yamlContent,
  testDecoder,
}: {
  yamlContent: string
  testDecoder: ReturnType<typeof useTestDecoder>
}) {
  const [rawLog, setRawLog] = useState('')
  const [result, setResult] = useState<{ matched: boolean; decoded_fields?: Record<string, unknown> } | null>(null)

  const handleTest = () => {
    if (!rawLog.trim()) return
    testDecoder.mutate(
      { content: yamlContent, raw_message: rawLog },
      {
        onSuccess: (r) => setResult(r),
      }
    )
  }

  return (
    <div className="border-t border-border px-4 py-3 space-y-2 bg-muted/20">
      <div className="text-xs font-semibold text-muted-foreground uppercase tracking-widest">
        Test Panel — Paste Raw Log
      </div>
      <textarea
        value={rawLog}
        onChange={(e) => setRawLog(e.target.value)}
        placeholder="Paste a raw log line here..."
        rows={2}
        className="w-full px-3 py-2 rounded border border-border bg-background text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary resize-y"
      />
      <div className="flex items-center gap-3">
        <button
          onClick={handleTest}
          disabled={testDecoder.isPending || !rawLog.trim()}
          className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted disabled:opacity-40"
        >
          {testDecoder.isPending ? 'Testing…' : 'Run Test'}
        </button>
        {result !== null && (
          <span className={`text-sm font-semibold ${result.matched ? 'text-green-400' : 'text-red-400'}`}>
            {result.matched ? 'Match' : 'No match'}
          </span>
        )}
      </div>
      {result?.matched && result.decoded_fields && (
        <pre className="text-xs font-mono text-muted-foreground bg-background rounded border border-border px-3 py-2 overflow-auto">
          {JSON.stringify(result.decoded_fields, null, 2)}
        </pre>
      )}
    </div>
  )
}

export default function DecodersPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const { data, isLoading } = useDecoders(page, pageSize)
  const createDecoder = useCreateDecoder()
  const updateDecoder = useUpdateDecoder()
  const deleteDecoder = useDeleteDecoder()
  const testDecoder = useTestDecoder()
  const [editing, setEditing] = useState<Decoder | null>(null)
  const [creating, setCreating] = useState(false)
  const [yamlContent, setYamlContent] = useState('')

  const handleSave = () => {
    if (editing) {
      updateDecoder.mutate({ id: editing.id, data: { content: yamlContent } })
    } else {
      createDecoder.mutate({ content: yamlContent, name: 'new', log_type: 'unknown' })
    }
    setEditing(null); setCreating(false)
  }

  const columns = [
    { key: 'name', header: 'Name', sortable: true, render: (r: Decoder) => r.name },
    { key: 'log_type', header: 'Log Type', sortable: true, render: (r: Decoder) => <span className="font-mono text-xs">{r.log_type}</span> },
    { key: 'priority', header: 'Priority', sortable: true, render: (r: Decoder) => r.priority },
    { key: 'enabled', header: 'Enabled', render: (r: Decoder) => (
      <span className={r.is_enabled ? 'text-green-400' : 'text-muted-foreground'}>{r.is_enabled ? 'Yes' : 'No'}</span>
    )},
    { key: 'actions', header: '', render: (r: Decoder) => (
      <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => { setEditing(r); setYamlContent(r.content) }}
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
        <button onClick={() => { setCreating(true); setYamlContent(DEFAULT_DECODER) }}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Decoder
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          total={data?.total ?? 0}
          page={page}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      )}
      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.name}` : 'New Decoder'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={() => { setEditing(null); setCreating(false) }}
          footer={
            <DecoderTestPanel
              key={editing?.id ?? 'new'}
              yamlContent={yamlContent}
              testDecoder={testDecoder}
            />
          }
        />
      )}
    </div>
  )
}
