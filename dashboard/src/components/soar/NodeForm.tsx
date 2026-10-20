import { useState } from 'react'
import { Copy, Plus, Terminal, X } from 'lucide-react'
import { apiErrors, useParseCurl } from '@/hooks/useSoar'
import { emitToast } from '@/hooks/useToast'
import { NODE_META, OUTPUT_PATHS, upstream } from '@/components/soar/meta'
import { Area, Check, Field, KeyValue, Num, S, Select, Text } from '@/components/soar/ui'
import type { Catalog, Condition, Graph, Params, WfNode } from '@/types/soar'

interface Props {
  node: WfNode
  graph: Graph
  catalog: Catalog
  disabled: boolean
  onChange: (node: WfNode) => void
}

const NO_VALUE = new Set(['not_null', 'is_null'])
const SEVERITIES = ['low', 'medium', 'high', 'critical']

function conditionsOf(p: Params): Condition[] {
  return Array.isArray(p.conditions) ? (p.conditions as Condition[]) : []
}

function Conditions({ params, set, fields, operators, disabled, listId }: {
  params: Params; set: (patch: Params) => void; fields: string[]; operators: string[]; disabled: boolean; listId: string
}) {
  const conds = conditionsOf(params)
  const update = (next: Condition[]) => set({ conditions: next })
  return (
    <>
      <datalist id={listId}>{fields.map(f => <option key={f} value={f} />)}</datalist>
      <Field label="Match">
        <Select value={params.match ?? 'all'} options={['all', 'any']} onChange={v => set({ match: v })} disabled={disabled} />
      </Field>
      <label style={S.label}>Conditions</label>
      {conds.map((c, i) => (
        <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 92px', gap: 6, marginBottom: 8,
          padding: 8, border: '1px solid var(--border)', borderRadius: 6 }}>
          <Text mono value={c.field} list={listId} placeholder="trigger.severity" disabled={disabled}
            onChange={v => update(conds.map((x, j) => (j === i ? { ...x, field: v } : x)))} />
          <Select value={c.operator} options={operators} disabled={disabled}
            onChange={v => update(conds.map((x, j) => (j === i ? { ...x, operator: v } : x)))} />
          {!NO_VALUE.has(c.operator) && (
            <Text mono value={Array.isArray(c.value) ? c.value.join(', ') : c.value} disabled={disabled}
              placeholder={c.operator === 'in' ? 'high, critical' : 'value or {{ steps.x.y }}'}
              onChange={v => update(conds.map((x, j) => (j === i ? { ...x, value: v } : x)))} />
          )}
          {!disabled && (
            <button style={{ ...S.ghost, justifyContent: 'center' }} onClick={() => update(conds.filter((_, j) => j !== i))}>
              <X size={12} /> Remove
            </button>
          )}
        </div>
      ))}
      {!disabled && (
        <button style={S.ghost} onClick={() => update([...conds, { field: 'trigger.severity', operator: 'eq', value: 'high' }])}>
          <Plus size={12} /> Add condition
        </button>
      )}
      {conds.length === 0 && <div style={S.hint}>No conditions: always matches.</div>}
    </>
  )
}

function CurlImport({ disabled, onImport }: { disabled: boolean; onImport: (p: Params, ignored: string[]) => void }) {
  const [open, setOpen] = useState(false)
  const [cmd, setCmd] = useState('')
  const parse = useParseCurl()
  if (disabled) return null
  if (!open) {
    return (
      <button style={{ ...S.ghost, marginBottom: 12 }} onClick={() => setOpen(true)}>
        <Terminal size={12} /> Import from curl
      </button>
    )
  }
  return (
    <div style={{ marginBottom: 14, padding: 10, border: '1px dashed var(--accent-cyan)', borderRadius: 6 }}>
      <Area mono rows={5} value={cmd} onChange={setCmd}
        placeholder={"curl -X POST https://api.example.com/v1/check \\\n  -H 'Authorization: Bearer {{ secrets.API_KEY }}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"ip\": \"{{ trigger.source_ip }}\"}'"} />
      <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
        <button style={S.btn()} disabled={parse.isPending || !cmd.trim()}
          onClick={() => parse.mutate(cmd, {
            onSuccess: r => { onImport(r.params, r.ignored); setOpen(false); setCmd('') },
            onError: e => emitToast(apiErrors(e)[0], 'error'),
          })}>
          {parse.isPending ? 'Parsing…' : 'Import'}
        </button>
        <button style={S.ghost} onClick={() => setOpen(false)}>Cancel</button>
      </div>
      <div style={S.hint}>Templates like {'{{ trigger.source_ip }}'} and {'{{ secrets.NAME }}'} can go anywhere in the command.</div>
    </div>
  )
}

function bodyText(body: unknown): string {
  if (body === null || body === undefined) return ''
  return typeof body === 'string' ? body : JSON.stringify(body, null, 2)
}

function HttpForm({ node, p, set, catalog, disabled }: {
  node: WfNode; p: Params; set: (patch: Params) => void; catalog: Catalog; disabled: boolean
}) {
  const bodyType = String(p.body_type ?? 'none')
  return (
    <>
      <CurlImport disabled={disabled} onImport={(params, ignored) => {
        set({ ...params, extract: p.extract ?? {} })
        emitToast(ignored.length ? `Imported (ignored: ${ignored.join(' ')})` : 'Imported from curl', 'success')
      }} />
      <div style={{ display: 'grid', gridTemplateColumns: '96px 1fr', gap: 6, marginBottom: 12 }}>
        <Select value={p.method ?? 'GET'} options={catalog.http_methods} onChange={v => set({ method: v })} disabled={disabled} />
        <Text mono value={p.url} onChange={v => set({ url: v })} placeholder="https://api.example.com/{{ trigger.source_ip }}" disabled={disabled} />
      </div>
      <Field label="Query parameters">
        <KeyValue value={p.query as Record<string, unknown>} onChange={v => set({ query: v })} keyPlaceholder="name" valuePlaceholder="value" disabled={disabled} />
      </Field>
      <Field label="Headers" hint={<>Keep API keys in Settings as <code>soar_secret_NAME</code> and use {'{{ secrets.NAME }}'} — they are never stored in run history.</>}>
        <KeyValue value={p.headers as Record<string, unknown>} onChange={v => set({ headers: v })} keyPlaceholder="Header" valuePlaceholder="value" disabled={disabled} />
      </Field>
      <Field label="Body">
        <Select value={bodyType} options={catalog.body_types} onChange={v => set({ body_type: v, body: v === 'form' ? {} : v === 'none' ? null : '' })} disabled={disabled} />
      </Field>
      {bodyType === 'form' && (
        <Field label="Form fields">
          <KeyValue value={(p.body ?? {}) as Record<string, unknown>} onChange={v => set({ body: v })} keyPlaceholder="field" valuePlaceholder="value" disabled={disabled} />
        </Field>
      )}
      {(bodyType === 'json' || bodyType === 'text') && (
        <Field label={bodyType === 'json' ? 'JSON body' : 'Text body'}>
          <Area mono rows={6} value={bodyText(p.body)} onChange={v => set({ body: v })} disabled={disabled}
            placeholder={bodyType === 'json' ? '{"ip": "{{ trigger.source_ip }}"}' : ''} />
        </Field>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        <Field label="Timeout (s)"><Num value={p.timeout ?? 15} min={1} max={30} onChange={v => set({ timeout: v })} disabled={disabled} /></Field>
        <div style={{ paddingTop: 22 }}>
          <Check checked={p.fail_on_status !== false} onChange={v => set({ fail_on_status: v })} label="4xx/5xx → error" disabled={disabled} />
        </div>
      </div>
      <Field label="Extract from the response"
        hint={<>Name → path into the response, e.g. <code>score</code> → <code>body.data.score</code>. Use later as <code>{`{{ steps.${node.id}.data.score }}`}</code>. The whole response is also at <code>{`{{ steps.${node.id}.body }}`}</code>.</>}>
        <KeyValue value={p.extract as Record<string, unknown>} onChange={v => set({ extract: v })} keyPlaceholder="name" valuePlaceholder="body.data.score" disabled={disabled} />
      </Field>
    </>
  )
}

function AvailableData({ node, graph, fields }: { node: WfNode; graph: Graph; fields: string[] }) {
  const ups = upstream(node.id, graph)
  const paths = [
    ...fields.map(f => `trigger.${f}`),
    ...ups.flatMap(id => {
      const t = graph.nodes.find(n => n.id === id)?.type
      return t ? OUTPUT_PATHS[t].map(p => `steps.${id}.${p}`) : []
    }),
  ]
  return (
    <details style={{ marginTop: 6 }}>
      <summary style={{ ...S.label, cursor: 'pointer' }}>Available data ({paths.length})</summary>
      <div style={{ maxHeight: 180, overflow: 'auto', marginTop: 6 }}>
        {paths.map(p => (
          <button key={p} title="Copy" style={{ ...S.ghost, ...S.mono, border: 'none', padding: '2px 4px', width: '100%', justifyContent: 'space-between' }}
            onClick={() => { void navigator.clipboard?.writeText(`{{ ${p} }}`); emitToast(`Copied {{ ${p} }}`, 'info') }}>
            {`{{ ${p} }}`} <Copy size={11} />
          </button>
        ))}
        {ups.length === 0 && node.type !== 'trigger' && <div style={S.hint}>Connect this node to see earlier nodes’ outputs.</div>}
      </div>
    </details>
  )
}

export function NodeForm({ node, graph, catalog, disabled, onChange }: Props) {
  const meta = NODE_META[node.type]
  const p = node.params
  const set = (patch: Params) => onChange({ ...node, params: { ...p, ...patch } })
  const ups = upstream(node.id, graph)
  const fieldSuggestions = [
    ...catalog.trigger_fields.map(f => `trigger.${f}`),
    ...ups.flatMap(id => {
      const t = graph.nodes.find(n => n.id === id)?.type
      return t ? OUTPUT_PATHS[t].map(x => `steps.${id}.${x}`) : []
    }),
  ]
  const op = String(p.operation ?? '')

  return (
    <div>
      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14, lineHeight: 1.5 }}>{meta.help}</div>
      <Field label="Name" hint={<>Id <code>{node.id}</code> — referenced as <code>{`{{ steps.${node.id}… }}`}</code></>}>
        <Text value={node.label} onChange={v => onChange({ ...node, label: v })} disabled={disabled} />
      </Field>

      {node.type === 'trigger' && (
        <>
          <Field label="Start on" hint="alert.triaged runs after the AI verdict is known; manual only runs from the Run button.">
            <Select value={p.event} options={catalog.events} onChange={v => set({ event: v })} disabled={disabled} />
          </Field>
          <Conditions params={p} set={set} fields={catalog.trigger_fields} operators={catalog.operators} disabled={disabled} listId={`f-${node.id}`} />
        </>
      )}

      {node.type === 'if' && (
        <Conditions params={p} set={set} fields={fieldSuggestions} operators={catalog.operators} disabled={disabled} listId={`f-${node.id}`} />
      )}

      {node.type === 'enrich' && (
        <>
          <Field label="Indicator" hint="IP, domain, URL or hash — or any text containing them.">
            <Text mono value={p.indicator} onChange={v => set({ indicator: v })} disabled={disabled} />
          </Field>
          <Check checked={p.add_note !== false} onChange={v => set({ add_note: v })} label="Write findings as an alert note" disabled={disabled} />
        </>
      )}

      {node.type === 'ai_decide' && (
        <>
          <Field label="Question" hint="Answered yes/no from the alert and every earlier node’s output.">
            <Area rows={4} value={p.question} onChange={v => set({ question: v })} disabled={disabled} />
          </Field>
          <Field label="Minimum confidence for “yes”">
            <Num value={p.min_confidence ?? 0.6} min={0} max={1} step={0.05} onChange={v => set({ min_confidence: v })} disabled={disabled} />
          </Field>
        </>
      )}

      {node.type === 'approval' && (
        <>
          <Field label="Message to the analyst"><Area value={p.message} onChange={v => set({ message: v })} disabled={disabled} /></Field>
          <Field label="Timeout (minutes)" hint="No decision by then → rejected.">
            <Num value={p.timeout_minutes ?? 60} min={1} max={10080} onChange={v => set({ timeout_minutes: v })} disabled={disabled} />
          </Field>
        </>
      )}

      {node.type === 'response' && (
        <>
          <Field label="Operation">
            <Select value={op} options={catalog.response_operations} onChange={v => set({ operation: v })} disabled={disabled} />
          </Field>
          <Field label="Agent hostname" hint="Empty = the alert’s host.">
            <Text mono value={p.hostname} placeholder="{{ trigger.hostname }}" onChange={v => set({ hostname: v })} disabled={disabled} />
          </Field>
          {(op === 'block_ip' || op === 'unblock_ip') && (
            <Field label="IP"><Text mono value={p.ip} placeholder="{{ trigger.source_ip }}" onChange={v => set({ ip: v })} disabled={disabled} /></Field>
          )}
          {op === 'block_ip' && (
            <Field label="Block for (seconds)"><Num value={p.duration_seconds ?? 3600} min={60} onChange={v => set({ duration_seconds: v })} disabled={disabled} /></Field>
          )}
          {op === 'kill_process' && (
            <>
              <Field label="PID"><Text mono value={p.pid} placeholder="{{ steps.http_1.data.pid }}" onChange={v => set({ pid: v })} disabled={disabled} /></Field>
              <Check checked={!!p.force} onChange={v => set({ force: v })} label="Force (SIGKILL)" disabled={disabled} />
            </>
          )}
          {op === 'quarantine_file' && (
            <Field label="File path"><Text mono value={p.path} onChange={v => set({ path: v })} disabled={disabled} /></Field>
          )}
        </>
      )}

      {node.type === 'case' && (
        <>
          <Field label="Operation">
            <Select value={op} options={catalog.case_operations} onChange={v => set({ operation: v })} disabled={disabled} />
          </Field>
          {op === 'create_case' && (
            <>
              <Field label="Title"><Text value={p.title} placeholder="SOAR: {{ trigger.rule_title }}" onChange={v => set({ title: v })} disabled={disabled} /></Field>
              <Field label="Description"><Area value={p.description} onChange={v => set({ description: v })} disabled={disabled} /></Field>
              <Field label="Severity" hint="Empty = the alert’s severity.">
                <Select value={p.severity ?? ''} options={['', ...SEVERITIES]} onChange={v => set({ severity: v || null })} disabled={disabled} />
              </Field>
            </>
          )}
          {op === 'add_note' && (
            <Field label="Note"><Area rows={4} value={p.content} onChange={v => set({ content: v })} disabled={disabled} /></Field>
          )}
          {op === 'set_alert_status' && (
            <Field label="Status">
              <Select value={p.status ?? ''} options={['', ...catalog.alert_statuses]} onChange={v => set({ status: v })} disabled={disabled} />
            </Field>
          )}
          {op === 'suppress' && (
            <>
              <Field label="Suppress by">
                <Select value={p.entity_type ?? 'ip'} options={['ip', 'hostname', 'rule_title']} onChange={v => set({ entity_type: v })} disabled={disabled} />
              </Field>
              <Field label="Reason"><Text value={p.reason} onChange={v => set({ reason: v })} disabled={disabled} /></Field>
            </>
          )}
        </>
      )}

      {node.type === 'notify' && (
        <>
          <Field label="Channel">
            <Select value={p.channel ?? 'webhook'} options={catalog.notify_channels} onChange={v => set({ channel: v })} disabled={disabled} />
          </Field>
          <Field label="Webhook URL"><Text mono value={p.url} onChange={v => set({ url: v })} disabled={disabled} /></Field>
          <Field label="Message"><Area rows={4} value={p.message} onChange={v => set({ message: v })} disabled={disabled} /></Field>
        </>
      )}

      {node.type === 'http' && <HttpForm node={node} p={p} set={set} catalog={catalog} disabled={disabled} />}

      {meta.outputs.includes('error') && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12, marginTop: 4 }}>
          <Field label="Retries on failure"><Num value={node.retry} min={0} max={3} onChange={v => onChange({ ...node, retry: v })} disabled={disabled} /></Field>
          <Check checked={node.continue_on_error} onChange={v => onChange({ ...node, continue_on_error: v })} disabled={disabled}
            label="If it still fails and the error output is not connected, carry on along the normal output" />
        </div>
      )}

      <AvailableData node={node} graph={graph} fields={catalog.trigger_fields} />
    </div>
  )
}
