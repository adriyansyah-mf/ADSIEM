import { useEffect, useRef, useState } from 'react'
import { Ban, CheckCircle2, Send } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'
import MarkdownNote from '@/components/MarkdownNote'
import { useInvestigationChat, type ChatAction, type ChatMessage } from '@/hooks/useInvestigationChat'

const mono: React.CSSProperties = { fontFamily: 'Share Tech Mono, monospace' }
const label: React.CSSProperties = {
  fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '11px', letterSpacing: '1.5px',
  textTransform: 'uppercase', color: 'var(--text-muted)',
}

const TOOL_LABEL: Record<string, string> = {
  isolate_host: 'Isolate host', unisolate_host: 'Unisolate host', block_domain: 'Block domain',
  add_threat_ioc: 'Add to Threat IoCs', block_ip: 'Block IP', kill_process: 'Kill process',
  quarantine_file: 'Quarantine file', run_live_response: 'Run live response', pin_evidence: 'Pin evidence',
  add_case_ioc: 'Add case IoC', remove_case_ioc: 'Remove case IoC',
}
const CASE_TOOLS = new Set(['pin_evidence', 'add_case_ioc', 'remove_case_ioc', 'add_threat_ioc'])
const STATUS_COLOR: Record<string, string> = {
  proposed: 'var(--accent-orange)', approved: 'var(--accent-cyan)', executed: 'var(--accent-green)',
  rejected: 'var(--text-muted)', failed: 'var(--accent-red)', expired: 'var(--text-muted)',
}

function paramLines(a: ChatAction): string[] {
  const p = a.params ?? {}
  const out: string[] = []
  const agents = (p.agent_ids as string[] | undefined) ?? (p.agent_id ? [String(p.agent_id)] : [])
  if (a.tool === 'block_ip') {
    out.push(`IP ${p.ip}`, `for ${Number(p.duration_seconds) >= 3600 ? `${Number(p.duration_seconds) / 3600}h` : `${p.duration_seconds}s`}`)
  }
  if (a.tool === 'block_domain') {
    out.push(`domain ${p.domain}`, p.days ? `${p.days} days` : 'no expiry')
  }
  if (a.tool === 'kill_process') out.push(`pid ${p.pid}`)
  if (a.tool === 'quarantine_file') out.push(`path ${p.path}`)
  if (a.tool === 'run_live_response') {
    out.push(`artifact ${p.artifact}`)
    const extra = Object.entries((p.params as Record<string, unknown>) ?? {}).map(([k, v]) => `${k}=${String(v)}`)
    out.push(...extra)
  }
  if (a.tool === 'pin_evidence') out.push(`evidence ${p.evidence_id}`)
  if (['add_case_ioc', 'remove_case_ioc', 'add_threat_ioc'].includes(a.tool)) out.push(`${p.type}: ${p.value}`)
  if (agents.length && a.tool !== 'block_ip') out.push(`agent ${agents.join(', ')}`)
  if (a.tool === 'block_ip' && agents.length) out.push(`agents ${agents.join(', ')}`)
  return out
}

function Chip({ text, color }: { text: string; color: string }) {
  return (
    <span style={{ ...label, color, border: `1px solid ${color}`, padding: '1px 6px', borderRadius: '3px', fontSize: '10px', letterSpacing: '1px' }}>
      {text}
    </span>
  )
}

function ProposalCard({ action, onDecide, busy }: {
  action: ChatAction
  onDecide: (approve: boolean, note?: string) => void
  busy: boolean
}) {
  const hasRole = useAuthStore(s => s.hasRole)
  const [note, setNote] = useState('')
  const isCase = CASE_TOOLS.has(action.tool)
  const allowed = hasRole(isCase ? 'analyst' : 'admin')
  const tip = allowed ? undefined : isCase ? 'Needs the analyst role' : 'Endpoint actions need the admin role'
  const name = TOOL_LABEL[action.tool] ?? action.tool
  const params = paramLines(action)
  const flow = action.result?.flow_status
  const approve = () => {
    if (!isCase && !window.confirm(`${name}${action.target ? ` — ${action.target}` : ''}\n\nThis acts on a live endpoint. Approve?`)) return
    onDecide(true)
  }
  const btn: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '5px 12px', borderRadius: '4px',
    fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px',
    background: 'transparent', cursor: allowed && !busy ? 'pointer' : 'not-allowed', opacity: allowed ? 1 : 0.5,
  }
  return (
    <div style={{ border: `1px solid ${STATUS_COLOR[action.status] ?? 'var(--border)'}`, borderRadius: '4px', padding: '8px 10px', marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
        <b style={{ fontSize: '13px' }}>{name}</b>
        {action.target && <span style={{ ...mono, fontSize: '12px', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{action.target}</span>}
        <Chip text={action.status} color={STATUS_COLOR[action.status] ?? 'var(--text-muted)'} />
      </div>
      {params.length > 0 && <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', wordBreak: 'break-all' }}>{params.join(' · ')}</div>}
      {action.reason && <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Reason: {action.reason}</div>}
      {action.result?.summary && <div style={{ fontSize: '12px', color: 'var(--accent-green)' }}>{action.result.summary}</div>}
      {action.tool === 'run_live_response' && action.status === 'executed' && flow && (
        <div style={{ ...mono, fontSize: '11px', color: action.result?.flow_error ? 'var(--accent-red)' : 'var(--text-muted)' }}>
          flow {flow}{action.result?.flow_rows != null ? ` · ${action.result.flow_rows} rows` : ''}
          {action.result?.flow_error ? ` · ${action.result.flow_error}` : ''}
          {action.result?.flow_id ? <> · <a href={`/live-response?flow=${action.result.flow_id}`} style={{ color: 'var(--accent-cyan)' }}>view flow</a></> : null}
        </div>
      )}
      {action.error && <div style={{ ...mono, fontSize: '12px', color: 'var(--accent-red)' }}>{action.error}</div>}
      {action.status === 'proposed' && (
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <input value={note} onChange={e => setNote(e.target.value)} maxLength={1000} aria-label="Note for a rejection (optional)"
            placeholder="Note (optional)"
            style={{ ...mono, flex: '1 1 160px', fontSize: '12px', padding: '5px 8px', background: 'var(--bg-base)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: '4px' }} />
          <button onClick={approve} disabled={!allowed || busy} title={tip} aria-label={`Approve: ${name}`}
            style={{ ...btn, border: '1px solid var(--accent-green)', color: 'var(--accent-green)' }}>
            <CheckCircle2 size={13} /> APPROVE
          </button>
          <button onClick={() => onDecide(false, note)} disabled={!allowed || busy} title={tip} aria-label={`Reject: ${name}`}
            style={{ ...btn, border: '1px solid var(--accent-red)', color: 'var(--accent-red)' }}>
            <Ban size={13} /> REJECT
          </button>
        </div>
      )}
    </div>
  )
}

function Bubble({ m }: { m: ChatMessage }) {
  if (m.role === 'system') {
    return <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)', textAlign: 'center', padding: '2px 0' }}>{m.content}</div>
  }
  if (m.role === 'user') {
    return (
      <div style={{ alignSelf: 'flex-end', maxWidth: '85%', border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.08)', borderRadius: '6px', padding: '6px 10px', fontSize: '13px', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
        {m.content}
      </div>
    )
  }
  return null
}

export default function InvestigationChat({ invId }: { invId: string }) {
  const { messages, actions, isLoading, send, decide, sending, sendError } = useInvestigationChat(invId, true)
  const [text, setText] = useState('')
  const endRef = useRef<HTMLDivElement>(null)
  useEffect(() => { endRef.current?.scrollIntoView?.({ block: 'nearest' }) }, [messages.length, actions.length])

  const submit = () => {
    const t = text.trim()
    if (!t || sending) return
    setText('')
    send.mutate(t, { onError: () => setText(t) })
  }

  const known = new Set(messages.map(m => m.id))
  const orphans = actions.filter(a => !a.message_id || !known.has(a.message_id))
  const card = (a: ChatAction) => (
    <ProposalCard key={a.id} action={a} busy={decide.isPending}
      onDecide={(approve, note) => decide.mutate({ actionId: a.id, approve, note })} />
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
        Ask the AI to look things up or propose actions. Every action that changes data or touches an endpoint waits for
        your approval. Chat IP blocks can target any agent in this case&apos;s group and any public IP.
      </div>
      <div role="log" aria-live="polite" aria-label="Investigation chat"
        style={{ border: '1px solid var(--border)', borderRadius: '4px', padding: '10px', maxHeight: '420px', minHeight: '120px', overflow: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {isLoading && <div style={{ ...mono, fontSize: '12px', color: 'var(--text-muted)' }}>Loading</div>}
        {!isLoading && messages.length === 0 && (
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Ask a follow-up about this investigation, or ask for a response action. Actions are only proposed; you approve each one.
          </div>
        )}
        {messages.map(m => (
          <div key={m.id} style={{ display: 'flex', flexDirection: 'column' }}>
            {m.role === 'assistant' ? (
              <div style={{ maxWidth: '92%', fontSize: '13px' }}>
                <MarkdownNote content={m.content} style={{ fontFamily: 'Exo 2, sans-serif', fontSize: '13px', color: 'var(--text-primary)' }} />
                {actions.filter(a => a.message_id === m.id).map(card)}
              </div>
            ) : <Bubble m={m} />}
          </div>
        ))}
        {orphans.length > 0 && (
          <div>
            <span style={label}>Other proposals</span>
            {orphans.map(card)}
          </div>
        )}
        {sending && <div style={{ ...mono, fontSize: '11px', color: 'var(--text-muted)' }}>Thinking...</div>}
        <div ref={endRef} />
      </div>
      {sendError && <div role="alert" style={{ ...mono, fontSize: '12px', color: 'var(--accent-red)' }}>{sendError}</div>}
      <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-end' }}>
        <textarea value={text} onChange={e => setText(e.target.value)} rows={2} maxLength={4000} aria-label="Message"
          placeholder="Ask about this investigation (Enter to send, Shift+Enter for a new line)"
          onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit() } }}
          style={{ ...mono, flex: 1, fontSize: '12px', padding: '6px 8px', resize: 'vertical', background: 'var(--bg-base)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: '4px' }} />
        <button onClick={submit} disabled={sending || !text.trim()} aria-label="Send message"
          style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '6px 12px', borderRadius: '4px', border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.08)', color: 'var(--accent-cyan)', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px', cursor: sending ? 'not-allowed' : 'pointer', opacity: sending ? 0.5 : 1 }}>
          <Send size={13} /> SEND
        </button>
      </div>
    </div>
  )
}
