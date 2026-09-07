import { useState, useRef, useEffect } from 'react'
import { Bot, Send, Loader2 } from 'lucide-react'
import { api } from '@/api/client'
import { PageHeader } from '@/components/ui/PageHeader'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

const SUGGESTIONS = [
  'Any critical alerts today?',
  "Summarize case sla-gate-check",
  "What's risky right now?",
  'Is host web01 online?',
]

export default function AssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const send = async (overrideText?: string) => {
    const text = (overrideText ?? input).trim()
    if (!text || loading) return
    const next = [...messages, { role: 'user' as const, content: text }]
    setMessages(next)
    setInput('')
    setLoading(true)
    try {
      const res = await api.post('/api/assistant/chat', {
        message: text,
        history: next.slice(0, -1),
      })
      setMessages(m => [...m, { role: 'assistant', content: res.data.reply }])
    } catch {
      setMessages(m => [...m, { role: 'assistant', content: 'Something went wrong reaching the assistant. Try again.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <PageHeader title={<><Bot aria-hidden="true" size={20} /> SOC Assistant</>} />
      <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: '4px 0 14px' }}>
        Read-only · alerts, cases, agents, UEBA, FIM, hunts, rules. It can't change settings, users, or webhooks, or take actions — it just looks things up.
      </p>

      <div style={{
        flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column',
        border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-card)', overflow: 'hidden',
      }}>
        <div style={{ flex: 1, overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {messages.length === 0 && (
            <div style={{ margin: 'auto', maxWidth: 480, textAlign: 'center' }}>
              <Bot size={32} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
              <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>
                Ask about anything in your tenant — alerts, cases, agent status, UEBA anomalies, FIM changes, hunts, or rules.
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, justifyContent: 'center' }}>
                {SUGGESTIONS.map(s => (
                  <button
                    key={s}
                    onClick={() => send(s)}
                    style={{
                      fontSize: 12, padding: '6px 12px', borderRadius: 999,
                      border: '1px solid var(--border)', background: 'var(--bg-panel)',
                      color: 'var(--text-secondary)', cursor: 'pointer',
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}
          {messages.map((m, i) => (
            <div key={i} style={{
              alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
              maxWidth: '70%',
              background: m.role === 'user' ? 'rgba(0,217,192,0.14)' : 'var(--bg-panel)',
              border: `1px solid ${m.role === 'user' ? 'rgba(0,217,192,0.55)' : 'var(--border)'}`,
              borderRadius: 8, padding: '10px 14px',
              fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.55, whiteSpace: 'pre-wrap',
            }}>
              {m.content}
            </div>
          ))}
          {loading && (
            <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 12 }}>
              <Loader2 size={13} className="animate-spin" /> Looking into it…
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        <div style={{ padding: 14, borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
            placeholder="Ask about alerts, cases, agents…"
            aria-label="Message SOC Assistant"
            disabled={loading}
            style={{
              flex: 1, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 6,
              padding: '10px 12px', color: 'var(--text-primary)', fontSize: 13,
            }}
          />
          <button
            onClick={() => send()}
            disabled={loading || !input.trim()}
            aria-label="Send message"
            style={{
              width: 42, minHeight: 42, borderRadius: 6, border: '1px solid var(--accent-blue)',
              background: 'rgba(0,217,192,0.12)', color: 'var(--accent-blue)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
              opacity: loading || !input.trim() ? 0.5 : 1,
            }}
          >
            <Send size={15} />
          </button>
        </div>
      </div>
    </div>
  )
}
