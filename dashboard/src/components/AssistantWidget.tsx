import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bot, X, Send, Loader2, ArrowRight } from 'lucide-react'
import { useAuthStore } from '@/stores/auth'

interface ChatAction {
  label: string
  to: string
}

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  actions?: ChatAction[]
}

export default function AssistantWidget() {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef<HTMLDivElement | null>(null)
  const navigate = useNavigate()

  const setActions = (actions: ChatAction[]) =>
    setMessages(m => {
      const copy = [...m]
      const last = copy[copy.length - 1]
      if (last?.role === 'assistant') {
        copy[copy.length - 1] = { ...last, actions }
      }
      return copy
    })

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const send = async () => {
    const text = input.trim()
    if (!text || loading) return
    const next = [...messages, { role: 'user' as const, content: text }]
    setMessages([...next, { role: 'assistant', content: '' }])
    setInput('')
    setLoading(true)

    const appendAssistant = (delta: string) =>
      setMessages(m => {
        const copy = [...m]
        const last = copy[copy.length - 1]
        if (last?.role === 'assistant') {
          copy[copy.length - 1] = { ...last, content: last.content + delta }
        }
        return copy
      })

    try {
      const token = useAuthStore.getState().accessToken
      const base = import.meta.env.VITE_API_URL || ''
      const res = await fetch(`${base}/api/assistant/chat/stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ message: text, history: next.slice(0, -1) }),
      })

      if (!res.ok || !res.body) throw new Error(`stream failed: ${res.status}`)

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        const frames = buffer.split('\n\n')
        buffer = frames.pop() ?? ''

        for (const frame of frames) {
          const line = frame.trim()
          if (!line.startsWith('data:')) continue
          const payload = line.slice(5).trim()
          if (!payload || payload === '[DONE]') continue
          try {
            const chunk = JSON.parse(payload) as {
              type: string
              text?: string
              message?: string
              actions?: ChatAction[]
            }
            if (chunk.type === 'text-delta' && chunk.text) {
              appendAssistant(chunk.text)
            } else if (chunk.type === 'actions' && chunk.actions) {
              setActions(chunk.actions)
            } else if (chunk.type === 'error') {
              appendAssistant(chunk.message || 'The assistant hit an error.')
            }
          } catch {
            continue
          }
        }
      }
    } catch {
      setMessages(m => {
        const copy = [...m]
        const last = copy[copy.length - 1]
        if (last?.role === 'assistant' && !last.content) {
          copy[copy.length - 1] = { ...last, content: 'Something went wrong reaching the assistant. Try again.' }
        }
        return copy
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <button
        onClick={() => setOpen(o => !o)}
        title="SOC Assistant"
        aria-label={open ? 'Close SOC assistant' : 'Open SOC assistant'}
        aria-expanded={open}
        style={{
          position: 'fixed', right: 24, bottom: 24, zIndex: 60,
          width: 44, height: 44, borderRadius: 8,
          background: 'var(--bg-card)',
          border: '1px solid var(--border-default)',
          color: 'var(--text-primary)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer',
        }}
      >
        {open ? <X size={22} /> : <Bot size={22} />}
      </button>

      {open && (
        <div role="region" aria-label="SOC assistant" onKeyDown={event => { if (event.key === 'Escape') setOpen(false) }} style={{
          position: 'fixed', right: 24, bottom: 88, zIndex: 60,
          width: 380, maxWidth: '92vw', height: 520, maxHeight: '70vh',
          background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 10,
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          boxShadow: '0 12px 40px rgba(0,0,0,.5)',
        }}>
          <div style={{
            padding: '12px 14px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', gap: 8,
            background: 'linear-gradient(180deg,var(--bg-card),var(--bg-panel))',
          }}>
            <Bot size={16} color="var(--accent-cyan)" />
            <div>
              <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 13, letterSpacing: 1, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                SOC Assistant
              </div>
              <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 9.5, color: 'var(--text-muted)' }}>
                Read-only · alerts, cases, agents, UEBA, FIM, hunts, rules
              </div>
            </div>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {messages.length === 0 && (
              <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Ask me things like "any critical alerts today?", "summarize case X", "what's risky right now?", or "is host web01 online?"
                <br /><br />
                I can't change settings, users, or webhooks, or take actions — I just look things up.
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} style={{
                alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '88%',
                background: m.role === 'user' ? 'rgba(0,212,255,0.12)' : 'var(--bg-card)',
                border: `1px solid ${m.role === 'user' ? 'var(--accent-cyan)' : 'var(--border)'}`,
                borderRadius: 8, padding: '8px 11px',
                fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5, whiteSpace: 'pre-wrap',
              }}>
                {m.content}
                {m.role === 'assistant' && m.actions && m.actions.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                    {m.actions.map(a => (
                      <button
                        key={a.to}
                        onClick={() => { setOpen(false); navigate(a.to) }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 4,
                          fontSize: 11, fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                          letterSpacing: '0.4px', padding: '3px 9px', borderRadius: 4,
                          border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.1)',
                          color: 'var(--accent-cyan)', cursor: 'pointer', whiteSpace: 'nowrap',
                        }}
                      >
                        {a.label}
                        <ArrowRight size={11} />
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-muted)', fontSize: 12 }}>
                <Loader2 size={13} className="animate-spin" /> Looking into it…
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          <div style={{ padding: 10, borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
              placeholder="Ask about alerts, cases, agents…"
              disabled={loading}
              style={{
                flex: 1, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 5,
                padding: '8px 10px', color: 'var(--text-primary)', fontSize: 13, outline: 'none',
              }}
            />
            <button
              onClick={send}
              disabled={loading || !input.trim()}
              style={{
                width: 36, borderRadius: 5, border: '1px solid var(--accent-cyan)',
                background: 'rgba(0,212,255,0.1)', color: 'var(--accent-cyan)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                cursor: loading || !input.trim() ? 'not-allowed' : 'pointer',
                opacity: loading || !input.trim() ? 0.5 : 1,
              }}
            >
              <Send size={14} />
            </button>
          </div>
        </div>
      )}
    </>
  )
}
