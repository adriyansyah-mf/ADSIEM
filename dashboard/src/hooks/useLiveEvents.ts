import { useEffect, useRef, useState } from 'react'
import { useAuthStore } from '@/stores/auth'

export interface LiveEvent {
  id: string
  agent_id?: string | null
  log_type?: string | null
  event_action?: string | null
  event_category?: string | null
  source_ip?: string | null
  user_name?: string | null
  created_at: string
  fields: Record<string, unknown>
}

type Status = 'connecting' | 'open' | 'error' | 'closed'

export function useLiveEvents(enabled: boolean, max = 200) {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [status, setStatus] = useState<Status>('closed')
  const [received, setReceived] = useState(0)
  const token = useAuthStore(s => s.accessToken)
  const esRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!enabled || !token) {
      setStatus('closed')
      return
    }

    const base = import.meta.env.VITE_API_URL || ''
    const url = `${base}/api/stream/events?topics=events&token=${encodeURIComponent(token)}`
    const es = new EventSource(url)
    esRef.current = es
    setStatus('connecting')

    es.addEventListener('ready', () => setStatus('open'))

    es.addEventListener('events', (e: MessageEvent) => {
      try {
        const evt = JSON.parse(e.data) as LiveEvent
        setEvents(prev => {
          const next = [evt, ...prev]
          return next.length > max ? next.slice(0, max) : next
        })
        setReceived(n => n + 1)
      } catch {
        return
      }
    })

    es.onerror = () => setStatus('error')

    return () => {
      es.close()
      esRef.current = null
      setStatus('closed')
    }
  }, [enabled, token, max])

  const clear = () => {
    setEvents([])
    setReceived(0)
  }

  return { events, status, received, clear }
}
