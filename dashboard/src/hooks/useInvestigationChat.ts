import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

// Follow-up chat on a finished AI investigation (server-api routes/investigation_chat.py).

export type ChatActionStatus = 'proposed' | 'approved' | 'rejected' | 'executed' | 'failed' | 'expired'

export interface ChatMessage {
  id: string
  investigation_id: string
  role: 'user' | 'assistant' | 'system' | string
  content: string
  created_at: string
}

export interface ChatAction {
  id: string
  investigation_id: string
  message_id: string | null
  tool: string
  target: string | null
  params: Record<string, unknown>
  reason: string | null
  status: ChatActionStatus
  result: {
    summary?: string
    flow_status?: string | null
    flow_rows?: number | null
    flow_error?: string | null
    [key: string]: unknown
  } | null
  error: string | null
  created_at: string
}

interface Chat {
  messages: ChatMessage[]
  actions: ChatAction[]
}

const FLOW_LIVE = new Set(['scheduled', 'running'])

export function errorDetail(err: unknown, fallback: string): string {
  const d = (err as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof d === 'string' ? d : fallback
}

/** Transcript and proposed actions; polled only while a reply is being written or a live-response flow runs. */
export function useInvestigationChat(invId: string | undefined, enabled: boolean) {
  const qc = useQueryClient()
  const key = ['investigation', invId, 'chat']
  const [sendError, setSendError] = useState<string | null>(null)
  const [sending, setSending] = useState(false)

  const chat = useQuery<Chat>({
    queryKey: key,
    enabled: enabled && !!invId,
    queryFn: () => api.get(`/api/investigations/${invId}/chat`).then(r => r.data),
    refetchInterval: (q) => {
      const data = q.state.data as Chat | undefined
      const flowLive = data?.actions.some(a => a.tool === 'run_live_response' && a.status === 'executed'
        && FLOW_LIVE.has(String(a.result?.flow_status))) ?? false
      return sending || flowLive ? 3000 : false
    },
  })

  const send = useMutation({
    mutationFn: (message: string) => api.post(`/api/investigations/${invId}/chat`, { message }).then(r => r.data as Chat),
    onMutate: () => { setSending(true); setSendError(null) },
    onSuccess: () => qc.invalidateQueries({ queryKey: key }),
    onError: (e) => { setSendError(errorDetail(e, 'The assistant could not reply')); qc.invalidateQueries({ queryKey: key }) },
    onSettled: () => setSending(false),
  })

  const decide = useMutation({
    mutationFn: ({ actionId, approve, note }: { actionId: string; approve: boolean; note?: string }) =>
      api.post(`/api/investigation-chat-actions/${actionId}/decision`, { approve, note: note || null }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: key }),
    onError: (e) => { emitToast(errorDetail(e, 'Could not record the decision'), 'error'); qc.invalidateQueries({ queryKey: key }) },
  })

  return {
    messages: chat.data?.messages ?? [],
    actions: chat.data?.actions ?? [],
    isLoading: chat.isLoading,
    send, decide, sending, sendError,
  }
}
