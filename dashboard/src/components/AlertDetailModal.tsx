import { useState } from 'react'
import type { Alert } from '@/types'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'
import { useUpdateAlert, useAddAlertNote } from '@/hooks/useAlerts'
import { format } from 'date-fns'
import { X, ShieldOff, CheckCircle } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import MarkdownNote from './MarkdownNote'

interface Props { alert: Alert; onClose: () => void }

const STATUS_OPTIONS = ['new', 'in_progress', 'resolved', 'false_positive']

export default function AlertDetailModal({ alert, onClose }: Props) {
  const qc = useQueryClient()
  const [note, setNote] = useState('')
  const [fpSuggestion, setFpSuggestion] = useState<{ entity_type: string; entity_value: string } | null>(null)
  const [suppressDone, setSuppressDone] = useState(false)

  const updateAlert = useUpdateAlert()
  const addNote = useAddAlertNote()

  const { data: usersData } = useQuery({
    queryKey: ['users-list'],
    queryFn: () => api.get('/api/users', { params: { page_size: 100 } }).then(r => r.data),
  })
  const users: Array<{ id: string; username: string }> = usersData?.items ?? []

  const createSuppression = useMutation({
    mutationFn: (body: { entity_type: string; entity_value: string; reason: string }) =>
      api.post('/api/suppressions', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['suppressions'] })
      setSuppressDone(true)
      setFpSuggestion(null)
    },
  })

  const handleStatusChange = (newStatus: string) => {
    updateAlert.mutate(
      { id: alert.id, data: { status: newStatus } },
      {
        onSuccess: (data: any) => {
          if (data?.fp_suppression_suggestion) {
            setFpSuggestion(data.fp_suppression_suggestion)
          }
        },
      }
    )
  }

  const handleAssigneeChange = (assigneeId: string) => {
    updateAlert.mutate({ id: alert.id, data: { assignee_id: assigneeId || undefined } })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-border bg-card p-6 shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold">{alert.title}</h2>
            <div className="flex gap-2 mt-1">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={20} /></button>
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm mb-4">
          <div><span className="text-muted-foreground">Source IP:</span> {alert.source_ip ?? '—'}</div>
          <div><span className="text-muted-foreground">Hostname:</span> {alert.hostname ?? '—'}</div>
          <div><span className="text-muted-foreground">Created:</span> {format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')}</div>
          <div><span className="text-muted-foreground">Group:</span> {alert.group_id}</div>
        </div>

        <div className="grid grid-cols-2 gap-3 mb-4">
          <div>
            <label className="block text-sm font-medium mb-1">Update Status</label>
            <select
              value={alert.status}
              onChange={(e) => handleStatusChange(e.target.value)}
              className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm"
            >
              {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Assignee</label>
            <select
              value={alert.assignee_id ?? ''}
              onChange={(e) => handleAssigneeChange(e.target.value)}
              className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm"
            >
              <option value="">Unassigned</option>
              {users.map((u) => (
                <option key={u.id} value={u.id}>{u.username}</option>
              ))}
            </select>
          </div>
        </div>

        {/* FP suppression suggestion */}
        {fpSuggestion && !suppressDone && (
          <div className="mb-4 p-3 rounded border border-yellow-600/40 bg-yellow-900/20 flex items-start gap-3">
            <ShieldOff size={16} className="text-yellow-400 mt-0.5 shrink-0" />
            <div className="flex-1 text-sm">
              <div className="font-medium text-yellow-300 mb-1">Create suppression rule?</div>
              <div className="text-muted-foreground text-xs mb-2">
                Suppress future alerts for{' '}
                <span className="font-mono text-yellow-200">{fpSuggestion.entity_type}: {fpSuggestion.entity_value}</span>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => createSuppression.mutate({
                    entity_type: fpSuggestion.entity_type,
                    entity_value: fpSuggestion.entity_value,
                    reason: 'Confirmed false positive',
                  })}
                  disabled={createSuppression.isPending}
                  className="px-3 py-1 rounded bg-yellow-600 text-black text-xs font-medium disabled:opacity-50"
                >
                  Yes, suppress
                </button>
                <button onClick={() => setFpSuggestion(null)}
                  className="px-3 py-1 rounded border border-border text-xs hover:bg-muted">
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}
        {suppressDone && (
          <div className="mb-4 p-2 rounded border border-emerald-600/40 bg-emerald-900/20 flex items-center gap-2 text-xs text-emerald-300">
            <CheckCircle size={13} /> Suppression rule created.
          </div>
        )}

        <div className="mb-4">
          <h3 className="text-sm font-medium mb-2">Notes ({alert.notes.length})</h3>
          <div className="space-y-2 max-h-48 overflow-auto">
            {alert.notes.map((n) => (
              <div key={n.id} className="p-3 rounded bg-muted text-sm">
                <div className="text-xs text-muted-foreground mb-1">{format(new Date(n.created_at), 'yyyy-MM-dd HH:mm')}</div>
                <MarkdownNote content={n.content} />
              </div>
            ))}
          </div>
          <div className="flex gap-2 mt-2">
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note..."
              className="flex-1 px-3 py-1.5 rounded border border-border bg-background text-sm" />
            <button
              onClick={() => { addNote.mutate({ id: alert.id, content: note }); setNote('') }}
              disabled={!note} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
              Add
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
