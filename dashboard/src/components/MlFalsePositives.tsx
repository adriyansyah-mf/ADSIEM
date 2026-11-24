import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle, Loader2, ShieldOff, Trash2 } from 'lucide-react'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

// Fleet-wide static ML false positives (server-api routes/ml_false_positives.py):
// every agent stops flagging the file with its next policy fetch.

interface MlFalsePositive {
  sha256: string
  engine: string
  path: string
  comment: string
  added_by: string | null
  added_at: string | null
}

const KEY = ['ml-false-positives']

function errorText(e: unknown, fallback: string): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export function useMlFalsePositives() {
  return useQuery<{ items: MlFalsePositive[]; limit: number }>({
    queryKey: KEY,
    queryFn: () => api.get('/api/ml-false-positives').then(r => r.data),
  })
}

function useAddMlFalsePositive() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: { sha256: string; engine?: string; path?: string; comment?: string }) =>
      api.post('/api/ml-false-positives', body).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    onError: (e) => emitToast(errorText(e, 'Could not mark the file as an ML false positive'), 'error'),
  })
}

/** On an ml_detection alert: tell every agent the model is wrong about this file. */
export function MlFalsePositiveButton({ sha256, engine, path, onMarked }: {
  sha256: string; engine?: string; path?: string; onMarked?: () => void
}) {
  const { data } = useMlFalsePositives()
  const add = useAddMlFalsePositive()
  const known = data?.items.some(i => i.sha256 === sha256.toLowerCase())
  if (known || add.isSuccess) {
    return (
      <div className="flex items-center gap-2 rounded border border-emerald-600/40 bg-emerald-900/20 p-2 text-xs text-emerald-300">
        <CheckCircle size={13} /> Marked as an ML false positive: agents stop flagging this file.
      </div>
    )
  }
  return (
    <div className="rounded border border-border p-2 text-xs">
      <div className="mb-1 flex items-center gap-1 font-medium"><ShieldOff size={13} /> Static ML false positive?</div>
      <p className="mb-2 text-muted-foreground">
        Every agent stops flagging this file (by its SHA-256) within a minute or two. The model itself is not changed.
      </p>
      <button disabled={add.isPending}
        onClick={() => add.mutate({ sha256, engine, path, comment: 'from an ml_detection alert' }, { onSuccess: () => onMarked?.() })}
        className="rounded border border-border px-2 py-1 hover:bg-muted disabled:opacity-50">
        {add.isPending ? 'Marking…' : 'Mark as false positive'}
      </button>
    </div>
  )
}

/** The list on the Policies page. */
export default function MlFalsePositives() {
  const qc = useQueryClient()
  const { data, isLoading } = useMlFalsePositives()
  const add = useAddMlFalsePositive()
  const [sha, setSha] = useState('')
  const [comment, setComment] = useState('')
  const remove = useMutation({
    mutationFn: (sha256: string) => api.delete(`/api/ml-false-positives/${sha256}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
    onError: (e) => emitToast(errorText(e, 'Could not remove it'), 'error'),
  })
  const items = data?.items ?? []
  const valid = /^[0-9a-fA-F]{64}$/.test(sha.trim())

  return (
    <section className="rounded-lg border border-border p-4 space-y-3">
      <div>
        <h2 className="text-sm font-semibold">Static ML false positives (every group)</h2>
        <p className="text-xs text-muted-foreground max-w-3xl">
          Files the ML model is wrong about. Every agent skips them with its next policy fetch, whatever its group's
          policy, so a false positive is fixed without retraining the model or releasing an agent. Mark one from its
          ML alert or paste its SHA-256. Only a superadmin or an admin of the default group can change this list.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <input value={sha} onChange={e => setSha(e.target.value)} placeholder="SHA-256" aria-label="SHA-256"
          className="min-w-0 flex-1 bg-muted border border-border rounded px-2 py-1.5 font-mono text-xs" />
        <input value={comment} onChange={e => setComment(e.target.value)} placeholder="Why (optional)" aria-label="Comment"
          className="min-w-0 flex-1 bg-muted border border-border rounded px-2 py-1.5 text-xs" />
        <button disabled={!valid || add.isPending}
          onClick={() => add.mutate({ sha256: sha.trim(), comment }, { onSuccess: () => { setSha(''); setComment('') } })}
          className="px-3 py-1.5 rounded border border-border text-sm hover:bg-muted disabled:opacity-40">Add</button>
      </div>
      {isLoading ? <Loader2 size={16} className="animate-spin" /> : items.length === 0 ? (
        <p className="text-xs text-muted-foreground">None.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-muted-foreground uppercase">
              <tr>
                <th className="text-left px-2 py-1">SHA-256</th>
                <th className="text-left px-2 py-1">File</th>
                <th className="text-left px-2 py-1">Added</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {items.map(i => (
                <tr key={i.sha256} className="border-t border-border align-top">
                  <td className="px-2 py-1 font-mono break-all">{i.sha256}</td>
                  <td className="px-2 py-1">
                    <div className="font-mono break-all">{i.path || '—'}</div>
                    {(i.engine || i.comment) && <div className="text-muted-foreground">{[i.engine, i.comment].filter(Boolean).join(' · ')}</div>}
                  </td>
                  <td className="px-2 py-1 whitespace-nowrap text-muted-foreground">
                    {i.added_at ? new Date(i.added_at).toLocaleString() : '—'}{i.added_by ? ` by ${i.added_by}` : ''}
                  </td>
                  <td className="px-2 py-1 text-right">
                    <button aria-label={`Remove ${i.sha256}`} disabled={remove.isPending} onClick={() => remove.mutate(i.sha256)}
                      className="rounded p-1 hover:bg-muted disabled:opacity-40"><Trash2 size={13} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
