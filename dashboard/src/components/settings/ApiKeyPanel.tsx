import { useState } from 'react'
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from '@/hooks/useApiKeys'
import type { ApiKeyCreated } from '@/types'

const font = { fontFamily: 'Public Sans, sans-serif' }

function StatusBadge({ revokedAt, expiresAt }: { revokedAt: string | null; expiresAt: string | null }) {
  const isRevoked = revokedAt !== null
  const isExpired = !isRevoked && expiresAt !== null && new Date(expiresAt) < new Date()
  const label = isRevoked ? 'REVOKED' : isExpired ? 'EXPIRED' : 'ACTIVE'
  const color = isRevoked || isExpired ? 'var(--text-muted)' : 'var(--accent-green)'
  const bg = isRevoked || isExpired ? 'rgba(100,116,139,0.15)' : 'rgba(46,212,122,0.15)'
  return (
    <span style={{ ...font, fontSize: 10, padding: '2px 7px', borderRadius: 3, background: bg, color }}>
      {label}
    </span>
  )
}

function CreatedKeyReveal({ created, onDismiss }: { created: ApiKeyCreated; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.secret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // clipboard API unavailable — the value is still selectable in the box below
    }
  }

  return (
    <div style={{ padding: 14, marginBottom: 14, background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.35)', borderRadius: 6 }}>
      <div style={{ ...font, fontSize: 12, fontWeight: 700, color: '#f87171', marginBottom: 6 }}>
        ⚠ This secret is shown once and cannot be retrieved again — copy it now.
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <code style={{
          ...font, fontSize: 12, flex: 1, padding: '8px 10px', background: 'var(--bg-base)',
          border: '1px solid var(--border)', borderRadius: 4, color: 'var(--text-primary)',
          overflowX: 'auto', whiteSpace: 'nowrap',
        }}>
          {created.secret}
        </code>
        <button onClick={copy} style={{
          ...font, padding: '7px 14px', background: copied ? 'rgba(46,212,122,0.1)' : 'rgba(44,110,142,0.1)',
          border: `1px solid ${copied ? 'var(--accent-green)' : 'var(--accent-blue)'}`,
          color: copied ? 'var(--accent-green)' : 'var(--accent-blue)',
          borderRadius: 4, cursor: 'pointer', fontWeight: 700, fontSize: 12, whiteSpace: 'nowrap',
        }}>
          {copied ? 'COPIED' : 'COPY'}
        </button>
      </div>
      <button onClick={onDismiss} style={{
        ...font, marginTop: 10, padding: '6px 14px', background: 'none', border: '1px solid var(--border)',
        color: 'var(--text-muted)', borderRadius: 4, cursor: 'pointer', fontSize: 12,
      }}>
        Done — I've saved it
      </button>
    </div>
  )
}

function CreateKeyForm({ onCreated, onCancel }: { onCreated: (k: ApiKeyCreated) => void; onCancel: () => void }) {
  const [name, setName] = useState('')
  const [permissions, setPermissions] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [error, setError] = useState('')
  const createKey = useCreateApiKey()

  const submit = async () => {
    setError('')
    const perms = permissions.split(',').map(p => p.trim()).filter(Boolean)
    if (!name.trim()) {
      setError('Name is required.')
      return
    }
    try {
      const created = await createKey.mutateAsync({
        name: name.trim(),
        permissions: perms,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      })
      onCreated(created)
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to create API key.')
    }
  }

  return (
    <div style={{ padding: 14, marginBottom: 14, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 6, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="Key name (e.g. ci-pipeline)"
          style={{ ...font, flex: '1 1 200px', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 10px', color: 'var(--text-primary)', fontSize: 12 }}
        />
        <input
          value={permissions}
          onChange={e => setPermissions(e.target.value)}
          placeholder="Permissions, comma-separated (e.g. alerts:read, logs:read)"
          style={{ ...font, flex: '2 1 260px', background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 10px', color: 'var(--text-primary)', fontSize: 12 }}
        />
        <input
          type="date"
          value={expiresAt}
          onChange={e => setExpiresAt(e.target.value)}
          title="Expiry date (optional)"
          style={{ ...font, background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 10px', color: 'var(--text-primary)', fontSize: 12 }}
        />
      </div>
      {error && <div style={{ ...font, fontSize: 11, color: 'var(--accent-red)' }}>{error}</div>}
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={submit} disabled={createKey.isPending} style={{
          ...font, padding: '7px 16px', background: 'rgba(44,110,142,0.1)', border: '1px solid var(--accent-blue)',
          color: 'var(--accent-blue)', borderRadius: 4, cursor: createKey.isPending ? 'not-allowed' : 'pointer',
          fontWeight: 700, fontSize: 12, opacity: createKey.isPending ? 0.6 : 1,
        }}>
          {createKey.isPending ? 'CREATING…' : 'CREATE'}
        </button>
        <button onClick={onCancel} style={{
          ...font, padding: '7px 16px', background: 'none', border: '1px solid var(--border)',
          color: 'var(--text-muted)', borderRadius: 4, cursor: 'pointer', fontSize: 12,
        }}>
          Cancel
        </button>
      </div>
    </div>
  )
}

export function ApiKeyPanel() {
  const { data: keys, isLoading, error } = useApiKeys()
  const revokeKey = useRevokeApiKey()
  const [showForm, setShowForm] = useState(false)
  const [revealed, setRevealed] = useState<ApiKeyCreated | null>(null)

  return (
    <div style={{ padding: '20px', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ ...font, fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>
            API Keys
          </div>
          <span style={{ ...font, fontSize: 10, padding: '2px 7px', borderRadius: 3, background: 'rgba(100,116,139,0.15)', color: 'var(--text-muted)' }}>
            {keys?.length ?? 0}
          </span>
        </div>
        {!showForm && !revealed && (
          <button onClick={() => setShowForm(true)} style={{
            ...font, padding: '7px 16px', background: 'rgba(44,110,142,0.1)', border: '1px solid var(--accent-blue)',
            color: 'var(--accent-blue)', borderRadius: 4, cursor: 'pointer', fontWeight: 700, fontSize: 12, letterSpacing: 0.5,
          }}>
            + CREATE KEY
          </button>
        )}
      </div>
      <div style={{ ...font, fontSize: 11, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.5 }}>
        Scoped service credentials for scripted or integration access. Each key can only be granted
        permissions its creator already holds, and its secret is shown exactly once at creation.
      </div>

      {revealed && (
        <CreatedKeyReveal created={revealed} onDismiss={() => { setRevealed(null); setShowForm(false) }} />
      )}

      {showForm && !revealed && (
        <CreateKeyForm
          onCreated={(created) => setRevealed(created)}
          onCancel={() => setShowForm(false)}
        />
      )}

      {isLoading && (
        <div style={{ ...font, fontSize: 12, color: 'var(--text-muted)', padding: '16px 0' }}>Loading API keys…</div>
      )}
      {error && (
        <div style={{ ...font, fontSize: 12, color: 'var(--accent-red)', padding: '16px 0' }}>
          Failed to load API keys.
        </div>
      )}
      {!isLoading && !error && keys?.length === 0 && (
        <div style={{ ...font, fontSize: 12, color: 'var(--text-muted)', padding: '16px 0' }}>
          No API keys yet.
        </div>
      )}

      {!isLoading && keys && keys.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 640 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['Name', 'Prefix', 'Permissions', 'Group', 'Expires', 'Last Used', 'Status', ''].map(h => (
                  <th key={h} style={{ ...font, textAlign: 'left', fontSize: 10, color: 'var(--text-muted)', padding: '8px 6px', letterSpacing: 0.5 }}>
                    {h.toUpperCase()}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ ...font, fontSize: 12, color: 'var(--text-primary)', padding: '8px 6px' }}>{k.name}</td>
                  <td style={{ ...font, fontSize: 11, color: 'var(--text-muted)', padding: '8px 6px', fontFamily: 'monospace' }}>{k.prefix}</td>
                  <td style={{ ...font, fontSize: 11, color: 'var(--text-secondary)', padding: '8px 6px' }}>
                    {k.permissions.length > 0 ? k.permissions.join(', ') : '—'}
                  </td>
                  <td style={{ ...font, fontSize: 11, color: 'var(--text-secondary)', padding: '8px 6px' }}>{k.group_id}</td>
                  <td style={{ ...font, fontSize: 11, color: 'var(--text-muted)', padding: '8px 6px' }}>
                    {k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never'}
                  </td>
                  <td style={{ ...font, fontSize: 11, color: 'var(--text-muted)', padding: '8px 6px' }}>
                    {k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'Never'}
                  </td>
                  <td style={{ padding: '8px 6px' }}>
                    <StatusBadge revokedAt={k.revoked_at} expiresAt={k.expires_at} />
                  </td>
                  <td style={{ padding: '8px 6px' }}>
                    {!k.revoked_at && (
                      <button
                        onClick={() => revokeKey.mutate(k.id)}
                        disabled={revokeKey.isPending}
                        style={{
                          ...font, padding: '5px 10px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.4)',
                          color: '#f87171', borderRadius: 4, cursor: revokeKey.isPending ? 'not-allowed' : 'pointer', fontSize: 11, fontWeight: 700,
                        }}>
                        REVOKE
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
