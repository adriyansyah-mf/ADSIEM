import { useRef, useState } from 'react'
import { format } from 'date-fns'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, FileText, Loader2 } from 'lucide-react'
import { api } from '@/api/client'

interface SopDocument {
  id: string
  filename: string
  content_type: string
  status: 'pending' | 'indexed' | 'failed'
  uploaded_by: string | null
  created_at: string
}

const statusColor: Record<string, string> = {
  pending:  'var(--accent-yellow)',
  indexed:  'var(--accent-green)',
  failed:   'var(--accent-red)',
}

export default function SopPage() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  const { data: docs = [], isLoading } = useQuery<SopDocument[]>({
    queryKey: ['sop-documents'],
    queryFn: () => api.get('/api/sop-documents').then(r => r.data),
    refetchInterval: 5000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/api/sop-documents/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sop-documents'] }),
  })

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setError('')
    setUploading(true)
    const form = new FormData()
    form.append('file', file)
    try {
      await api.post('/api/sop-documents', form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      qc.invalidateQueries({ queryKey: ['sop-documents'] })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Upload failed')
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <h1 style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 700, fontSize: '20px', color: 'var(--text-primary)', margin: 0 }}>
          SOP Documents
        </h1>
        <div>
          <input ref={fileRef} type="file" accept=".pdf,.docx,.txt" style={{ display: 'none' }} onChange={handleUpload} />
          <button
            onClick={() => fileRef.current?.click()}
            disabled={uploading}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: '6px',
              padding: '8px 16px', borderRadius: '4px',
              border: '1px solid var(--accent-cyan)', background: 'rgba(0,212,255,0.12)',
              color: 'var(--accent-cyan)', fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 700, fontSize: '12px', letterSpacing: '1px',
              cursor: uploading ? 'wait' : 'pointer', opacity: uploading ? 0.6 : 1,
            }}
          >
            {uploading ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}
            UPLOAD SOP
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', borderRadius: '4px', background: 'rgba(255,34,68,0.1)', border: '1px solid rgba(255,34,68,0.3)', color: 'var(--accent-red)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '12px' }}>
        Upload PDF, DOCX, or TXT files (max 10 MB). Uploaded SOPs are chunked, embedded, and used by the AI analyst when triaging alerts.
      </div>

      {isLoading ? (
        <div style={{ color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px' }}>Loading...</div>
      ) : docs.length === 0 ? (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', border: '1px dashed var(--border)', borderRadius: '6px' }}>
          No SOP documents uploaded yet. Upload your Incident Handling SOP to improve AI triage accuracy.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {docs.map(doc => (
            <div key={doc.id} style={{
              display: 'flex', alignItems: 'center', gap: '12px',
              padding: '12px 14px', borderRadius: '6px',
              border: '1px solid var(--border)', background: 'var(--bg-card)',
            }}>
              <FileText size={16} style={{ color: 'var(--accent-cyan)', flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: 'Exo 2, sans-serif', fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {doc.filename}
                </div>
                <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {format(new Date(doc.created_at), 'yyyy-MM-dd HH:mm')} · {doc.content_type.split('/').pop()?.toUpperCase()}
                </div>
              </div>
              <span style={{
                padding: '2px 8px', borderRadius: '3px',
                border: `1px solid ${statusColor[doc.status] ?? 'var(--text-muted)'}44`,
                background: `${statusColor[doc.status] ?? 'var(--text-muted)'}18`,
                color: statusColor[doc.status] ?? 'var(--text-muted)',
                fontFamily: 'Rajdhani, sans-serif', fontWeight: 700,
                fontSize: '10px', letterSpacing: '1px', textTransform: 'uppercase' as const,
              }}>
                {doc.status}
              </span>
              <button
                onClick={() => deleteMutation.mutate(doc.id)}
                disabled={deleteMutation.isPending}
                style={{
                  padding: '4px 8px', borderRadius: '4px', border: '1px solid rgba(255,34,68,0.3)',
                  background: 'rgba(255,34,68,0.08)', color: 'var(--accent-red)',
                  cursor: 'pointer', display: 'flex', alignItems: 'center',
                }}
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
