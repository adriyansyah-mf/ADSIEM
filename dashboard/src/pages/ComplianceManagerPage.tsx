import { useEffect, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { PageHeader } from '@/components/ui/PageHeader'
import { GlassCard } from '@/components/ui/GlassCard'

interface FrameworkSummary { id: string; name: string; control_count: number }
interface Endpoint { id: string; name: string; hostname: string; status: 'online' | 'offline' }
interface Control { id: string; title: string; check: string; status: 'met' | 'partial' | 'gap' | 'not_automated'; evidence: string }
interface FrameworkDetail {
  id: string; name: string; agent_id: string; controls: Control[]
  met_count: number; total_count: number; score_pct: number; evaluated_at: string
}
interface CustomControl {
  id: string; agent_id: string; framework_id: string | null; title: string
  description: string | null; status: 'met' | 'partial' | 'gap'; evidence: string | null
  created_at: string; updated_at: string
}
type CustomControlForm = { framework_id: string; title: string; description: string; status: 'met' | 'partial' | 'gap'; evidence: string }

const STATUS_STYLE: Record<Control['status'], { color: string; label: string }> = {
  met: { color: 'var(--accent-green)', label: 'MET' },
  partial: { color: 'var(--accent-yellow)', label: 'PARTIAL' },
  gap: { color: 'var(--accent-red)', label: 'GAP' },
  not_automated: { color: 'var(--text-muted)', label: 'NO DATA' },
}

function StatusPill({ status }: { status: Control['status'] }) {
  const s = STATUS_STYLE[status]
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 4, border: `1px solid ${s.color}`,
      background: `color-mix(in srgb, ${s.color} 12%, transparent)`, color: s.color,
      fontWeight: 700, fontSize: 10.5, letterSpacing: '0.04em', whiteSpace: 'nowrap',
    }}>
      {s.label}
    </span>
  )
}

const EMPTY_FORM: CustomControlForm = { framework_id: '', title: '', description: '', status: 'gap', evidence: '' }

const inputStyle: CSSProperties = {
  background: 'var(--bg-panel)', color: 'var(--text-primary)', border: '1px solid var(--border)',
  borderRadius: 4, padding: '6px 10px', fontSize: 13, width: '100%',
}

function CustomControlsTab({ agentId, frameworks }: { agentId: string; frameworks: FrameworkSummary[] }) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [form, setForm] = useState<CustomControlForm>(EMPTY_FORM)

  const { data: controls = [], isLoading } = useQuery<CustomControl[]>({
    queryKey: ['compliance', 'custom', agentId],
    queryFn: () => api.get(`/api/compliance/endpoints/${agentId}/custom`).then(r => r.data),
    enabled: !!agentId,
  })

  const invalidate = () => qc.invalidateQueries({ queryKey: ['compliance', 'custom', agentId] })

  const create = useMutation({
    mutationFn: (body: CustomControlForm) => api.post(`/api/compliance/endpoints/${agentId}/custom`, {
      ...body, framework_id: body.framework_id || null,
    }),
    onSuccess: () => { invalidate(); setShowForm(false); setForm(EMPTY_FORM) },
  })
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: CustomControlForm }) => api.patch(`/api/compliance/endpoints/${agentId}/custom/${id}`, {
      ...body, framework_id: body.framework_id || null,
    }),
    onSuccess: () => { invalidate(); setEditingId(null); setShowForm(false); setForm(EMPTY_FORM) },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/compliance/endpoints/${agentId}/custom/${id}`),
    onSuccess: invalidate,
  })

  const startEdit = (c: CustomControl) => {
    setEditingId(c.id)
    setForm({ framework_id: c.framework_id || '', title: c.title, description: c.description || '', status: c.status, evidence: c.evidence || '' })
    setShowForm(true)
  }
  const startCreate = () => { setEditingId(null); setForm(EMPTY_FORM); setShowForm(true) }
  const cancel = () => { setShowForm(false); setEditingId(null); setForm(EMPTY_FORM) }
  const submit = () => {
    if (!form.title.trim()) return
    if (editingId) update.mutate({ id: editingId, body: form })
    else create.mutate(form)
  }

  return (
    <GlassCard title="Custom Controls">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          Org-specific requirements this platform can't check automatically — status and evidence are attested by an analyst.
        </div>
        {!showForm && (
          <button onClick={startCreate} style={{
            background: 'var(--accent-blue)', color: '#fff', border: 'none', borderRadius: 4,
            padding: '6px 12px', fontSize: 12, fontWeight: 700, cursor: 'pointer', whiteSpace: 'nowrap',
          }}>
            + Add Control
          </button>
        )}
      </div>

      {showForm && (
        <div style={{ border: '1px solid var(--border)', borderRadius: 4, padding: 12, marginBottom: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: 8 }}>
            <input placeholder="Title" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} style={inputStyle} />
            <select value={form.framework_id} onChange={e => setForm({ ...form, framework_id: e.target.value })} style={inputStyle}>
              <option value="">No framework tag</option>
              {frameworks.map(fw => <option key={fw.id} value={fw.id}>{fw.name}</option>)}
            </select>
            <select value={form.status} onChange={e => setForm({ ...form, status: e.target.value as CustomControlForm['status'] })} style={inputStyle}>
              <option value="met">Met</option>
              <option value="partial">Partial</option>
              <option value="gap">Gap</option>
            </select>
          </div>
          <textarea placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })}
            style={{ ...inputStyle, minHeight: 50, resize: 'vertical', fontFamily: 'inherit' }} />
          <textarea placeholder="Evidence" value={form.evidence} onChange={e => setForm({ ...form, evidence: e.target.value })}
            style={{ ...inputStyle, minHeight: 50, resize: 'vertical', fontFamily: 'inherit' }} />
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button onClick={cancel} style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4, padding: '6px 12px', fontSize: 12, color: 'var(--text-secondary)', cursor: 'pointer' }}>Cancel</button>
            <button onClick={submit} disabled={!form.title.trim() || create.isPending || update.isPending} style={{
              background: 'var(--accent-blue)', color: '#fff', border: 'none', borderRadius: 4,
              padding: '6px 12px', fontSize: 12, fontWeight: 700, cursor: 'pointer',
            }}>
              {editingId ? 'Save' : 'Create'}
            </button>
          </div>
        </div>
      )}

      {isLoading && <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Loading…</div>}
      {!isLoading && controls.length === 0 && !showForm && (
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No custom controls yet for this endpoint.</div>
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        {controls.map(c => (
          <div key={c.id} style={{
            display: 'grid', gridTemplateColumns: '1fr 90px 140px', gap: 12, alignItems: 'start',
            padding: '10px 4px', borderBottom: '1px solid var(--border)',
          }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                {c.title}{c.framework_id && <span style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>[{c.framework_id}]</span>}
              </div>
              {c.description && <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2, lineHeight: 1.5 }}>{c.description}</div>}
              {c.evidence && <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.5 }}>Evidence: {c.evidence}</div>}
            </div>
            <div style={{ textAlign: 'right', paddingTop: 2 }}>
              <StatusPill status={c.status} />
            </div>
            <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
              <button onClick={() => startEdit(c)} style={{ background: 'none', border: '1px solid var(--border)', borderRadius: 4, padding: '4px 8px', fontSize: 11, color: 'var(--text-secondary)', cursor: 'pointer' }}>Edit</button>
              <button onClick={() => { if (confirm('Delete this control?')) remove.mutate(c.id) }} style={{ background: 'none', border: '1px solid var(--accent-red)', borderRadius: 4, padding: '4px 8px', fontSize: 11, color: 'var(--accent-red)', cursor: 'pointer' }}>Delete</button>
            </div>
          </div>
        ))}
      </div>
    </GlassCard>
  )
}

/** Compliance Manager — per-ENDPOINT posture (each host running the
 * siem-agent), not the ADSIEM platform itself. Maps live hygiene/FIM/fleet
 * telemetry already collected from each host to ISO 27001 / PCI-DSS / SOC 2
 * control references (see server-api/app/services/compliance.py). Internal
 * posture tracker, not a certified audit — nothing here is fabricated; a
 * control this platform can't yet evidence for a host shows "NO DATA". */
export default function ComplianceManagerPage() {
  const { data: frameworks = [] } = useQuery<FrameworkSummary[]>({
    queryKey: ['compliance', 'frameworks'],
    queryFn: () => api.get('/api/compliance/frameworks').then(r => r.data),
  })
  const { data: endpoints = [] } = useQuery<Endpoint[]>({
    queryKey: ['compliance', 'endpoints'],
    queryFn: () => api.get('/api/compliance/endpoints').then(r => r.data),
  })

  const [activeFramework, setActiveFramework] = useState<string>('iso27001')
  const [activeEndpoint, setActiveEndpoint] = useState<string>('')

  useEffect(() => {
    if (!activeEndpoint && endpoints.length > 0) setActiveEndpoint(endpoints[0].id)
  }, [endpoints, activeEndpoint])

  const { data: detail, isLoading } = useQuery<FrameworkDetail>({
    queryKey: ['compliance', 'endpoint', activeEndpoint, activeFramework],
    queryFn: () => api.get(`/api/compliance/endpoints/${activeEndpoint}/frameworks/${activeFramework}`).then(r => r.data),
    enabled: !!activeEndpoint && !!activeFramework && activeFramework !== 'custom',
  })

  const scoreColor = (pct: number) => pct >= 80 ? 'var(--accent-green)' : pct >= 50 ? 'var(--accent-yellow)' : 'var(--accent-red)'

  return (
    <div>
      <PageHeader title="Compliance Manager" subtitle="Per-endpoint posture against common control frameworks — not a certified audit." />

      {endpoints.length === 0 ? (
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>No agents enrolled yet — enroll an endpoint under Agent Fleet to see compliance posture.</div>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
            <select
              value={activeEndpoint}
              onChange={e => setActiveEndpoint(e.target.value)}
              style={{
                background: 'var(--bg-panel)', color: 'var(--text-primary)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '6px 10px', fontSize: 13, minWidth: 220,
              }}
            >
              {endpoints.map(ep => (
                <option key={ep.id} value={ep.id}>
                  {ep.name} ({ep.hostname}) — {ep.status}
                </option>
              ))}
            </select>

            <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border)', flex: 1 }}>
              {frameworks.map(fw => (
                <button
                  key={fw.id}
                  onClick={() => setActiveFramework(fw.id)}
                  style={{
                    background: 'none', border: 'none', borderBottom: activeFramework === fw.id ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    color: activeFramework === fw.id ? 'var(--text-primary)' : 'var(--text-muted)',
                    fontWeight: activeFramework === fw.id ? 700 : 500, fontSize: 13, padding: '8px 4px', cursor: 'pointer', marginBottom: -1,
                  }}
                >
                  {fw.name}
                </button>
              ))}
              <button
                onClick={() => setActiveFramework('custom')}
                style={{
                  background: 'none', border: 'none', borderBottom: activeFramework === 'custom' ? '2px solid var(--accent-blue)' : '2px solid transparent',
                  color: activeFramework === 'custom' ? 'var(--text-primary)' : 'var(--text-muted)',
                  fontWeight: activeFramework === 'custom' ? 700 : 500, fontSize: 13, padding: '8px 4px', cursor: 'pointer', marginBottom: -1,
                }}
              >
                Custom
              </button>
            </div>
          </div>

          {activeFramework === 'custom' && activeEndpoint && (
            <CustomControlsTab agentId={activeEndpoint} frameworks={frameworks} />
          )}

          {activeFramework !== 'custom' && isLoading && <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>Evaluating controls…</div>}

          {activeFramework !== 'custom' && detail && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 14 }}>
                <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-panel)', padding: '12px 14px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Score</div>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, fontWeight: 800, color: scoreColor(detail.score_pct), marginTop: 4 }}>{detail.score_pct}%</div>
                </div>
                <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-panel)', padding: '12px 14px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Controls Met</div>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 28, fontWeight: 800, marginTop: 4, fontVariantNumeric: 'tabular-nums' }}>{detail.met_count}/{detail.total_count}</div>
                </div>
                <div style={{ borderRadius: 4, border: '1px solid var(--border)', background: 'var(--bg-panel)', padding: '12px 14px' }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>Evaluated</div>
                  <div style={{ fontSize: 13, marginTop: 8, color: 'var(--text-secondary)' }}>{new Date(detail.evaluated_at).toLocaleString()}</div>
                </div>
              </div>

              <GlassCard title={detail.name}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {detail.controls.map(c => (
                    <div key={c.id} style={{
                      display: 'grid', gridTemplateColumns: '100px 1fr 90px', gap: 12, alignItems: 'start',
                      padding: '10px 4px', borderBottom: '1px solid var(--border)',
                    }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-muted)', paddingTop: 2 }}>{c.id}</div>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{c.title}</div>
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2, lineHeight: 1.5 }}>{c.evidence}</div>
                      </div>
                      <div style={{ textAlign: 'right', paddingTop: 2 }}>
                        <StatusPill status={c.status} />
                      </div>
                    </div>
                  ))}
                </div>
              </GlassCard>
            </>
          )}
        </>
      )}
    </div>
  )
}
