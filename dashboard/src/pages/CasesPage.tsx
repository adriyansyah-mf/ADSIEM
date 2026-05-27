import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import { Download } from 'lucide-react'
import { useCases, useUpdateCase, useEscalateCase } from '@/hooks/useCases'
import { useAuthStore } from '@/stores/auth'
import type { Case } from '@/types'

const severityColors = {
  critical: { bg: 'rgba(255,34,68,0.15)', border: '#ff2244', color: '#ff2244' },
  high:     { bg: 'rgba(255,107,0,0.15)', border: '#ff6b00', color: '#ff6b00' },
  medium:   { bg: 'rgba(255,215,0,0.1)',  border: '#ffd700', color: '#ffd700' },
  low:      { bg: 'rgba(0,255,136,0.1)',  border: '#00ff88', color: '#00ff88' },
  info:     { bg: 'rgba(0,212,255,0.1)',  border: '#00d4ff', color: '#00d4ff' },
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = severity as keyof typeof severityColors
  const c = severityColors[s] ?? severityColors.info
  return (
    <div style={{
      width: '36px',
      height: '36px',
      borderRadius: '4px',
      border: `2px solid ${c.border}`,
      background: c.bg,
      color: c.color,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Rajdhani, sans-serif',
      fontWeight: 700,
      fontSize: '11px',
      letterSpacing: '0.5px',
      textTransform: 'uppercase',
      flexShrink: 0,
      boxShadow: `0 0 8px ${c.border}44`,
    }}>
      {severity.slice(0, 3).toUpperCase()}
    </div>
  )
}

const STATUS_TABS = ['All', 'Open', 'In Review', 'Escalated', 'Resolved', 'Closed']
const TAB_TO_API: Record<string, string | undefined> = {
  'All': undefined,
  'Open': 'open',
  'In Review': 'in_review',
  'Escalated': 'escalated',
  'Resolved': 'resolved',
  'Closed': 'closed',
}

function CaseCard({ c }: { c: Case }) {
  const navigate = useNavigate()
  const { user } = useAuthStore()
  const update = useUpdateCase(c.id)
  const escalate = useEscalateCase(c.id)
  const sourceIp = c.ioc_data?.source_ip as string | undefined

  const statusColor = {
    open: 'var(--accent-cyan)',
    in_review: 'var(--accent-yellow)',
    escalated: 'var(--accent-orange)',
    resolved: 'var(--accent-green)',
    closed: 'var(--text-muted)',
  }[c.status] ?? 'var(--text-muted)'

  return (
    <div style={{
      borderRadius: '6px',
      border: '1px solid var(--border)',
      background: 'var(--bg-card)',
      padding: '14px',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px',
      cursor: 'pointer',
      transition: 'border-color 0.15s',
    }}
    onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-glow)')}
    onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
    onClick={() => navigate(`/cases/${c.id}`)}
    >
      {/* Top row */}
      <div style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
        <SeverityBadge severity={c.severity} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            {c.created_by_ai && <span title="AI Generated" style={{ fontSize: '14px' }}>🤖</span>}
            <span style={{
              fontFamily: 'Exo 2, sans-serif',
              fontWeight: 700,
              fontSize: '14px',
              color: 'var(--text-primary)',
            }}>
              {c.title}
            </span>
          </div>
          {c.ai_reasoning && (
            <div style={{
              fontFamily: 'Exo 2, sans-serif',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              overflow: 'hidden',
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
            }}>
              {c.ai_reasoning}
            </div>
          )}
          {sourceIp && (
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-cyan)', marginTop: '3px' }}>
              SRC: {sourceIp}
            </div>
          )}
        </div>
        <div style={{ flexShrink: 0, textAlign: 'right' }}>
          <span style={{
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: '3px',
            border: `1px solid ${statusColor}`,
            color: statusColor,
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: '0.5px',
            textTransform: 'uppercase',
            background: `${statusColor}18`,
          }}>
            {c.status.replace('_', ' ')}
          </span>
          {c.escalated_at && (
            <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--accent-orange)', marginTop: '3px' }}>
              ESC {format(new Date(c.escalated_at), 'MM-dd HH:mm')}
            </div>
          )}
        </div>
      </div>

      {/* Bottom row */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        paddingTop: '8px',
        borderTop: '1px solid var(--border)',
      }}
      onClick={e => e.stopPropagation()}
      >
        <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
          {format(new Date(c.created_at), 'yyyy-MM-dd HH:mm')}
        </span>
        {c.alert_id && (
          <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '10px', color: 'var(--text-muted)' }}>
            ALT:{c.alert_id.slice(0, 8)}
          </span>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '6px' }}>
          <ActionBtn label="View Detail" onClick={() => navigate(`/cases/${c.id}`)} color="var(--accent-cyan)" />
          {user?.id && (
            <ActionBtn
              label="Assign to Me"
              onClick={() => update.mutate({ assignee_id: user.id })}
              color="var(--accent-green)"
              loading={update.isPending}
            />
          )}
          {c.status !== 'escalated' && c.status !== 'resolved' && c.status !== 'closed' && (
            <ActionBtn
              label="Escalate"
              onClick={() => escalate.mutate()}
              color="var(--accent-orange)"
              loading={escalate.isPending}
            />
          )}
          {c.status !== 'closed' && (
            <ActionBtn
              label="Close"
              onClick={() => update.mutate({ status: 'closed' })}
              color="var(--text-muted)"
              loading={update.isPending}
            />
          )}
        </div>
      </div>
    </div>
  )
}

function ActionBtn({ label, onClick, color, loading }: { label: string; onClick: () => void; color: string; loading?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      style={{
        padding: '3px 10px',
        borderRadius: '3px',
        border: `1px solid ${color}`,
        background: 'transparent',
        color,
        fontFamily: 'Rajdhani, sans-serif',
        fontWeight: 700,
        fontSize: '10px',
        letterSpacing: '0.5px',
        cursor: loading ? 'wait' : 'pointer',
        opacity: loading ? 0.6 : 1,
        transition: 'all 0.15s',
      }}
    >
      {loading ? '...' : label}
    </button>
  )
}

async function downloadFile(url: string, filename: string) {
  let href: string | null = null
  try {
    const res = await import('@/api/client').then(m => m.api.get(url, { responseType: 'blob' }))
    href = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = href
    a.download = filename
    a.click()
  } catch {
    alert('Export failed. Please try again.')
  } finally {
    if (href) URL.revokeObjectURL(href)
  }
}

export default function CasesPage() {
  const [activeTab, setActiveTab] = useState('All')
  const [page] = useState(1)
  const statusFilter = TAB_TO_API[activeTab]
  const { data, isLoading } = useCases(page, statusFilter)

  const cases: Case[] = data?.items ?? []
  const total = data?.total ?? 0

  const openCount = cases.filter(c => c.status === 'open').length
  const escalatedCount = cases.filter(c => c.status === 'escalated').length

  return (
    <div>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div>
          <h1 style={{
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 700,
            fontSize: '22px',
            letterSpacing: '2px',
            color: 'var(--text-primary)',
            margin: 0,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}>
            <span>🎫</span> SECURITY CASES
          </h1>
          <div style={{ display: 'flex', gap: '16px', marginTop: '6px' }}>
            <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-cyan)' }}>
              OPEN: {openCount}
            </span>
            <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--accent-orange)' }}>
              ESCALATED: {escalatedCount}
            </span>
            <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-muted)' }}>
              TOTAL: {total}
            </span>
          </div>
        </div>
        <button onClick={() => downloadFile('/api/export/cases/csv', 'cases.csv')}
          className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
          <Download size={13} /> CSV
        </button>
      </div>

      {/* Filter tabs */}
      <div style={{
        display: 'flex',
        gap: '4px',
        marginBottom: '16px',
        borderBottom: '1px solid var(--border)',
        paddingBottom: '0',
      }}>
        {STATUS_TABS.map(tab => {
          const isActive = activeTab === tab
          return (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: '7px 16px',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                background: 'transparent',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontFamily: 'Rajdhani, sans-serif',
                fontWeight: 700,
                fontSize: '12px',
                letterSpacing: '1px',
                cursor: 'pointer',
                transition: 'all 0.15s',
              }}
            >
              {tab.toUpperCase()}
            </button>
          )
        })}
      </div>

      {/* Cases list */}
      {isLoading ? (
        <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>
          LOADING CASES...
        </div>
      ) : cases.length === 0 ? (
        <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>
          NO CASES FOUND
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {cases.map(c => <CaseCard key={c.id} c={c} />)}
        </div>
      )}
    </div>
  )
}
