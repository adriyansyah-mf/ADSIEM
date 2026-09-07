import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { format } from 'date-fns'
import { useCases, useUpdateCase, useEscalateCase } from '@/hooks/useCases'
import { useAuthStore } from '@/stores/auth'
import { TimeRangeFilter, type TimeRange } from '@/components/TimeRangeSelect'
import { PageHeader } from '@/components/ui/PageHeader'
import { BrainCircuit, BriefcaseBusiness } from 'lucide-react'
import type { Case } from '@/types'

const filterInputStyle: React.CSSProperties = {
  padding: '6px 10px',
  borderRadius: '4px',
  border: '1px solid var(--border)',
  background: 'var(--bg-card)',
  color: 'var(--text-primary)',
  fontFamily: 'Public Sans, sans-serif',
  fontSize: '12px',
}

// Colors reference the same shared tokens as components/SeverityBadge.tsx so the
// two badge shapes (this fixed-size tile vs. the inline pill used elsewhere) never
// drift out of sync on what "critical"/"high"/etc. actually render as.
const severityColors = {
  critical: 'var(--accent-red)',
  high:     'var(--accent-orange)',
  medium:   'var(--accent-yellow)',
  low:      'var(--accent-green)',
  info:     'var(--accent-blue)',
}

/** Fixed-size severity tile for the case-card leading edge — visually distinct from
 * the shared inline SeverityBadge pill, so it keeps its own name and abbreviation. */
function SeverityTile({ severity }: { severity: string }) {
  const s = severity as keyof typeof severityColors
  const c = severityColors[s] ?? severityColors.info
  return (
    <div
      title={severity}
      style={{
        width: '36px',
        height: '36px',
        borderRadius: '4px',
        border: `2px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'Public Sans, sans-serif',
        fontWeight: 700,
        fontSize: '11px',
        letterSpacing: '0.5px',
        textTransform: 'uppercase',
        flexShrink: 0,
        boxShadow: `0 0 8px color-mix(in srgb, ${c} 27%, transparent)`,
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
    open: 'var(--accent-blue)',
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
        <SeverityTile severity={c.severity} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            {c.created_by_ai && <BrainCircuit aria-label="AI generated" size={14} />}
            <span style={{
              fontFamily: 'Public Sans, sans-serif',
              fontWeight: 700,
              fontSize: '14px',
              color: 'var(--text-primary)',
            }}>
              {c.title}
            </span>
          </div>
          {c.ai_reasoning && (
            <div style={{
              fontFamily: 'Public Sans, sans-serif',
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
            <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '11px', color: 'var(--accent-blue)', marginTop: '3px' }}>
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
            fontFamily: 'Public Sans, sans-serif',
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: '0.5px',
            textTransform: 'uppercase',
            background: `${statusColor}18`,
          }}>
            {c.status.replace('_', ' ')}
          </span>
          {c.escalated_at && (
            <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--accent-orange)', marginTop: '3px' }}>
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
        <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--text-muted)' }}>
          {format(new Date(c.created_at), 'yyyy-MM-dd HH:mm')}
        </span>
        {c.alert_id && (
          <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '10px', color: 'var(--text-muted)' }}>
            ALT:{c.alert_id.slice(0, 8)}
          </span>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '6px' }}>
          <ActionBtn label="View Detail" onClick={() => navigate(`/cases/${c.id}`)} color="var(--accent-blue)" />
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
        fontFamily: 'Public Sans, sans-serif',
        fontWeight: 700,
        fontSize: '10px',
        letterSpacing: '0.5px',
        cursor: loading ? 'wait' : 'pointer',
        opacity: loading ? 0.6 : 1,
        transition: 'opacity 0.15s',
      }}
    >
      {loading ? '...' : label}
    </button>
  )
}

const PAGE_SIZE = 25

export default function CasesPage() {
  const [activeTab, setActiveTab] = useState('All')
  const [page, setPage] = useState(1)
  const statusFilter = TAB_TO_API[activeTab]
  const [severityFilter, setSeverityFilter] = useState('')
  const [hostnameFilter, setHostnameFilter] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [searchFilter, setSearchFilter] = useState('')
  const [timeFilter, setTimeFilter] = useState<TimeRange>({})

  useEffect(() => {
    const t = setTimeout(() => { setSearchFilter(searchInput); setPage(1) }, 400)
    return () => clearTimeout(t)
  }, [searchInput])

  const { data, isLoading } = useCases(page, {
    status: statusFilter,
    severity: severityFilter || undefined,
    hostname: hostnameFilter || undefined,
    search: searchFilter || undefined,
    start_time: timeFilter.start_time,
    end_time: timeFilter.end_time,
  })

  const cases: Case[] = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const switchTab = (tab: string) => {
    setActiveTab(tab)
    setPage(1)
  }

  const openCount = cases.filter(c => c.status === 'open').length
  const escalatedCount = cases.filter(c => c.status === 'escalated').length

  return (
    <div>
      {/* Page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <PageHeader
          title={<><BriefcaseBusiness aria-hidden="true" size={20} /> Security cases</>}
          className="!mb-0"
          subtitle={<span style={{ display: 'flex', flexWrap: 'wrap', gap: '16px' }}>
            <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '11px', color: 'var(--accent-blue)' }}>
              OPEN: {openCount}
            </span>
            <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '11px', color: 'var(--accent-orange)' }}>
              ESCALATED: {escalatedCount}
            </span>
            <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '11px', color: 'var(--text-muted)' }}>
              TOTAL: {total}
            </span>
          </span>}
        />
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
              onClick={() => switchTab(tab)}
              style={{
                padding: '7px 16px',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent-blue)' : '2px solid transparent',
                background: 'transparent',
                color: isActive ? 'var(--accent-blue)' : 'var(--text-secondary)',
                fontFamily: 'Public Sans, sans-serif',
                fontWeight: 700,
                fontSize: '12px',
                letterSpacing: '1px',
                cursor: 'pointer',
                transition: 'color 0.15s, border-bottom-color 0.15s',
              }}
            >
              {tab.toUpperCase()}
            </button>
          )
        })}
      </div>

      {/* Filter bar */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px' }}>
        <input
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          placeholder="Search title/description…"
          style={{ ...filterInputStyle, width: '220px' }}
        />
        <input
          value={hostnameFilter}
          onChange={e => { setHostnameFilter(e.target.value); setPage(1) }}
          placeholder="Hostname…"
          style={{ ...filterInputStyle, width: '150px' }}
        />
        <select
          value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value); setPage(1) }}
          style={filterInputStyle}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <TimeRangeFilter
          value={timeFilter}
          onChange={r => { setTimeFilter(r); setPage(1) }}
          selectStyle={filterInputStyle}
          inputStyle={filterInputStyle}
        />
      </div>

      {/* Cases list */}
      {isLoading ? (
        <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '12px', color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>
          LOADING CASES...
        </div>
      ) : cases.length === 0 ? (
        <div style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '12px', color: 'var(--text-muted)', padding: '24px', textAlign: 'center' }}>
          NO CASES FOUND
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {cases.map(c => <CaseCard key={c.id} c={c} />)}
        </div>
      )}

      {!isLoading && total > PAGE_SIZE && (
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '14px',
          marginTop: '18px', padding: '10px 0',
        }}>
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page <= 1}
            style={{
              padding: '6px 14px', borderRadius: '4px', border: '1px solid var(--border)',
              background: 'transparent', color: page <= 1 ? 'var(--text-muted)' : 'var(--text-secondary)',
              fontFamily: 'Public Sans, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px',
              cursor: page <= 1 ? 'not-allowed' : 'pointer',
            }}
          >
            ← PREV
          </button>
          <span style={{ fontFamily: 'Public Sans, sans-serif', fontSize: '11px', color: 'var(--text-muted)' }}>
            PAGE {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            style={{
              padding: '6px 14px', borderRadius: '4px', border: '1px solid var(--border)',
              background: 'transparent', color: page >= totalPages ? 'var(--text-muted)' : 'var(--text-secondary)',
              fontFamily: 'Public Sans, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px',
              cursor: page >= totalPages ? 'not-allowed' : 'pointer',
            }}
          >
            NEXT →
          </button>
        </div>
      )}
    </div>
  )
}
