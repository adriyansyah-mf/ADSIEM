import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useAgent, useFirewallRules, useAddFirewallRule, useDeleteFirewallRule } from '@/hooks/useAgents'
import { Trash2, Plus, ArrowLeft, Shield } from 'lucide-react'

const ACTIONS = ['block', 'allow']
const PROTOS = ['any', 'tcp', 'udp', 'icmp']
const DIRECTIONS = ['both', 'inbound', 'outbound']

export default function FirewallPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: agent } = useAgent(id!)
  const { data: rules, isLoading } = useFirewallRules(id!)
  const addRule = useAddFirewallRule(id!)
  const deleteRule = useDeleteFirewallRule(id!)

  const [cidr, setCidr] = useState('')
  const [action, setAction] = useState('block')
  const [proto, setProto] = useState('any')
  const [port, setPort] = useState('0')
  const [direction, setDirection] = useState('both')
  const [ttl, setTtl] = useState('600')
  const [reason, setReason] = useState('')
  const [error, setError] = useState('')

  const handleAdd = () => {
    if (!cidr.trim()) { setError('CIDR or IP is required'); return }
    const portNum = Number(port) || 0
    if (portNum > 0 && proto !== 'tcp' && proto !== 'udp') {
      setError('A port requires proto tcp or udp')
      return
    }
    setError('')
    addRule.mutate(
      {
        action,
        cidr: cidr.trim(),
        proto,
        port: portNum,
        direction,
        ttl_seconds: Number(ttl) || 0,
        reason: reason.trim(),
        is_enabled: true,
      },
      {
        onSuccess: () => { setCidr(''); setReason(''); setPort('0') },
        onError: (e: unknown) => {
          const msg = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
          setError(typeof msg === 'string' ? msg : 'Request rejected')
        },
      },
    )
  }

  return (
    <div style={{ padding: '20px 24px', maxWidth: 1200, margin: '0 auto' }}>
      <button
        onClick={() => navigate(`/agents/${id}/sources`)}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, background: 'none',
          border: 'none', color: 'var(--text-muted)', cursor: 'pointer',
          marginBottom: 16, fontSize: 13,
        }}
      >
        <ArrowLeft size={14} /> back to {agent?.hostname ?? 'agent'}
      </button>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <Shield size={20} color="var(--accent-cyan)" />
        <h1 style={{ margin: 0, fontSize: 20, letterSpacing: '0.5px' }}>Firewall Gate</h1>
      </div>
      <p style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 0, marginBottom: 20 }}>
        Rules are pushed on the next heartbeat. The agent refuses anything that would cover
        its own management path (the SIEM server, its subnet, the default gateway, or loopback).
      </p>

      <div style={{
        border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-card)',
        padding: 16, marginBottom: 20,
      }}>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 1fr', gap: 8, marginBottom: 10 }}>
          <input
            placeholder="203.0.113.5 or 10.0.0.0/24"
            value={cidr}
            onChange={e => setCidr(e.target.value)}
            style={inputStyle}
          />
          <select value={action} onChange={e => setAction(e.target.value)} style={inputStyle}>
            {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <select value={proto} onChange={e => setProto(e.target.value)} style={inputStyle}>
            {PROTOS.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          <input placeholder="port" value={port} onChange={e => setPort(e.target.value)} style={inputStyle} />
          <select value={direction} onChange={e => setDirection(e.target.value)} style={inputStyle}>
            {DIRECTIONS.map(d => <option key={d} value={d}>{d}</option>)}
          </select>
          <input placeholder="ttl sec" value={ttl} onChange={e => setTtl(e.target.value)} style={inputStyle} />
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            placeholder="reason (shows in the audit log)"
            value={reason}
            onChange={e => setReason(e.target.value)}
            style={{ ...inputStyle, flex: 1 }}
          />
          <button
            onClick={handleAdd}
            disabled={addRule.isPending}
            style={{
              display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px',
              background: 'var(--accent-cyan)', color: '#001018', border: 'none',
              borderRadius: 6, fontWeight: 600, cursor: 'pointer',
            }}
          >
            <Plus size={14} /> Add rule
          </button>
        </div>
        {error && <p style={{ color: '#ff5c5c', fontSize: 12, marginBottom: 0 }}>{error}</p>}
      </div>

      {isLoading ? (
        <p style={{ color: 'var(--text-muted)' }}>Loading…</p>
      ) : !rules?.length ? (
        <div style={{
          border: '1px dashed var(--border)', borderRadius: 8, padding: 28,
          textAlign: 'center', color: 'var(--text-muted)', fontSize: 13,
        }}>
          No firewall rules for this agent. It still runs local detection and blocks
          brute-force sources on its own.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: 'var(--bg-panel)' }}>
              {['CIDR', 'ACTION', 'PROTO', 'PORT', 'DIRECTION', 'TTL', 'REASON', ''].map(h => (
                <th key={h} style={thStyle}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ ...tdStyle, fontFamily: 'Share Tech Mono, monospace' }}>{r.cidr}</td>
                <td style={{ ...tdStyle, color: r.action === 'block' ? '#ff5c5c' : '#3ddc84' }}>
                  {r.action.toUpperCase()}
                </td>
                <td style={tdStyle}>{r.proto}</td>
                <td style={tdStyle}>{r.port || '—'}</td>
                <td style={tdStyle}>{r.direction}</td>
                <td style={tdStyle}>{r.ttl_seconds ? `${r.ttl_seconds}s` : 'permanent'}</td>
                <td style={{ ...tdStyle, color: 'var(--text-muted)' }}>{r.reason || '—'}</td>
                <td style={{ ...tdStyle, textAlign: 'right' }}>
                  <button
                    onClick={() => deleteRule.mutate(r.id)}
                    title="remove rule"
                    style={{ background: 'none', border: 'none', color: '#ff5c5c', cursor: 'pointer' }}
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const inputStyle: React.CSSProperties = {
  padding: '8px 10px',
  background: 'var(--bg-panel)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  color: 'var(--text)',
  fontSize: 13,
}

const thStyle: React.CSSProperties = {
  padding: '8px 12px',
  textAlign: 'left',
  fontSize: 10,
  fontWeight: 700,
  letterSpacing: '1.5px',
  color: 'var(--text-muted)',
  borderBottom: '1px solid var(--border)',
  whiteSpace: 'nowrap',
}

const tdStyle: React.CSSProperties = {
  padding: '8px 12px',
  whiteSpace: 'nowrap',
}
