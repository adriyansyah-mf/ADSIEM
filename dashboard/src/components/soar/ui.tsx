import { Plus, X } from 'lucide-react'
import type { CSSProperties, ReactNode } from 'react'

export const S = {
  card: { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16 } as CSSProperties,
  label: { fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600, letterSpacing: '0.06em',
    textTransform: 'uppercase', marginBottom: 4, display: 'block' } as CSSProperties,
  input: { background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', fontSize: 13, padding: '6px 10px', width: '100%', outline: 'none' } as CSSProperties,
  mono: { fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12 } as CSSProperties,
  btn: (color = 'var(--accent-cyan)', fg = '#04121c', disabled = false): CSSProperties => ({
    padding: '6px 12px', borderRadius: 6, border: 'none', background: color, color: fg, fontSize: 12,
    fontWeight: 700, cursor: disabled ? 'default' : 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6,
    whiteSpace: 'nowrap', opacity: disabled ? 0.4 : 1,
  }),
  ghost: { padding: '5px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent',
    cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 12, display: 'inline-flex', alignItems: 'center',
    gap: 6 } as CSSProperties,
  hint: { fontSize: 11, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.5 } as CSSProperties,
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <label style={S.label}>{label}</label>
      {children}
      {hint && <div style={S.hint}>{hint}</div>}
    </div>
  )
}

interface TextProps {
  value: unknown
  onChange: (v: string) => void
  placeholder?: string
  disabled?: boolean
  mono?: boolean
  list?: string
}

export function Text({ value, onChange, placeholder, disabled, mono, list }: TextProps) {
  return (
    <input style={{ ...S.input, ...(mono ? S.mono : {}) }} value={value === undefined || value === null ? '' : String(value)}
      onChange={e => onChange(e.target.value)} placeholder={placeholder} disabled={disabled} list={list} />
  )
}

export function Area({ value, onChange, placeholder, disabled, rows = 3, mono }: TextProps & { rows?: number }) {
  return (
    <textarea style={{ ...S.input, ...(mono ? S.mono : {}), resize: 'vertical' }} rows={rows}
      value={value === undefined || value === null ? '' : String(value)}
      onChange={e => onChange(e.target.value)} placeholder={placeholder} disabled={disabled} />
  )
}

export function Num({ value, onChange, min, max, step, disabled }: {
  value: unknown; onChange: (v: number) => void; min?: number; max?: number; step?: number; disabled?: boolean
}) {
  return (
    <input type="number" style={S.input} value={typeof value === 'number' ? value : Number(value ?? 0)}
      min={min} max={max} step={step} disabled={disabled}
      onChange={e => onChange(e.target.value === '' ? 0 : Number(e.target.value))} />
  )
}

export function Select({ value, options, onChange, disabled }: {
  value: unknown; options: readonly string[]; onChange: (v: string) => void; disabled?: boolean
}) {
  return (
    <select style={S.input} value={String(value ?? '')} onChange={e => onChange(e.target.value)} disabled={disabled}>
      {options.map(o => <option key={o} value={o}>{o}</option>)}
    </select>
  )
}

export function Check({ checked, onChange, label, disabled }: {
  checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean
}) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, color: 'var(--text-primary)', marginBottom: 12 }}>
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} disabled={disabled} />
      {label}
    </label>
  )
}

/** Editable string→string map (headers, query, extract). */
export function KeyValue({ value, onChange, keyPlaceholder, valuePlaceholder, disabled }: {
  value: Record<string, unknown> | undefined
  onChange: (v: Record<string, string>) => void
  keyPlaceholder: string
  valuePlaceholder: string
  disabled?: boolean
}) {
  const rows = Object.entries(value ?? {}).map(([k, v]) => [k, v === null || v === undefined ? '' : String(v)] as [string, string])
  const emit = (next: [string, string][]) => onChange(Object.fromEntries(next))
  return (
    <div>
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
          <input style={{ ...S.input, ...S.mono, flex: '0 0 38%' }} value={k} placeholder={keyPlaceholder} disabled={disabled}
            onChange={e => emit(rows.map((r, j) => (j === i ? [e.target.value, r[1]] : r)))} />
          <input style={{ ...S.input, ...S.mono }} value={v} placeholder={valuePlaceholder} disabled={disabled}
            onChange={e => emit(rows.map((r, j) => (j === i ? [r[0], e.target.value] : r)))} />
          {!disabled && (
            <button style={S.ghost} title="Remove" onClick={() => emit(rows.filter((_, j) => j !== i))}><X size={12} /></button>
          )}
        </div>
      ))}
      {!disabled && (
        <button style={S.ghost} onClick={() => emit([...rows.filter(r => r[0] !== ''), ['', '']])}>
          <Plus size={12} /> Add
        </button>
      )}
    </div>
  )
}

export function JsonBlock({ value }: { value: unknown }) {
  const text = value === undefined ? '' : JSON.stringify(value, null, 2)
  return (
    <pre style={{ ...S.mono, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 6,
      padding: 10, margin: 0, maxHeight: 320, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
      color: 'var(--text-primary)' }}>
      {text || '—'}
    </pre>
  )
}
