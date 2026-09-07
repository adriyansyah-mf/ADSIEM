import type { CSSProperties } from 'react'

export const S = {
  card: { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 12 } as CSSProperties,
  label: { fontSize: 11, color: 'var(--text-secondary)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' as const, marginBottom: 4 },
  input: {
    background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', fontSize: 13, padding: '6px 10px', width: '100%', outline: 'none',
  } as CSSProperties,
  select: {
    background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text-primary)', fontSize: 13, padding: '6px 8px',
  } as CSSProperties,
  btn: (color = 'var(--accent-blue)') => ({
    padding: '6px 14px', borderRadius: 6, border: 'none',
    background: color, color: '#fff', fontSize: 12, fontWeight: 600,
    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
  } as CSSProperties),
  ghost: { padding: '4px 8px', borderRadius: 4, border: 'none', background: 'transparent', cursor: 'pointer', color: 'var(--text-secondary)' } as CSSProperties,
}
