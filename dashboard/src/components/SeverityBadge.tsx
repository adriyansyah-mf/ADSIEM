const COLOR: Record<string, string> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-blue)',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  const c = COLOR[severity] ?? 'var(--text-muted)'
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 4,
        border: `1px solid ${c}`,
        background: `color-mix(in srgb, ${c} 12%, transparent)`,
        color: c,
        fontWeight: 600,
        fontSize: 11,
        letterSpacing: '0.02em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  )
}
