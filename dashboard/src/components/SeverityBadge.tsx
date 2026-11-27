const KNOWN = new Set(['critical', 'high', 'medium', 'low', 'info'])

// Filled chips so severity reads at a glance in dense tables (redesign palette).
export default function SeverityBadge({ severity }: { readonly severity: string }) {
  const key = KNOWN.has(severity) ? severity : 'unknown'
  return (
    <span className={`severity-chip severity-chip--${key}`}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  )
}
