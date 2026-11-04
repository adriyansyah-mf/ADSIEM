/** Severity → design-token color, shared by the attack map and command-center panels. */
export const SEVERITY_COLOR: Readonly<Record<string, string>> = {
  critical: 'var(--accent-red)',
  high: 'var(--accent-orange)',
  medium: 'var(--accent-yellow)',
  low: 'var(--accent-green)',
  info: 'var(--accent-cyan)',
}
