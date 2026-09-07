export const IOC_TYPES = [
  { value: 'ip', label: 'IP Address' },
  { value: 'hostname', label: 'Hostname' },
  { value: 'user', label: 'Username' },
  { value: 'hash', label: 'File Hash (SHA256)' },
]

export const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/30 border-red-700',
  high:     'text-orange-400 bg-orange-900/30 border-orange-700',
  medium:   'text-yellow-400 bg-yellow-900/30 border-yellow-700',
  low:      'text-blue-400 bg-blue-900/30 border-blue-700',
  unknown:  'text-muted-foreground bg-muted/20 border-border',
}

export const SIGMA_EXAMPLE = `title: Suspicious PowerShell download
logsource:
  product: windows
  service: powershell
detection:
  selection:
    event.action: process-start
    process.command_line|contains: Invoke-WebRequest
  condition: selection`

export function errorMessage(error: unknown, fallback: string) {
  if (typeof error === 'object' && error !== null && 'response' in error) {
    const response = (error as { response?: { data?: { detail?: unknown } } }).response
    if (typeof response?.data?.detail === 'string') return response.data.detail
  }
  return fallback
}
