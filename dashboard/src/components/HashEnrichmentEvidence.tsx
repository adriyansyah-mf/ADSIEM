const OUTCOMES: Readonly<Record<string, string>> = {
  found: 'Known malware record',
  not_found: 'Unknown to this provider — not a clean verdict',
  unavailable: 'Provider unavailable — investigation continues',
  disabled: 'External hash enrichment disabled',
  not_configured: 'Provider API key not configured',
  rate_limited: 'Provider rate limit — further queries stopped for this run',
  auth_error: 'Provider authentication failed — further queries stopped for this run',
  invalid_hash: 'Invalid hash — no query sent',
  unobserved_hash: 'Hash not observed in case evidence — no query sent',
  invalid_response: 'Invalid provider response — no verdict available',
  budget_exhausted: 'Hash lookup budget exhausted',
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function HashEnrichmentEvidence({ result, reason }: {
  readonly result: unknown
  readonly reason: unknown
}) {
  if (!isRecord(result)) return <span>Enrichment evidence unavailable</span>
  const status = typeof result.status === 'string' ? result.status : ''
  const hash = typeof result.queried_hash === 'string' ? result.queried_hash : ''
  const checkedAt = typeof result.checked_at === 'string' ? result.checked_at : ''
  const sample = isRecord(result.sample) ? result.sample : null
  const signature = typeof sample?.signature === 'string' ? sample.signature : ''
  const fileName = typeof sample?.file_name === 'string' ? sample.file_name : ''
  const tags = Array.isArray(sample?.tags)
    ? sample.tags.filter((tag): tag is string => typeof tag === 'string').join(', ') : ''
  // Only allow the provider's fixed sample-report route, never arbitrary returned URLs.
  const reportUrl = typeof result.report_url === 'string'
    && /^https:\/\/bazaar\.abuse\.ch\/sample\/[a-f0-9]{64}\/$/.test(result.report_url)
    ? result.report_url : null

  return (
    <div style={{ display: 'grid', gap: '4px', minWidth: 0, overflowWrap: 'anywhere', fontSize: '12px' }}>
      <span style={{ color: status === 'found' ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
        {OUTCOMES[status] ?? 'Unknown enrichment outcome'}
      </span>
      <code style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{hash}</code>
      {signature && <span>Family: {signature}</span>}
      {fileName && <span>File: {fileName}</span>}
      {tags && <span>Tags: {tags}</span>}
      {checkedAt && <span>Checked: {checkedAt}{result.cached === true ? ' · cached for this investigation' : ''}</span>}
      {typeof reason === 'string' && reason && <span>{reason}</span>}
      {reportUrl && <a href={reportUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-cyan)' }}>Provider report</a>}
      {status === 'found' && <span>A provider match is not proof of execution or compromise.</span>}
    </div>
  )
}
