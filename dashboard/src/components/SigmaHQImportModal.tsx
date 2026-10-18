import { useRef, useState } from 'react'
import { X, Download, Upload } from 'lucide-react'
import { useImportSigmaHQ, useUploadSigmaHQ } from '@/hooks/useRules'
import type { SigmaHQImportResult } from '@/types'

const RULESETS = [
  { value: 'core', label: 'Core', hint: 'stable/test, high & critical — the recommended baseline (~1.4k rules)' },
  { value: 'core+', label: 'Core+', hint: 'adds medium level' },
  { value: 'core++', label: 'Core++', hint: 'adds experimental rules' },
  { value: 'emerging_threats', label: 'Emerging threats', hint: 'campaign / CVE specific add-on' },
  { value: 'all', label: 'All rules', hint: 'everything except deprecated (~3.3k rules)' },
]
const LEVELS = ['critical', 'high', 'medium', 'low', 'informational']
const STATUSES = ['stable', 'test', 'experimental']

function toggle(list: string[], v: string) {
  return list.includes(v) ? list.filter(x => x !== v) : [...list, v]
}

export default function SigmaHQImportModal({ onClose }: { onClose: () => void }) {
  const [ruleset, setRuleset] = useState('core')
  const [levels, setLevels] = useState(['critical', 'high'])
  const [statuses, setStatuses] = useState(['stable', 'test'])
  const [result, setResult] = useState<SigmaHQImportResult | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const importRules = useImportSigmaHQ()
  const uploadRules = useUploadSigmaHQ()
  const busy = importRules.isPending || uploadRules.isPending

  const runImport = () =>
    importRules.mutate({ ruleset, enable_levels: levels, enable_statuses: statuses }, { onSuccess: setResult })

  const runUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    uploadRules.mutate({ file, enable_levels: levels, enable_statuses: statuses }, {
      onSuccess: setResult,
      onSettled: () => { if (fileRef.current) fileRef.current.value = '' },
    })
  }

  const chip = (active: boolean) =>
    `px-2 py-0.5 rounded border text-xs ${active ? 'border-primary text-primary bg-primary/10' : 'border-border text-muted-foreground'}`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={busy ? undefined : onClose}>
      <div className="w-full max-w-xl rounded-lg border border-border bg-card shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="font-semibold">Import SigmaHQ rules</h2>
          <button onClick={onClose} disabled={busy} className="text-muted-foreground hover:text-foreground"><X size={18} /></button>
        </div>

        <div className="px-4 py-3 space-y-4 text-sm">
          <p className="text-muted-foreground text-xs">
            Imports the official <a className="underline" href="https://github.com/SigmaHQ/sigma" target="_blank" rel="noreferrer">SigmaHQ</a> release.
            Running it again updates rules to the latest release; rules you edited here are kept as they are.
          </p>

          <div>
            <div className="text-xs font-semibold mb-1">Ruleset</div>
            <div className="space-y-1">
              {RULESETS.map(r => (
                <label key={r.value} className="flex items-start gap-2 cursor-pointer">
                  <input type="radio" name="ruleset" checked={ruleset === r.value} onChange={() => setRuleset(r.value)} className="mt-1" />
                  <span><span className="font-medium">{r.label}</span> <span className="text-muted-foreground text-xs">— {r.hint}</span></span>
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="text-xs font-semibold mb-1">Enable new rules with level</div>
            <div className="flex flex-wrap gap-1">
              {LEVELS.map(l => <button key={l} onClick={() => setLevels(toggle(levels, l))} className={chip(levels.includes(l))}>{l}</button>)}
            </div>
            <div className="text-xs font-semibold mt-2 mb-1">and status</div>
            <div className="flex flex-wrap gap-1">
              {STATUSES.map(s => <button key={s} onClick={() => setStatuses(toggle(statuses, s))} className={chip(statuses.includes(s))}>{s}</button>)}
            </div>
            <p className="text-muted-foreground text-xs mt-1">
              Other rules are imported disabled, as are rules for log sources this platform doesn't collect (cloud, macOS, …).
            </p>
          </div>

          {result && (
            <div className="rounded border border-border bg-muted/30 p-3 text-xs space-y-1">
              <div className="font-semibold">Imported {result.release}</div>
              <div>
                {result.total} rules · <b>{result.created}</b> new · <b>{result.updated}</b> updated · {result.unchanged} unchanged
                {result.kept_local_edits > 0 && <> · {result.kept_local_edits} kept (edited locally)</>}
              </div>
              <div>{result.enabled} new rules enabled · {result.not_collected} not collected · {result.rejected} rejected</div>
              {result.rejected_examples.map((r, i) => <div key={i} className="text-destructive font-mono break-all">{r}</div>)}
            </div>
          )}
        </div>

        <div className="flex gap-2 justify-end px-4 py-3 border-t border-border">
          <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={runUpload} />
          <button onClick={() => fileRef.current?.click()} disabled={busy}
            title="For servers without internet access: upload a release zip from github.com/SigmaHQ/sigma/releases"
            className="flex items-center gap-1 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted disabled:opacity-50">
            <Upload size={14} /> Upload zip
          </button>
          <button onClick={runImport} disabled={busy}
            className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
            <Download size={14} /> {busy ? 'Importing…' : 'Import latest release'}
          </button>
        </div>
      </div>
    </div>
  )
}
