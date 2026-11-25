import { useEffect, useRef, type ReactNode } from 'react'
import type { AgentConfig } from '@/types'

/** Upper bounds the server enforces (Go int is 32 bits on 32-bit builds). */
const INT_MAX = 2 ** 31 - 1
const INT64_MAX = Number.MAX_SAFE_INTEGER

type Sections = { [K in keyof AgentConfig]-?: NonNullable<AgentConfig[K]> }

function cleanList(items: readonly string[]): string[] {
  return items.map(x => x.trim()).filter(Boolean)
}

/**
 * The overlay with unset fields and empty sections removed; null when nothing is set.
 * With cleanLists (on save), list items are trimmed and blank ones dropped: a list that was
 * only blanks becomes unset, while an explicit [] ("kosongkan") stays [].
 */
export function pruneAgentConfig(c: AgentConfig | null | undefined, cleanLists = false): AgentConfig | null {
  if (!c) return null
  const out: Record<string, Record<string, unknown>> = {}
  for (const [section, fields] of Object.entries(c)) {
    if (!fields || typeof fields !== 'object') continue
    const kept: Record<string, unknown> = {}
    for (const [key, v] of Object.entries(fields as Record<string, unknown>)) {
      if (v === undefined || v === null || (typeof v === 'number' && Number.isNaN(v))) continue
      if (cleanLists && Array.isArray(v)) {
        const items = cleanList(v as string[])
        if (items.length === 0 && v.length > 0) continue
        kept[key] = items
      } else if (cleanLists && typeof v === 'string') {
        if (v.trim()) kept[key] = v.trim()
      } else {
        kept[key] = v
      }
    }
    if (Object.keys(kept).length > 0) out[section] = kept
  }
  return Object.keys(out).length > 0 ? (out as AgentConfig) : null
}

const inputCls = 'w-full bg-muted border border-border rounded px-2 py-1.5 text-sm'
const LOCAL = 'pakai nilai lokal'

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <span className="block font-mono text-xs">{label}</span>
      {children}
      {hint && <span className="block text-xs text-muted-foreground">{hint}</span>}
    </div>
  )
}

/** Three states: lokal (indeterminate) → on → off → lokal. */
function TriBool({ label, value, onChange }: { label: string; value: boolean | undefined; onChange: (v: boolean | undefined) => void }) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => { if (ref.current) ref.current.indeterminate = value === undefined }, [value])
  const next = value === undefined ? true : value ? false : undefined
  return (
    <label className="flex items-center gap-2 cursor-pointer">
      <input ref={ref} type="checkbox" checked={value === true} onChange={() => onChange(next)} />
      <span className="font-mono text-xs">{label}</span>
      <span className={`text-xs ${value === undefined ? 'text-muted-foreground' : 'font-medium'}`}>
        {value === undefined ? 'lokal' : value ? 'on' : 'off'}
      </span>
    </label>
  )
}

function NumField({ label, hint, value, onChange, min, max }: {
  label: string; hint?: string; value: number | undefined; onChange: (v: number | undefined) => void; min: number; max: number
}) {
  return (
    <Field label={label} hint={hint}>
      <input type="number" step={1} min={min} max={max} value={value ?? ''} placeholder={LOCAL}
        onChange={e => onChange(e.target.value === '' ? undefined : Number(e.target.value))}
        className={`${inputCls} font-mono`} />
    </Field>
  )
}

function EnumField<T extends string>({ label, hint, value, options, onChange }: {
  label: string; hint?: string; value: T | undefined; options: readonly T[]; onChange: (v: T | undefined) => void
}) {
  return (
    <Field label={label} hint={hint}>
      <select value={value ?? ''} onChange={e => onChange((e.target.value || undefined) as T | undefined)} className={inputCls}>
        <option value="">{LOCAL}</option>
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </Field>
  )
}

/** One item per line. Empty textarea: unset (local value); "kosongkan": an explicit []. */
function ListField({ label, hint, value, onChange, placeholder }: {
  label: string; hint?: string; value: string[] | undefined; onChange: (v: string[] | undefined) => void; placeholder?: string
}) {
  const cleared = value !== undefined && value.length === 0
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs">{label}</span>
        <label className="ml-auto flex items-center gap-1 text-xs text-muted-foreground cursor-pointer">
          <input type="checkbox" checked={cleared} onChange={e => onChange(e.target.checked ? [] : undefined)} /> kosongkan
        </label>
      </div>
      <textarea rows={3} disabled={cleared} value={(value ?? []).join('\n')}
        placeholder={cleared ? 'daftar kosong: menimpa nilai lokal' : placeholder ?? `${LOCAL} (satu item per baris)`}
        onChange={e => onChange(e.target.value.trim() === '' ? undefined : e.target.value.split('\n'))}
        onBlur={e => { const items = cleanList(e.target.value.split('\n')); onChange(items.length > 0 ? items : undefined) }}
        className={`${inputCls} text-xs font-mono disabled:opacity-50`} />
      {hint && <span className="block text-xs text-muted-foreground">{hint}</span>}
    </div>
  )
}

/** A list limited to fixed choices: lokal, or exactly the ones ticked (none ticked: []). */
function ChoiceList<T extends string>({ label, hint, value, options, onChange }: {
  label: string; hint?: string; value: T[] | undefined; options: readonly T[]; onChange: (v: T[] | undefined) => void
}) {
  return (
    <Field label={label} hint={hint}>
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <select value={value === undefined ? '' : 'set'} onChange={e => onChange(e.target.value ? [] : undefined)}
          className="bg-muted border border-border rounded px-2 py-1.5 text-sm">
          <option value="">{LOCAL}</option>
          <option value="set">atur</option>
        </select>
        {value !== undefined && options.map(o => (
          <label key={o} className="flex items-center gap-1 cursor-pointer">
            <input type="checkbox" checked={value.includes(o)}
              onChange={e => onChange(e.target.checked ? [...value, o] : value.filter(x => x !== o))} />
            {o}
          </label>
        ))}
      </div>
    </Field>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="rounded border border-border p-3">
      <legend className="px-1 text-sm font-medium">{title}</legend>
      <div className="grid gap-3 md:grid-cols-2">{children}</div>
    </fieldset>
  )
}

export function AgentConfigEditor({ value, onChange }: { value: AgentConfig | null; onChange: (v: AgentConfig | null) => void }) {
  const get = <S extends keyof Sections, F extends keyof Sections[S]>(s: S, f: F) =>
    (value?.[s] as Sections[S] | undefined)?.[f]
  const set = <S extends keyof Sections, F extends keyof Sections[S]>(s: S, f: F) =>
    (v: Sections[S][F] | undefined) =>
      onChange(pruneAgentConfig({ ...(value ?? {}), [s]: { ...(value?.[s] ?? {}), [f]: v } }))
  const bind = <S extends keyof Sections, F extends keyof Sections[S]>(s: S, f: F) =>
    ({ label: `${String(s)}.${String(f)}`, value: get(s, f), onChange: set(s, f) })

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold text-sm">Agent config</h3>
        <span className="text-xs text-muted-foreground">
          Menimpa config.yaml lokal agent di group ini. Field yang kosong memakai nilai lokal.
        </span>
      </div>
      <p className="rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
        Menyimpan perubahan merestart agent di group ini (±10 detik, dengan jeda acak hingga 1 menit).
      </p>
      <p className="text-xs text-muted-foreground">Group dengan policy sendiri tidak mewarisi Agent config dari default.</p>

      <Section title="Server">
        <Field label="server.url" hint="Hanya port/path di host yang sama. Pindah host lewat config.yaml lokal.">
          <input type="url" value={get('server', 'url') ?? ''} placeholder={LOCAL}
            onChange={e => set('server', 'url')(e.target.value === '' ? undefined : e.target.value)}
            className={`${inputCls} font-mono`} />
        </Field>
        <NumField {...bind('server', 'heartbeat_interval')} min={10} max={3600} hint="Detik, 10–3600." />
        <NumField {...bind('agent', 'buffer_size')} min={1} max={INT_MAX} hint="Jumlah event di buffer memori." />
      </Section>

      <Section title="Firewall">
        <TriBool {...bind('firewall', 'enabled')} />
        <TriBool {...bind('firewall', 'dry_run')} />
        <EnumField {...bind('firewall', 'backend')} options={['auto', 'nft', 'netsh', 'noop'] as const} />
        <NumField {...bind('firewall', 'isolation_release_after_offline_minutes')} min={0} max={INT_MAX}
          hint="Menit offline sebelum isolasi dilepas." />
        <ListField {...bind('firewall', 'protected_ips')} placeholder={`${LOCAL} (satu IP/CIDR per baris)`} />
      </Section>

      <Section title="ETW">
        <EnumField {...bind('etw', 'mode')} options={['auto', 'on', 'off'] as const} />
        <ChoiceList {...bind('etw', 'disabled_events')} options={['file', 'image'] as const} />
      </Section>

      <Section title="Detect">
        <TriBool {...bind('detect', 'enabled')} />
        <NumField {...bind('detect', 'max_blocked')} min={0} max={INT_MAX} hint="0: default agent." />
        <NumField {...bind('detect', 'max_blocks_per_minute')} min={0} max={INT_MAX} hint="0: default agent." />
        <ListField {...bind('detect', 'rules')} />
      </Section>

      <Section title="YARA">
        <NumField {...bind('yara', 'max_file_size_mb')} min={1} max={1024} hint="MB, 1–1024." />
        <ListField {...bind('yara', 'watch_paths')} />
      </Section>

      <Section title="Ransomware">
        <TriBool {...bind('ransomware', 'disabled')} />
        <TriBool {...bind('ransomware', 'canary_visible')} />
        <ListField {...bind('ransomware', 'canary_dirs')} />
        <ListField {...bind('ransomware', 'canary_names')} />
        <ListField {...bind('ransomware', 'allow_images')} />
      </Section>

      <Section title="Memory sweep">
        <TriBool {...bind('memory_sweep', 'disabled')} />
        <NumField {...bind('memory_sweep', 'interval_minutes')} min={1} max={1440} hint="Menit, 1–1440." />
      </Section>

      <Section title="Evidence">
        <TriBool {...bind('evidence', 'enabled')} />
        <NumField {...bind('evidence', 'max_bytes')} min={1} max={INT64_MAX} hint="Byte." />
        <NumField {...bind('evidence', 'segment_bytes')} min={1} max={INT64_MAX} hint="Byte." />
        <NumField {...bind('evidence', 'reserved_bytes')} min={0} max={INT64_MAX} hint="Byte." />
        <NumField {...bind('evidence', 'max_event_bytes')} min={1} max={INT_MAX} hint="Byte." />
      </Section>

      <Section title="Modul lain">
        <TriBool {...bind('fim', 'enabled')} />
        <TriBool {...bind('netwatch', 'enabled')} />
        <TriBool {...bind('netwatch', 'snapshot_fallback')} />
        <TriBool {...bind('linux_sensor', 'disabled')} />
        <TriBool {...bind('prevention', 'disabled')} />
        <TriBool {...bind('notify', 'disabled')} />
        <TriBool {...bind('project_scan', 'disabled')} />
        <TriBool {...bind('update', 'disabled')} />
        <ListField {...bind('linux_sensor', 'disabled_events')} />
      </Section>
    </section>
  )
}
