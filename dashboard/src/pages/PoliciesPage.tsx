import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Loader2, Plus, RotateCcw, Save, ShieldCheck, Trash2 } from 'lucide-react'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'

type Scope = 'prevention' | 'malware' | 'yara' | 'ransomware' | 'script' | 'ml' | 'alerts'
type Kind = 'path_prefix' | 'image' | 'sha256' | 'command_line'

interface Exclusion { kind: Kind; value: string; scopes: Scope[]; comment: string }

interface Settings {
  prevention_enabled: boolean
  malware_action: 'off' | 'detect' | 'block' | null
  yara_on_access: boolean
  ransomware_mode: 'off' | 'report' | 'stop'
  ransomware_isolate: boolean
  notify_user: boolean
  script_scan: 'off' | 'detect' | 'block'
  ml_action: 'off' | 'detect' | 'block'
  quick_scan_time: string
  full_scan_schedule: string
  exclusions: Exclusion[]
}

interface GroupRow {
  group: string
  agents: number
  own_policy: boolean
  applies: string
  updated_by: string | null
  updated_at: string | null
}

interface PolicyOut { group: string; applies: string; own_policy: boolean; settings: Settings; version: string }

const SCOPES: { value: Scope; label: string }[] = [
  { value: 'prevention', label: 'Prevention rules' },
  { value: 'malware', label: 'Known malware' },
  { value: 'yara', label: 'YARA on-access' },
  { value: 'ransomware', label: 'Ransomware' },
  { value: 'script', label: 'Script scanning' },
  { value: 'ml', label: 'Static ML' },
  { value: 'alerts', label: 'Alerts' },
]

const KINDS: { value: Kind; label: string; placeholder: string }[] = [
  { value: 'path_prefix', label: 'Path or folder', placeholder: 'C:\\Tools\\Sysinternals\\  or  /opt/backup/' },
  { value: 'image', label: 'Program', placeholder: 'veeam.exe  or  /usr/bin/restic' },
  { value: 'sha256', label: 'SHA-256', placeholder: '64 hex characters' },
  { value: 'command_line', label: 'Command line contains', placeholder: '--nightly-backup' },
]

function apiError(e: unknown): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(d => {
    const x = d as { msg?: string; loc?: unknown[] }
    return `${(x.loc ?? []).slice(1).join('.')}: ${x.msg ?? ''}`
  }).join('; ')
  return 'Could not save'
}

function Toggle({ label, hint, on, onChange }: { label: string; hint: string; on: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start gap-3 rounded border border-border p-3 cursor-pointer hover:bg-muted/40">
      <input type="checkbox" checked={on} onChange={e => onChange(e.target.checked)} className="mt-1" />
      <span>
        <span className="block text-sm font-medium">{label}</span>
        <span className="block text-xs text-muted-foreground">{hint}</span>
      </span>
    </label>
  )
}

function Editor({ group, onClose }: { group: string; onClose: () => void }) {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery<PolicyOut>({
    queryKey: ['policy', group],
    queryFn: () => api.get(`/api/policies/${encodeURIComponent(group)}`).then(r => r.data),
  })
  const [s, setS] = useState<Settings | null>(null)
  const [error, setError] = useState('')
  useEffect(() => { if (data) setS(data.settings) }, [data])
  const save = useMutation({
    mutationFn: (body: Settings) => api.put(`/api/policies/${encodeURIComponent(group)}`, body).then(r => r.data),
    onSuccess: () => {
      setError('')
      emitToast(`Policy saved: agents in ${group} pick it up within a minute`, 'success')
      qc.invalidateQueries({ queryKey: ['policies'] })
      qc.invalidateQueries({ queryKey: ['policy', group] })
    },
    onError: e => setError(apiError(e)),
  })
  const reset = useMutation({
    mutationFn: () => api.delete(`/api/policies/${encodeURIComponent(group)}`),
    onSuccess: () => {
      emitToast(`${group} now follows the default policy`, 'success')
      qc.invalidateQueries({ queryKey: ['policies'] })
      qc.invalidateQueries({ queryKey: ['policy', group] })
    },
  })

  if (isLoading || !s || !data) return <Loader2 size={16} className="animate-spin" />
  const set = (patch: Partial<Settings>) => setS({ ...s, ...patch })
  const setEx = (i: number, patch: Partial<Exclusion>) =>
    set({ exclusions: s.exclusions.map((e, j) => (j === i ? { ...e, ...patch } : e)) })

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="text-lg font-semibold">Group: {group}</h2>
        <span className="text-xs text-muted-foreground">
          {data.own_policy ? 'its own policy' : `follows the ${data.applies} policy until you save`}
        </span>
        <div className="ml-auto flex gap-2">
          <button onClick={onClose} className="px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">Back</button>
          {data.own_policy && group !== 'default' && (
            <button onClick={() => reset.mutate()} disabled={reset.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border text-sm hover:bg-muted">
              <RotateCcw size={13} /> Use default policy
            </button>
          )}
          <button onClick={() => save.mutate(s)} disabled={save.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
            <Save size={13} /> {save.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
      {error && <p className="text-xs text-destructive">{error}</p>}

      <section className="grid gap-3 md:grid-cols-2">
        <Toggle label="Execution prevention" on={s.prevention_enabled} onChange={v => set({ prevention_enabled: v })}
          hint="Prevention rules and blocking known malware at start (Linux: before it runs; Windows: right after)." />
        <Toggle label="YARA on-access scanning" on={s.yara_on_access} onChange={v => set({ yara_on_access: v })}
          hint="Scan new and changed files in the watched folders with the enabled YARA rules." />
        <Toggle label="Pop-ups for the signed-in user" on={s.notify_user} onChange={v => set({ notify_user: v })}
          hint="Windows: tell the user when malware is found or stopped." />
        <Toggle label="Isolate the host on ransomware" on={s.ransomware_isolate}
          onChange={v => set({ ransomware_isolate: v })}
          hint="Cut the host off the network (except the SIEM) when ransomware is confirmed." />
        <label className="rounded border border-border p-3 space-y-1">
          <span className="block text-sm font-medium">Known-malware hashes</span>
          <select value={s.malware_action ?? ''} onChange={e => set({ malware_action: (e.target.value || null) as Settings['malware_action'] })}
            className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm">
            <option value="">Use the global setting (Malware hashes page)</option>
            <option value="off">Off</option>
            <option value="detect">Detect: alert only</option>
            <option value="block">Block: stop and quarantine</option>
          </select>
        </label>
        <label className="rounded border border-border p-3 space-y-1">
          <span className="block text-sm font-medium">Script scanning</span>
          <select value={s.script_scan} onChange={e => set({ script_scan: e.target.value as Settings['script_scan'] })}
            className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm">
            <option value="detect">Detect: alert on malicious scripts</option>
            <option value="block">Block: also stop the process (high and critical rules)</option>
            <option value="off">Off</option>
          </select>
          <span className="block text-xs text-muted-foreground">
            YARA rules on PowerShell, VBScript, JScript and Office macros (Windows, through AMSI) and on shell,
            Python, Perl, PHP and Node code (Linux).
          </span>
        </label>
        <label className="rounded border border-border p-3 space-y-1">
          <span className="block text-sm font-medium">Ransomware protection</span>
          <select value={s.ransomware_mode} onChange={e => set({ ransomware_mode: e.target.value as Settings['ransomware_mode'] })}
            className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm">
            <option value="stop">Stop: kill the encrypting process</option>
            <option value="report">Report only</option>
            <option value="off">Off</option>
          </select>
        </label>
        <label className="rounded border border-border p-3 space-y-1">
          <span className="block text-sm font-medium">Static ML (unknown files)</span>
          <select value={s.ml_action ?? 'detect'} onChange={e => set({ ml_action: e.target.value as Settings['ml_action'] })}
            className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm">
            <option value="detect">Detect: alert only</option>
            <option value="block">Block: quarantine files scored malicious</option>
            <option value="off">Off</option>
          </select>
          <span className="block text-xs text-muted-foreground">
            Scores Windows programs (PE) with a model trained on EMBER and Linux programs (ELF) with heuristics, in the YARA watched folders. Exclude false positives with the Static ML scope.
          </span>
        </label>
        <label className="rounded border border-border p-3 space-y-1">
          <span className="block text-sm font-medium">Scheduled quick scan</span>
          <input value={s.quick_scan_time ?? ''} onChange={e => set({ quick_scan_time: e.target.value })} placeholder="12:30 (empty: off)"
            className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm font-mono" />
          <span className="block text-xs text-muted-foreground">Every day at this time (the endpoint's local time): downloads, temp, startup and autostart folders, web roots.</span>
        </label>
        <label className="rounded border border-border p-3 space-y-1">
          <span className="block text-sm font-medium">Scheduled full scan</span>
          <input value={s.full_scan_schedule ?? ''} onChange={e => set({ full_scan_schedule: e.target.value })} placeholder="sun 02:00 (or daily 02:00; empty: off)"
            className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm font-mono" />
          <span className="block text-xs text-muted-foreground">Every local disk, at low priority. A slot missed while the endpoint was off runs later the same day.</span>
        </label>
      </section>

      <section className="space-y-2">
        <div className="flex items-center gap-2">
          <h3 className="font-semibold text-sm">Exclusions</h3>
          <span className="text-xs text-muted-foreground">Known-good programs, folders, hashes or command lines, and what they are excluded from.</span>
          <button onClick={() => set({ exclusions: [...s.exclusions, { kind: 'path_prefix', value: '', scopes: ['alerts'], comment: '' }] })}
            className="ml-auto flex items-center gap-1 px-2 py-1 rounded border border-border text-xs hover:bg-muted">
            <Plus size={12} /> Add
          </button>
        </div>
        {s.exclusions.length === 0 ? <p className="text-xs text-muted-foreground">None.</p> : (
          <div className="space-y-2">
            {s.exclusions.map((e, i) => (
              <div key={i} className="rounded border border-border p-3 space-y-2">
                <div className="flex flex-wrap gap-2">
                  <select value={e.kind} onChange={ev => setEx(i, { kind: ev.target.value as Kind })}
                    className="bg-muted border border-border rounded px-2 py-1.5 text-sm">
                    {KINDS.map(k => <option key={k.value} value={k.value}>{k.label}</option>)}
                  </select>
                  <input value={e.value} onChange={ev => setEx(i, { value: ev.target.value })}
                    placeholder={KINDS.find(k => k.value === e.kind)?.placeholder}
                    className="flex-1 min-w-[16rem] bg-muted border border-border rounded px-2 py-1.5 text-sm font-mono" />
                  <button onClick={() => set({ exclusions: s.exclusions.filter((_, j) => j !== i) })} title="Remove"
                    className="p-1.5 rounded hover:bg-muted text-destructive"><Trash2 size={14} /></button>
                </div>
                <div className="flex flex-wrap items-center gap-3 text-xs">
                  {SCOPES.map(sc => (
                    <label key={sc.value} className="flex items-center gap-1">
                      <input type="checkbox" checked={e.scopes.includes(sc.value)}
                        onChange={ev => setEx(i, { scopes: ev.target.checked ? [...e.scopes, sc.value] : e.scopes.filter(x => x !== sc.value) })} />
                      {sc.label}
                    </label>
                  ))}
                  <input value={e.comment} onChange={ev => setEx(i, { comment: ev.target.value })} placeholder="Why (e.g. backup software, ticket)"
                    className="flex-1 min-w-[12rem] bg-muted border border-border rounded px-2 py-1 text-xs" />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

export default function PoliciesPage() {
  const { data = [], isLoading } = useQuery<GroupRow[]>({
    queryKey: ['policies'],
    queryFn: () => api.get('/api/policies').then(r => r.data),
  })
  const [open, setOpen] = useState<string | null>(null)
  const [newGroup, setNewGroup] = useState('')

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center gap-2">
        <ShieldCheck size={18} className="text-primary" />
        <h1 className="text-xl font-bold">Policies</h1>
      </div>
      <p className="text-xs text-muted-foreground max-w-3xl">
        One policy per agent group, for Linux and Windows agents alike: which protections run and what they leave out.
        A group without its own policy follows the <span className="font-semibold">default</span> group's. Agents apply a
        change within a minute, without a restart. A protection turned off in an agent's local config stays off.
      </p>
      {open ? <Editor group={open} onClose={() => setOpen(null)} /> : isLoading ? <Loader2 size={16} className="animate-spin" /> : (
        <>
          <div className="rounded-lg border border-border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 text-xs text-muted-foreground uppercase">
                <tr>
                  <th className="text-left px-3 py-2">Group</th>
                  <th className="text-left px-3 py-2">Agents</th>
                  <th className="text-left px-3 py-2">Policy</th>
                  <th className="text-left px-3 py-2">Changed</th>
                </tr>
              </thead>
              <tbody>
                {data.map(g => (
                  <tr key={g.group} onClick={() => setOpen(g.group)} className="border-t border-border cursor-pointer hover:bg-muted/40">
                    <td className="px-3 py-2 font-medium">{g.group}</td>
                    <td className="px-3 py-2">{g.agents}</td>
                    <td className="px-3 py-2 text-xs">{g.own_policy ? 'own' : `follows ${g.applies}`}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground">
                      {g.updated_at ? `${new Date(g.updated_at).toLocaleString()} by ${g.updated_by ?? '?'}` : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <input value={newGroup} onChange={e => setNewGroup(e.target.value)} placeholder="Another group name"
              className="bg-muted border border-border rounded px-2 py-1.5 text-sm" />
            <button disabled={!newGroup.trim()} onClick={() => setOpen(newGroup.trim())}
              className="px-3 py-1.5 rounded border border-border text-sm hover:bg-muted disabled:opacity-40">Edit its policy</button>
          </div>
        </>
      )}
    </div>
  )
}
