import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, KeyRound, ScanSearch, ShieldCheck, ShieldOff } from 'lucide-react'
import { api } from '@/api/client'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { QueryState } from '@/components/Workspace'
import type { Agent } from '@/types'

type ResponseAction = 'isolate' | 'unisolate' | 'approve'
const LABELS: Readonly<Record<ResponseAction, string>> = {
  isolate: 'Isolate host', unisolate: 'Lift isolation', approve: 'Approve agent',
}

export function AgentActions({ agent }: { readonly agent: Agent }) {
  const [action, setAction] = useState<ResponseAction | null>(null)
  const [showToken, setShowToken] = useState(false)
  const [showScan, setShowScan] = useState(false)
  return <div className="control-cluster" onClick={event => event.stopPropagation()}>
    {agent.approved === false && <button className="ui-button" onClick={() => setAction('approve')}><Check size={14} /> Approve agent</button>}
    <button className="ui-button" onClick={() => setAction(agent.is_isolated ? 'unisolate' : 'isolate')}>
      {agent.is_isolated ? <ShieldCheck size={14} /> : <ShieldOff size={14} />}{agent.is_isolated ? 'Lift isolation' : 'Isolate host'}
    </button>
    <button className="ui-button" onClick={() => setShowScan(true)} title="Scan the disk with the agent's file engines"><ScanSearch size={14} /> Scan files</button>
    <button className="ui-button" onClick={() => setShowToken(true)} title="View the uninstall token; access is recorded in the audit log"><KeyRound size={14} /> Uninstall token</button>
    {action && <AgentResponseDialog agent={agent} action={action} onClose={() => setAction(null)} />}
    {showToken && <UninstallTokenDialog agent={agent} onClose={() => setShowToken(false)} />}
    {showScan && <FileScanDialog agent={agent} onClose={() => setShowScan(false)} />}
  </div>
}

function AgentResponseDialog({ agent, action, onClose }: {
  readonly agent: Agent
  readonly action: ResponseAction
  readonly onClose: () => void
}) {
  const client = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => action === 'unisolate' ? api.delete(`/api/agents/${agent.id}/isolate`)
      : api.post(`/api/agents/${agent.id}/${action}`),
    onSuccess: async () => { await client.invalidateQueries({ queryKey: ['agents'] }); onClose() },
  })
  const title = action === 'isolate' ? `Isolate ${agent.hostname}?`
    : action === 'unisolate' ? `Lift isolation for ${agent.hostname}?` : `Approve ${agent.hostname}?`
  return <WorkspaceDialog title={title} description={`${agent.name} · ${agent.group_id}`} busy={mutation.isPending} onClose={onClose}>
    <p>{action === 'isolate' ? 'This requests network isolation on the endpoint. It may interrupt user sessions and business traffic. The agent will apply the request when it next checks in.'
      : action === 'unisolate' ? 'This requests removal of endpoint network isolation. Verify that the host is safe to reconnect before continuing.'
        : 'This allows the agent to submit logs and receive tasks. Verify the hostname and group before approving enrollment.'}</p>
    {mutation.isError && <p role="alert" className="text-destructive">Could not complete this request. Check your permissions and try again.</p>}
    <div className="control-cluster justify-end">
      <button className="ui-button" disabled={mutation.isPending} onClick={onClose}>Cancel</button>
      <button className={`ui-button ${action === 'isolate' ? 'ui-button--danger' : 'ui-button--primary'}`} disabled={mutation.isPending} onClick={() => mutation.mutate()}>
        {mutation.isPending ? 'Submitting…' : LABELS[action]}
      </button>
    </div>
  </WorkspaceDialog>
}

interface UninstallToken {
  readonly token: string
  readonly commands: { readonly windows: string; readonly debian: string; readonly rhel: string }
}

function UninstallTokenDialog({ agent, onClose }: { readonly agent: Agent; readonly onClose: () => void }) {
  const query = useQuery<UninstallToken>({
    queryKey: ['uninstall-token', agent.id],
    queryFn: () => api.get(`/api/agents/${agent.id}/uninstall-token`).then(response => response.data),
    gcTime: 0,
  })
  return <WorkspaceDialog title={`Uninstall token · ${agent.hostname}`} description="Sensitive information · access is recorded in the audit log" onClose={onClose}>
    <p>Agent 1.8.0+ requires this token to remove the package. Share it only with an authorized endpoint administrator.</p>
    {query.isPending ? <QueryState kind="loading" title="Loading uninstall token…" />
      : query.isError ? <QueryState kind="error" title="Could not load the token" onRetry={() => { void query.refetch() }} />
        : <div className="space-y-4"><code className="block rounded border border-border bg-background p-3 break-all">{query.data.token}</code>
          {([['Windows', query.data.commands.windows], ['Debian / Ubuntu', query.data.commands.debian], ['RHEL / Fedora', query.data.commands.rhel]] as const).map(([os, command]) =>
            <div key={os}><h3 className="text-xs font-medium mb-2 text-muted-foreground">{os}</h3><pre className="rounded border border-border bg-background p-3 text-xs whitespace-pre-wrap break-all mb-0">{command}</pre></div>)}
        </div>}
  </WorkspaceDialog>
}

type ScanKind = 'quick' | 'full' | 'custom'
const SCAN_KINDS: ReadonlyArray<{ value: ScanKind; label: string; hint: string }> = [
  { value: 'quick', label: 'Quick scan', hint: 'Downloads, desktop, temp, startup and autostart folders, web roots, cron and systemd units. Minutes.' },
  { value: 'full', label: 'Full scan', hint: 'Every local disk (no network or pseudo file systems). Hours on a large disk.' },
  { value: 'custom', label: 'Custom paths', hint: 'The folders or files listed below, one per line.' },
]

function FileScanDialog({ agent, onClose }: { readonly agent: Agent; readonly onClose: () => void }) {
  const [kind, setKind] = useState<ScanKind>('quick')
  const [paths, setPaths] = useState('')
  const [queued, setQueued] = useState(false)
  const mutation = useMutation({
    mutationFn: () => api.post(`/api/agents/${agent.id}/file-scan`, {
      kind, paths: kind === 'custom' ? paths.split('\n').map(p => p.trim()).filter(Boolean) : [],
    }),
    onSuccess: () => setQueued(true),
  })
  const noPaths = kind === 'custom' && !paths.trim()
  return <WorkspaceDialog title={`Scan files · ${agent.hostname}`} description={`${agent.name} · ${agent.group_id}`} busy={mutation.isPending} onClose={onClose}>
    {queued ? <>
      <p>Scan queued. The agent starts it when it next checks in and runs it at low priority. Detections arrive as alerts; the summary (files, detections, duration) is the task result and a <code>file_scan</code> event.</p>
      <div className="control-cluster justify-end"><button className="ui-button ui-button--primary" onClick={onClose}>Close</button></div>
    </> : <>
      <div className="space-y-2">
        {SCAN_KINDS.map(k => <label key={k.value} className="flex items-start gap-2 cursor-pointer">
          <input type="radio" name="scan-kind" checked={kind === k.value} onChange={() => setKind(k.value)} className="mt-1" />
          <span><span className="block text-sm font-medium">{k.label}</span><span className="block text-xs text-muted-foreground">{k.hint}</span></span>
        </label>)}
      </div>
      {kind === 'custom' && <textarea value={paths} onChange={e => setPaths(e.target.value)} rows={4}
        placeholder={'C:\\Users\\Public\\\n/srv/upload'} className="w-full bg-muted border border-border rounded px-2 py-1.5 text-sm font-mono" />}
      <p className="text-xs text-muted-foreground">Uses the agent's engines: known-malware hashes and variants, YARA rules, static ML, and the files inside archives. Group policy exclusions apply; nothing found is quarantined unless the policy says block.</p>
      {mutation.isError && <p role="alert" className="text-destructive">Could not queue the scan. Check your permissions and try again.</p>}
      <div className="control-cluster justify-end">
        <button className="ui-button" disabled={mutation.isPending} onClick={onClose}>Cancel</button>
        <button className="ui-button ui-button--primary" disabled={mutation.isPending || noPaths} onClick={() => mutation.mutate()}>
          {mutation.isPending ? 'Queuing…' : 'Start scan'}
        </button>
      </div>
    </>}
  </WorkspaceDialog>
}
