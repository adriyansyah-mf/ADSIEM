import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, Check, KeyRound, Trash2 } from 'lucide-react'
import { WorkspaceDialog } from '@/components/WorkspaceDialog'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import { useAuthStore } from '@/stores/auth'
import type { AgentPackage, EnrollmentKey } from '@/types'
import { firstCertB64, installCommand, isIpHost, sha256Fingerprint, type Target } from '@/lib/deployCommands'

const TARGETS: { value: Target; label: string; hint: string }[] = [
  { value: 'deb', label: 'Linux (DEB)', hint: 'Debian, Ubuntu, Kali' },
  { value: 'rpm', label: 'Linux (RPM)', hint: 'RHEL, Rocky, Alma, Fedora' },
  { value: 'windows', label: 'Windows', hint: 'Windows 10 / Server 2016+' },
]

function fmt(bytes: number) {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${(bytes / 1024).toFixed(0)} KB`
}

export default function DeployAgentModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const { data: packages = [] } = useQuery<AgentPackage[]>({
    queryKey: ['agent-packages'],
    queryFn: () => api.get('/api/agents/packages').then(r => r.data),
  })
  const { data: keys = [] } = useQuery<EnrollmentKey[]>({
    queryKey: ['enrollment-tokens'],
    queryFn: () => api.get('/api/enrollment-tokens').then(r => r.data),
  })

  const [target, setTarget] = useState<Target>('deb')
  const [server, setServer] = useState(window.location.origin)
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [label, setLabel] = useState('deployment')
  const [maxUses, setMaxUses] = useState('')
  const [expiresDays, setExpiresDays] = useState('7')
  const [approval, setApproval] = useState(false)
  const [group, setGroup] = useState(user?.group_id || 'default')
  const [copied, setCopied] = useState(false)
  // nginx serves the platform certificate (prod config); absent on plain-HTTP setups
  const { data: cert } = useQuery<{ b64: string; fingerprint: string } | null>({
    queryKey: ['platform-ca'],
    queryFn: async () => {
      const r = await fetch('/api/agents/platform-ca.pem')
      const b64 = r.ok ? firstCertB64(await r.text()) : null
      return b64 ? { b64, fingerprint: await sha256Fingerprint(b64) } : null
    },
    staleTime: Infinity,
  })
  // default on for https://<IP>: an IP address can't have a publicly trusted certificate
  const [trustCert, setTrustCert] = useState<boolean | null>(null)
  const trusting = Boolean(cert) && (trustCert ?? (server.startsWith('https:') && isIpHost(server)))

  const createKey = useMutation({
    mutationFn: () => api.post('/api/enrollment-tokens', {
      label,
      group_id: group || undefined,
      max_uses: maxUses ? parseInt(maxUses, 10) : null,
      expires_at: expiresDays ? new Date(Date.now() + parseInt(expiresDays, 10) * 86_400_000).toISOString() : null,
      require_approval: approval,
    }).then(r => r.data as { token: string }),
    onSuccess: (r) => {
      setKey(r.token)
      qc.invalidateQueries({ queryKey: ['enrollment-tokens'] })
      emitToast('Enrollment key created — it is shown only once', 'success')
    },
    onError: () => emitToast('Failed to create enrollment key', 'error'),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.delete(`/api/enrollment-tokens/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['enrollment-tokens'] }),
  })

  // Windows: the MSI when the server has one, else the zip + install.ps1
  const pkg = (target === 'windows' ? packages.find(p => p.type === 'msi') : undefined)
    ?? packages.find(p => p.type === target && (p.arch === 'amd64' || p.arch === 'x86_64'))
    ?? packages.find(p => p.type === target)
  const serverClean = server.trim().replace(/\/+$/, '')
  const command = useMemo(
    () => (pkg && key
      ? installCommand(target, pkg, serverClean, key.trim(), target === 'windows' ? '' : name.trim(),
                       trusting && cert ? cert.b64 : null)
      : ''),
    [pkg, key, target, serverClean, name, trusting, cert],
  )

  const copy = async () => {
    await navigator.clipboard.writeText(command)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  const input = 'ui-input'
  const label_ = 'block text-xs font-semibold mb-1'

  return (
    <WorkspaceDialog title="Deploy agent" description="Run one command on the host to download, enroll, and start the agent." onClose={onClose} busy={createKey.isPending || revoke.isPending} wide>
        <div className="space-y-5 text-sm">
          {/* 1. OS */}
          <div>
            <div className={label_}>1. Operating system</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {TARGETS.map(t => {
                const p = (t.value === 'windows' ? packages.find(x => x.type === 'msi') : undefined)
                  ?? packages.find(x => x.type === t.value)
                return (
                  <button key={t.value} onClick={() => setTarget(t.value)} disabled={!p}
                    aria-pressed={target === t.value}
                    className={`text-left px-3 py-2 rounded border border-border ${target === t.value ? 'bg-muted' : 'bg-background'} disabled:opacity-40`}>
                    <div className="font-medium">{t.label}</div>
                    <div className="text-xs text-muted-foreground">{p ? `v${p.version} · ${p.arch} · ${fmt(p.size_bytes)}` : 'package not built'}</div>
                    <div className="text-xs text-muted-foreground">{t.hint}</div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* 2. Server */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className={label_}>2. Server address (as the host reaches it)</label>
              <input aria-label="Server address" value={server} onChange={e => setServer(e.target.value)} className={input} />
            </div>
            {target !== 'windows' && (
              <div>
                <label className={label_}>Agent name (optional, default: hostname)</label>
                <input aria-label="Agent name" value={name} onChange={e => setName(e.target.value)} placeholder="web-01" className={input} />
              </div>
            )}
          </div>
          {cert && (
            <div className="rounded border border-border p-2 text-xs space-y-1">
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={trusting} onChange={e => setTrustCert(e.target.checked)} />
                <span>
                  Make the host trust this server&apos;s certificate (needed for a self-signed one — otherwise the
                  download and the agent fail TLS verification)
                </span>
              </label>
              {trusting && (
                <div className="text-muted-foreground break-all">
                  SHA-256 <span className="font-mono">{cert.fingerprint}</span> — compare with{' '}
                  <span className="font-mono">openssl x509 -noout -fingerprint -sha256 -in nginx/certs/cert.pem</span> on the server
                </div>
              )}
            </div>
          )}

          {/* 3. Key */}
          <div>
            <div className={label_}>3. Enrollment key</div>
            <div className="rounded border border-border p-3 space-y-2">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="col-span-2">
                  <label className="text-xs text-muted-foreground">Label</label>
                  <input aria-label="Enrollment key label" value={label} onChange={e => setLabel(e.target.value)} className={input} />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">Max agents (blank = ∞)</label>
                  <input aria-label="Maximum agents" value={maxUses} onChange={e => setMaxUses(e.target.value.replace(/\D/g, ''))} placeholder="∞" className={input} />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">Expires in days</label>
                  <input aria-label="Expires in days" value={expiresDays} onChange={e => setExpiresDays(e.target.value.replace(/\D/g, ''))} placeholder="never" className={input} />
                </div>
              </div>
              <div className="control-cluster">
                {user?.role === 'superadmin' && (
                  <label className="flex items-center gap-1 text-xs">Group
                    <input value={group} onChange={e => setGroup(e.target.value)} className="ui-input w-28" />
                  </label>
                )}
                <label className="flex items-center gap-1 text-xs cursor-pointer">
                  <input type="checkbox" checked={approval} onChange={e => setApproval(e.target.checked)} />
                  New agents wait for approval
                </label>
                <button onClick={() => createKey.mutate()} disabled={createKey.isPending}
                  className="ui-button ml-auto">
                  <KeyRound size={12} /> Create key
                </button>
              </div>
              <div>
                <label className="text-xs text-muted-foreground">…or paste an existing key</label>
                <input aria-label="Existing enrollment key" value={key} onChange={e => setKey(e.target.value)} placeholder="enrollment key" className={`${input} font-mono`} />
              </div>
            </div>
          </div>

          {/* 4. Command */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <div className={label_}>4. Run on the host{target === 'windows' ? ' (PowerShell as Administrator)' : ''}</div>
              {command && (
                <button onClick={copy} className="ui-button">
                  {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy'}
                </button>
              )}
            </div>
            <pre className="rounded border border-border bg-muted/30 p-3 text-xs font-mono whitespace-pre-wrap break-all min-h-[3rem]">
              {command || (pkg ? 'Create or paste an enrollment key to get the command.' : 'No package for this OS on the server yet.')}
            </pre>
            <div className="text-xs text-muted-foreground mt-1">
              {target === 'windows'
                ? `${pkg?.type === 'msi' ? 'MSI: the same msiexec line works from Intune/SCCM.' : 'Zip + install.ps1.'} Installs the SIEMAgent service; config and agent.log in C:\\ProgramData\\SIEMAgent. Auditing of logons, processes and PowerShell is switched on.`
                : 'Re-point an installed agent with: sudo siem-agent-configure --server <url> --key <key> · logs: journalctl -u siem-agent -f'}
            </div>
          </div>

          {/* keys */}
          {keys.length > 0 && (
            <div>
              <div className={label_}>Active enrollment keys</div>
              <div className="rounded border border-border divide-y divide-border">
                {keys.map(k => {
                  const spent = k.max_uses != null && k.use_count >= k.max_uses
                  const expired = k.expires_at != null && new Date(k.expires_at) < new Date()
                  return (
                    <div key={k.id} className="control-cluster px-3 py-2 text-xs">
                      <span className="font-medium">{k.label || '(no label)'}</span>
                      <span className="text-muted-foreground">group {k.group_id}</span>
                      <span className="text-muted-foreground">{k.use_count}/{k.max_uses ?? '∞'} used</span>
                      {k.require_approval && <span className="text-amber-400">approval</span>}
                      {(spent || expired) && <span className="text-muted-foreground">{spent ? 'spent' : 'expired'}</span>}
                      {k.expires_at && !expired && <span className="text-muted-foreground">expires {new Date(k.expires_at).toLocaleDateString()}</span>}
                      <button onClick={() => revoke.mutate(k.id)} disabled={revoke.isPending} title="Revoke" aria-label={`Revoke enrollment key ${k.label || k.id}`} className="ui-icon-button ml-auto text-destructive">
                        <Trash2 size={12} />
                      </button>
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
    </WorkspaceDialog>
  )
}
