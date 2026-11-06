import { useState } from 'react'
import { Panel } from '@/components/Workspace'
import { useBlockCaseIps, useCaseEvidence, useCaseRemediations } from '@/hooks/useCaseEvidence'
import { useAuthStore } from '@/stores/auth'

export function CaseRemediations({ caseId }: { caseId: string }) {
  const evidence = useCaseEvidence(caseId)
  const tasks = useCaseRemediations(caseId)
  const block = useBlockCaseIps(caseId)
  const canManage = useAuthStore(state => state.hasRole('admin'))
  const [ips, setIps] = useState<string[]>([])
  const [agents, setAgents] = useState<string[]>([])
  const [duration, setDuration] = useState(3600)
  const [requestId, setRequestId] = useState(() => crypto.randomUUID())
  const hosts = new Map<string, string>()
  for (const alert of evidence.data?.alerts ?? []) {
    if (alert.status === 'linked' && alert.agent_id) hosts.set(alert.agent_id, alert.hostname ?? alert.agent_id)
  }
  const selectedIps = ips.filter(ip => evidence.data?.blockable_ips.includes(ip))
  const selectedAgents = agents.filter(id => hosts.has(id))
  const count = selectedIps.length * selectedAgents.length
  function toggle(value: string, values: string[], setter: (values: string[]) => void) {
    setter(values.includes(value) ? values.filter(v => v !== value) : [...values, value])
    setRequestId(crypto.randomUUID())
    block.reset()
  }
  return <Panel title="Remediations">
    <p className="text-sm mb-3">Block selected IPs on selected hosts. Domain and file-hash indicators require a different response action.</p>
    {evidence.isError && <p role="alert">Could not load remediation targets.</p>}
    {evidence.isPending && <p>Loading targets…</p>}
    <fieldset disabled={block.isPending || !canManage}>
      <legend>IP indicators</legend>
      {evidence.data?.blockable_ips.map(ip => <label key={ip} className="flex gap-2 py-1 font-mono text-xs">
        <input type="checkbox" checked={ips.includes(ip)} onChange={() => toggle(ip, ips, setIps)} />{ip}
      </label>)}
      {evidence.data?.blockable_ips.length === 0 && <p>No blockable IPs in linked evidence.</p>}
      <div className="mt-3">Target hosts</div>
      {[...hosts].map(([id, name]) => <label key={id} className="flex gap-2 py-1 text-sm">
        <input type="checkbox" checked={agents.includes(id)} onChange={() => toggle(id, agents, setAgents)} />{name}
      </label>)}
      {hosts.size === 0 && !evidence.isPending && <p>No agent linked to the case evidence.</p>}
      <label className="field my-3"><span>Block duration</span><select className="ui-input" value={duration} onChange={event => {
        setDuration(Number(event.target.value)); setRequestId(crypto.randomUUID()); block.reset()
      }}>
        <option value={3600}>1 hour</option><option value={86400}>24 hours</option><option value={604800}>7 days</option>
      </select></label>
      <p className="text-sm mb-2">{selectedIps.length} IPs × {selectedAgents.length} hosts = {count} tasks (maximum 100).</p>
      <button className="ui-button ui-button--danger" disabled={count === 0 || count > 100 || block.isPending || block.isSuccess}
        onClick={() => block.mutate({ request_id: requestId, ips: selectedIps, agent_ids: selectedAgents, duration_seconds: duration })}>
        {block.isPending ? 'Queuing…' : `Queue ${count} block tasks`}
      </button>
    </fieldset>
    {!canManage && <p className="text-sm">Agent management permission is required to queue remediation.</p>}
    {block.isError && <p role="alert">Could not queue tasks. Check the evidence and permissions, then retry.</p>}
    {block.isSuccess && <p role="status">{block.data.length} tasks queued. Check execution status below.</p>}
    <div className="mt-4 text-sm">Recent remediation tasks</div>
    {tasks.isError && <p role="alert">Could not load execution status.</p>}
    {tasks.data?.map(task => <div key={task.id} className="border-b py-2 text-xs">
      <div>{String(task.params.ip ?? '')} → {hosts.get(task.agent_id ?? '') ?? task.agent_id}</div>
      <strong>{task.status}</strong>{task.error && <p role="alert">{task.error}</p>}
    </div>)}
  </Panel>
}
