import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { Plus } from 'lucide-react'
import { PageHeader } from '@/components/ui/PageHeader'
import { PlaybookEditor } from '@/components/soar/PlaybookEditor'
import { PlaybookList } from '@/components/soar/PlaybookList'
import { ExecutionsPanel } from '@/components/soar/ExecutionsPanel'
import { S } from '@/components/soar/styles'
import type { Playbook, SoarExecution } from '@/components/soar/types'

export default function SoarPage() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<Playbook | null | undefined>(undefined)

  const { data: playbooks = [], isLoading } = useQuery<Playbook[]>({
    queryKey: ['soar-playbooks'],
    queryFn: () => api.get('/api/soar/playbooks').then(r => r.data),
  })

  const { data: executions = [] } = useQuery<SoarExecution[]>({
    queryKey: ['soar-executions'],
    queryFn: () => api.get('/api/soar/executions').then(r => r.data),
    refetchInterval: 15000,
  })

  const approve = useMutation({
    mutationFn: ({ id, key }: { id: string; key: string }) =>
      api.post(`/api/soar/executions/${id}/approve`, { idempotency_key: key }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-executions'] }),
  })

  const rollback = useMutation({
    mutationFn: ({ id, key }: { id: string; key: string }) =>
      api.post(`/api/soar/executions/${id}/rollback`, { idempotency_key: key }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-executions'] }),
  })

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/api/soar/playbooks/${id}`, { is_enabled: enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-playbooks'] }),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.delete(`/api/soar/playbooks/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['soar-playbooks'] }),
  })

  return (
    <div>
      {editing !== undefined && (
        <PlaybookEditor playbook={editing} onClose={() => setEditing(undefined)} />
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <PageHeader title="SOAR playbooks" subtitle="Define trigger conditions and automated response actions" className="!mb-0" />
        <button style={S.btn()} onClick={() => setEditing(null)}>
          <Plus size={14} /> New Playbook
        </button>
      </div>

      <PlaybookList playbooks={playbooks} isLoading={isLoading} onEdit={setEditing} toggle={toggle} del={del} />

      <ExecutionsPanel executions={executions} approve={approve} rollback={rollback} />
    </div>
  )
}
