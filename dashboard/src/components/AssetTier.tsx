import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import { emitToast } from '@/hooks/useToast'
import { ASSET_TIERS, assetTierLabel } from '@/lib/assetTier'

export function AssetTierChip({ tier, role }: { readonly tier: number | null | undefined; readonly role?: string | null }) {
  if (tier == null && !role) return <span className="table-secondary">Unclassified</span>
  return <span className={`tier-chip ${tier === 0 ? 'tier-chip--0' : tier === 1 ? 'tier-chip--1' : ''}`}
    title={ASSET_TIERS.find(item => item.tier === tier)?.hint}>{assetTierLabel(tier, role)}</span>
}

export function AssetTierEditor({ agentId, tier, role }: {
  readonly agentId: string
  readonly tier: number | null | undefined
  readonly role: string | null | undefined
}) {
  const qc = useQueryClient()
  const [nextTier, setNextTier] = useState(tier == null ? '' : String(tier))
  const [nextRole, setNextRole] = useState(role ?? '')
  useEffect(() => { setNextTier(tier == null ? '' : String(tier)); setNextRole(role ?? '') }, [tier, role])
  const save = useMutation({
    mutationFn: () => api.put(`/api/agents/${agentId}`, nextTier === ''
      ? { clear_asset_tier: true, asset_role: nextRole }
      : { asset_tier: Number(nextTier), asset_role: nextRole }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['agents'] })
      void qc.invalidateQueries({ queryKey: ['alerts'] })
      emitToast('Asset classification saved', 'success')
    },
    onError: () => emitToast('Could not save the asset classification', 'error'),
  })
  const changed = nextTier !== (tier == null ? '' : String(tier)) || nextRole !== (role ?? '')
  return (
    <div className="asset-tier-editor">
      <label className="field"><span>Criticality tier</span>
        <select className="ui-input" value={nextTier} onChange={event => setNextTier(event.target.value)}>
          <option value="">Unclassified</option>
          {ASSET_TIERS.map(item => <option key={item.tier} value={item.tier}>{item.label}: {item.hint}</option>)}
        </select></label>
      <label className="field"><span>Role</span>
        <input className="ui-input" value={nextRole} maxLength={100} placeholder="e.g. Finance workstation"
          onChange={event => setNextRole(event.target.value)} /></label>
      <button className="ui-button" disabled={!changed || save.isPending} onClick={() => save.mutate()}>
        {save.isPending ? 'Saving…' : 'Save classification'}</button>
    </div>
  )
}
