// Asset criticality tiers (server-api models.Agent.asset_tier).
export const ASSET_TIERS: readonly { readonly tier: number; readonly label: string; readonly hint: string }[] = [
  { tier: 0, label: 'Tier 0', hint: 'Identity and control plane: domain controllers, identity provider' },
  { tier: 1, label: 'Tier 1', hint: 'Business servers and applications' },
  { tier: 2, label: 'Tier 2', hint: 'User workstations' },
  { tier: 3, label: 'Tier 3', hint: 'Lab and test systems' },
]

export function assetTierLabel(tier: number | null | undefined, role?: string | null): string {
  if (tier == null) return role || 'Unclassified'
  const label = ASSET_TIERS.find(item => item.tier === tier)?.label ?? `Tier ${tier}`
  return role ? `${label} · ${role}` : label
}
