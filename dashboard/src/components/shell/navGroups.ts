import {
  LayoutDashboard, FileText, Activity, Bell, FolderOpen,
  Brain, HeartPulse, Lock, ScanLine, Crosshair,
  Terminal, Server, BookOpen, Wrench, Shield, Bot,
  Users, Settings, Webhook, ClipboardList, FileBarChart, Grid3x3,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  minRole?: string
}

/** Workflow-grouped navigation per the Ironwatch IA
 * (docs/superpowers/specs/2026-09-07-ironwatch-ai-siem-ui-ux-design.md, section 3):
 * Command Center stands alone as the landing surface; everything else groups
 * by analyst workflow rather than backend feature taxonomy. Pages not named
 * explicitly in that IA (Logs, Decoders, MITRE Heatmap, Reports) are placed
 * by closest workflow fit, not dropped from navigation. */
export const COMMAND_CENTER: NavItem = { to: '/', label: 'Command Center', icon: LayoutDashboard }

export const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Detection',
    items: [
      { to: '/logs', label: 'Logs', icon: FileText },
      { to: '/events', label: 'Events', icon: Activity },
      { to: '/alerts', label: 'Alerts', icon: Bell },
      { to: '/hunts', label: 'Threat Hunt', icon: Crosshair },
      { to: '/rules', label: 'Rules', icon: BookOpen },
      { to: '/decoders', label: 'Decoders', icon: Wrench },
      { to: '/yara', label: 'YARA', icon: ScanLine },
      { to: '/mitre-heatmap', label: 'MITRE Heatmap', icon: Grid3x3 },
    ],
  },
  {
    label: 'Investigation',
    items: [
      { to: '/cases', label: 'Cases', icon: FolderOpen },
      // UEBA has no dedicated Entities page yet (spec Phase 3); its data feeds
      // Command Center's Exposure/Coverage section, kept reachable here meanwhile.
      { to: '/ueba', label: 'UEBA', icon: Brain },
      { to: '/assistant', label: 'SOC Assistant', icon: Bot },
    ],
  },
  {
    label: 'Agent Fleet',
    items: [
      { to: '/agents', label: 'Fleet', icon: Server },
      { to: '/live-response', label: 'Live Response', icon: Terminal },
      { to: '/fim', label: 'FIM', icon: Lock },
      { to: '/hygiene', label: 'Hygiene', icon: HeartPulse },
    ],
  },
  {
    label: 'Automation',
    items: [
      { to: '/soar', label: 'Automation', icon: Shield },
    ],
  },
  {
    label: 'Governance',
    items: [
      { to: '/reports', label: 'Reports', icon: FileBarChart },
      { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
      { to: '/webhooks', label: 'Integrations', icon: Webhook, minRole: 'admin' },
      { to: '/audit-logs', label: 'Audit Log', icon: ClipboardList, minRole: 'admin' },
      { to: '/settings', label: 'Settings', icon: Settings, minRole: 'admin' },
      { to: '/users', label: 'Users', icon: Users, minRole: 'superadmin' },
    ],
  },
]

export const ALL_NAV_ITEMS: NavItem[] = [COMMAND_CENTER, ...NAV_GROUPS.flatMap(g => g.items)]
