import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import {
  LayoutDashboard, Shield, FileText, Activity, Bell,
  BookOpen, Code, Users, Webhook, LogOut, Sun, Moon,
  ShieldAlert, GitMerge
} from 'lucide-react'
import { useState } from 'react'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, minRole: 'viewer' },
  { to: '/agents', label: 'Agents', icon: Shield, minRole: 'viewer' },
  { to: '/logs', label: 'Logs', icon: FileText, minRole: 'viewer' },
  { to: '/events', label: 'Events', icon: Activity, minRole: 'viewer' },
  { to: '/alerts', label: 'Alerts', icon: Bell, minRole: 'viewer' },
  { to: '/rules', label: 'Rules', icon: BookOpen, minRole: 'viewer' },
  { to: '/correlation', label: 'Correlation', icon: GitMerge, minRole: 'viewer' },
  { to: '/decoders', label: 'Decoders', icon: Code, minRole: 'viewer' },
  { to: '/fim', label: 'FIM', icon: ShieldAlert, minRole: 'viewer' },
  { to: '/webhooks', label: 'Webhooks', icon: Webhook, minRole: 'admin' },
  { to: '/users', label: 'Users', icon: Users, minRole: 'superadmin' },
]

export default function Sidebar() {
  const { pathname } = useLocation()
  const { user, logout, hasRole } = useAuthStore()
  const [dark, setDark] = useState(true)

  const toggleDark = () => {
    document.documentElement.classList.toggle('dark')
    setDark(!dark)
  }

  return (
    <aside className="w-56 flex-shrink-0 bg-card border-r border-border flex flex-col">
      <div className="p-4 font-bold text-lg border-b border-border">SIEM Platform</div>
      <nav className="flex-1 p-2 space-y-1">
        {nav.filter((item) => hasRole(item.minRole)).map((item) => {
          const Icon = item.icon
          const active = pathname === item.to
          return (
            <Link key={item.to} to={item.to}
              className={`flex items-center gap-2 px-3 py-2 rounded text-sm transition-colors
                ${active ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'}`}>
              <Icon size={16} />{item.label}
            </Link>
          )
        })}
      </nav>
      <div className="p-3 border-t border-border space-y-2">
        <div className="text-xs text-muted-foreground truncate">{user?.username} ({user?.role})</div>
        <div className="flex gap-2">
          <button onClick={toggleDark} className="flex-1 flex justify-center py-1 rounded hover:bg-muted">
            {dark ? <Sun size={14} /> : <Moon size={14} />}
          </button>
          <button onClick={logout} className="flex-1 flex justify-center py-1 rounded hover:bg-muted text-destructive">
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </aside>
  )
}
