# SIEM Platform — Plan 4: React Dashboard

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full React + Vite + TypeScript dashboard with dark mode default, JWT auth, role-based sidebar, and all pages (Login, Dashboard, Agents, Logs, Events, Alerts, Rules, Decoders, Users, Webhooks).

**Architecture:** SPA served by nginx in Docker. Zustand for auth state, TanStack Query for server state with auto-refresh, axios with interceptor for token refresh. shadcn/ui + TailwindCSS for UI. CodeMirror for YAML editing.

**Tech Stack:** React 18, Vite 5, TypeScript, TailwindCSS 3, shadcn/ui, Zustand, TanStack Query v5, axios, CodeMirror 6, react-router-dom v6, date-fns

**Prerequisite:** Plans 1–3 must be complete. server-api must be reachable at `VITE_API_URL`.

---

## File Map

```
dashboard/
├── Dockerfile
├── index.html
├── package.json
├── vite.config.ts
├── tailwind.config.ts
├── tsconfig.json
├── tsconfig.app.json
├── components.json              (shadcn config)
└── src/
    ├── main.tsx
    ├── App.tsx
    ├── types/
    │   └── index.ts             — all shared TypeScript interfaces
    ├── api/
    │   └── client.ts            — axios instance + interceptors
    ├── stores/
    │   └── auth.ts              — Zustand auth store
    ├── hooks/
    │   ├── useAlerts.ts
    │   ├── useAgents.ts
    │   ├── useLogs.ts
    │   ├── useEvents.ts
    │   ├── useRules.ts
    │   ├── useDecoders.ts
    │   ├── useUsers.ts
    │   └── useWebhooks.ts
    ├── components/
    │   ├── Layout.tsx            — sidebar + topbar wrapper
    │   ├── Sidebar.tsx           — role-filtered nav
    │   ├── ProtectedRoute.tsx    — role/permission guard
    │   ├── SeverityBadge.tsx
    │   ├── StatusBadge.tsx
    │   ├── DataTable.tsx         — reusable table with sort/search/pagination
    │   ├── YamlEditor.tsx        — CodeMirror YAML editor modal
    │   └── AlertDetailModal.tsx
    └── pages/
        ├── LoginPage.tsx
        ├── DashboardPage.tsx
        ├── AgentsPage.tsx
        ├── LogSourcesPage.tsx
        ├── LogsPage.tsx
        ├── EventsPage.tsx
        ├── AlertsPage.tsx
        ├── RulesPage.tsx
        ├── DecodersPage.tsx
        ├── UsersPage.tsx
        └── WebhooksPage.tsx
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `dashboard/package.json`
- Create: `dashboard/vite.config.ts`
- Create: `dashboard/tailwind.config.ts`
- Create: `dashboard/tsconfig.json`
- Create: `dashboard/tsconfig.app.json`
- Create: `dashboard/index.html`
- Create: `dashboard/Dockerfile`

- [ ] **Step 1: Write package.json**

```json
{
  "name": "siem-dashboard",
  "private": true,
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "@codemirror/lang-yaml": "^6.1.1",
    "@codemirror/theme-one-dark": "^6.1.2",
    "@radix-ui/react-dialog": "^1.1.2",
    "@radix-ui/react-dropdown-menu": "^2.1.2",
    "@radix-ui/react-label": "^2.1.0",
    "@radix-ui/react-select": "^2.1.2",
    "@radix-ui/react-slot": "^1.1.0",
    "@radix-ui/react-toast": "^1.2.2",
    "@tanstack/react-query": "^5.59.20",
    "axios": "^1.7.9",
    "class-variance-authority": "^0.7.1",
    "clsx": "^2.1.1",
    "codemirror": "^6.0.1",
    "date-fns": "^4.1.0",
    "lucide-react": "^0.460.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.28.0",
    "tailwind-merge": "^2.5.4",
    "tailwindcss-animate": "^1.0.7",
    "zustand": "^5.0.1"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.3",
    "autoprefixer": "^10.4.20",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.15",
    "typescript": "~5.6.2",
    "vite": "^5.4.10"
  }
}
```

- [ ] **Step 2: Write vite.config.ts**

```typescript
// dashboard/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: process.env.VITE_API_URL || 'http://localhost:8000', changeOrigin: true },
      '/health': { target: process.env.VITE_API_URL || 'http://localhost:8000', changeOrigin: true },
    },
  },
})
```

- [ ] **Step 3: Write tailwind.config.ts**

```typescript
// dashboard/tailwind.config.ts
import type { Config } from 'tailwindcss'
import animate from 'tailwindcss-animate'

export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: { DEFAULT: 'hsl(var(--primary))', foreground: 'hsl(var(--primary-foreground))' },
        muted: { DEFAULT: 'hsl(var(--muted))', foreground: 'hsl(var(--muted-foreground))' },
        card: { DEFAULT: 'hsl(var(--card))', foreground: 'hsl(var(--card-foreground))' },
        destructive: { DEFAULT: 'hsl(var(--destructive))', foreground: 'hsl(var(--destructive-foreground))' },
      },
      borderRadius: { lg: 'var(--radius)', md: 'calc(var(--radius) - 2px)', sm: 'calc(var(--radius) - 4px)' },
    },
  },
  plugins: [animate],
} satisfies Config
```

- [ ] **Step 4: Write index.html**

```html
<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SIEM Platform</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 5: Write Dockerfile**

```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx-spa.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

- [ ] **Step 6: Write nginx-spa.conf (SPA fallback)**

```nginx
# dashboard/nginx-spa.conf
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

- [ ] **Step 7: Install dependencies**

```bash
cd dashboard && npm install
```

- [ ] **Step 8: Commit**

```bash
git add dashboard/
git commit -m "feat: scaffold React dashboard project"
```

---

## Task 2: Types & API Client

**Files:**
- Create: `dashboard/src/types/index.ts`
- Create: `dashboard/src/api/client.ts`

- [ ] **Step 1: Write types/index.ts**

```typescript
// dashboard/src/types/index.ts

export interface User {
  id: string
  username: string
  email: string
  role: string
  group_id: string
  is_active: boolean
  created_at: string
}

export interface Agent {
  id: string
  name: string
  hostname: string
  group_id: string
  version: string | null
  status: 'online' | 'offline'
  last_seen_at: string | null
  enrolled_at: string
  log_sources: LogSource[]
}

export interface LogSource {
  id: string
  path: string
  log_type: string
  is_enabled: boolean
}

export interface RawLog {
  id: string
  agent_id: string | null
  log_type: string | null
  raw_message: string
  received_at: string
}

export interface Event {
  id: string
  agent_id: string | null
  group_id: string
  decoded_fields: Record<string, unknown>
  event_category: string | null
  event_action: string | null
  source_ip: string | null
  user_name: string | null
  created_at: string
}

export interface Alert {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'new' | 'in_progress' | 'resolved' | 'false_positive'
  rule_id: string | null
  event_id: string | null
  agent_id: string | null
  group_id: string
  source_ip: string | null
  hostname: string | null
  assignee_id: string | null
  created_at: string
  updated_at: string
  notes: AlertNote[]
}

export interface AlertNote {
  id: string
  author_id: string | null
  content: string
  created_at: string
}

export interface Rule {
  id: string
  title: string
  description: string | null
  content: string
  level: string
  tags: string[]
  mitre_tags: string[]
  version: number
  is_enabled: boolean
  group_id: string | null
  created_at: string
  updated_at: string
}

export interface Decoder {
  id: string
  name: string
  log_type: string
  content: string
  priority: number
  is_enabled: boolean
  created_at: string
  updated_at: string
}

export interface Webhook {
  id: string
  name: string
  url: string
  is_enabled: boolean
  group_id: string | null
  created_at: string
}

export interface PaginatedResponse<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export type Role = 'superadmin' | 'admin' | 'analyst' | 'viewer'

export const ROLE_HIERARCHY: Record<Role, number> = {
  superadmin: 4, admin: 3, analyst: 2, viewer: 1,
}
```

- [ ] **Step 2: Write api/client.ts**

```typescript
// dashboard/src/api/client.ts
import axios from 'axios'
import { useAuthStore } from '@/stores/auth'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  withCredentials: true,
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

let isRefreshing = false
let refreshQueue: Array<(token: string) => void> = []

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true
      if (isRefreshing) {
        return new Promise((resolve) => {
          refreshQueue.push((token) => {
            original.headers.Authorization = `Bearer ${token}`
            resolve(api(original))
          })
        })
      }
      isRefreshing = true
      try {
        const { data } = await axios.post('/api/auth/refresh', {}, { withCredentials: true })
        useAuthStore.getState().setAccessToken(data.access_token)
        refreshQueue.forEach((cb) => cb(data.access_token))
        refreshQueue = []
        original.headers.Authorization = `Bearer ${data.access_token}`
        return api(original)
      } catch {
        useAuthStore.getState().logout()
        window.location.href = '/login'
        return Promise.reject(error)
      } finally {
        isRefreshing = false
      }
    }
    return Promise.reject(error)
  }
)
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/types/ dashboard/src/api/
git commit -m "feat: add TypeScript types and axios client with token refresh interceptor"
```

---

## Task 3: Auth Store & Main Entry

**Files:**
- Create: `dashboard/src/stores/auth.ts`
- Create: `dashboard/src/main.tsx`
- Create: `dashboard/src/App.tsx`
- Create: `dashboard/src/index.css`

- [ ] **Step 1: Write stores/auth.ts**

```typescript
// dashboard/src/stores/auth.ts
import { create } from 'zustand'
import type { User } from '@/types'

interface AuthState {
  accessToken: string | null
  user: User | null
  setAccessToken: (token: string) => void
  setUser: (user: User) => void
  logout: () => void
  hasRole: (minRole: string) => boolean
}

const ROLE_ORDER = ['viewer', 'analyst', 'admin', 'superadmin']

export const useAuthStore = create<AuthState>((set, get) => ({
  accessToken: null,
  user: null,
  setAccessToken: (token) => set({ accessToken: token }),
  setUser: (user) => set({ user }),
  logout: () => set({ accessToken: null, user: null }),
  hasRole: (minRole) => {
    const user = get().user
    if (!user) return false
    return ROLE_ORDER.indexOf(user.role) >= ROLE_ORDER.indexOf(minRole)
  },
}))
```

- [ ] **Step 2: Write index.css (CSS variables for dark/light theme)**

```css
/* dashboard/src/index.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 222.2 84% 4.9%;
    --card: 0 0% 100%;
    --card-foreground: 222.2 84% 4.9%;
    --border: 214.3 31.8% 91.4%;
    --primary: 222.2 47.4% 11.2%;
    --primary-foreground: 210 40% 98%;
    --muted: 210 40% 96.1%;
    --muted-foreground: 215.4 16.3% 46.9%;
    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 210 40% 98%;
    --radius: 0.5rem;
  }
  .dark {
    --background: 222.2 84% 4.9%;
    --foreground: 210 40% 98%;
    --card: 222.2 84% 4.9%;
    --card-foreground: 210 40% 98%;
    --border: 217.2 32.6% 17.5%;
    --primary: 210 40% 98%;
    --primary-foreground: 222.2 47.4% 11.2%;
    --muted: 217.2 32.6% 17.5%;
    --muted-foreground: 215 20.2% 65.1%;
    --destructive: 0 62.8% 30.6%;
    --destructive-foreground: 210 40% 98%;
    --radius: 0.5rem;
  }
}

* { @apply border-border; }
body { @apply bg-background text-foreground; }
```

- [ ] **Step 3: Write main.tsx**

```tsx
// dashboard/src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 10_000 } },
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>
)
```

- [ ] **Step 4: Write App.tsx**

```tsx
// dashboard/src/App.tsx
import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'
import ProtectedRoute from '@/components/ProtectedRoute'
import Layout from '@/components/Layout'
import LoginPage from '@/pages/LoginPage'
import DashboardPage from '@/pages/DashboardPage'
import AgentsPage from '@/pages/AgentsPage'
import LogSourcesPage from '@/pages/LogSourcesPage'
import LogsPage from '@/pages/LogsPage'
import EventsPage from '@/pages/EventsPage'
import AlertsPage from '@/pages/AlertsPage'
import RulesPage from '@/pages/RulesPage'
import DecodersPage from '@/pages/DecodersPage'
import UsersPage from '@/pages/UsersPage'
import WebhooksPage from '@/pages/WebhooksPage'

export default function App() {
  const { accessToken, setUser, logout } = useAuthStore()

  useEffect(() => {
    if (accessToken) {
      api.get('/api/auth/me').then((r) => setUser(r.data)).catch(() => logout())
    }
  }, [accessToken])

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute minRole="viewer" />}>
          <Route element={<Layout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/agents" element={<AgentsPage />} />
            <Route path="/agents/:id/sources" element={<ProtectedRoute minRole="admin"><LogSourcesPage /></ProtectedRoute>} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/decoders" element={<DecodersPage />} />
            <Route path="/users" element={<ProtectedRoute minRole="superadmin"><UsersPage /></ProtectedRoute>} />
            <Route path="/webhooks" element={<ProtectedRoute minRole="admin"><WebhooksPage /></ProtectedRoute>} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
```

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/
git commit -m "feat: add auth store, main entry, app router"
```

---

## Task 4: Shared Components

**Files:**
- Create: `dashboard/src/components/ProtectedRoute.tsx`
- Create: `dashboard/src/components/Layout.tsx`
- Create: `dashboard/src/components/Sidebar.tsx`
- Create: `dashboard/src/components/SeverityBadge.tsx`
- Create: `dashboard/src/components/StatusBadge.tsx`
- Create: `dashboard/src/components/DataTable.tsx`

- [ ] **Step 1: Write ProtectedRoute.tsx**

```tsx
// dashboard/src/components/ProtectedRoute.tsx
import { Navigate, Outlet } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'

interface Props {
  minRole?: string
  children?: React.ReactNode
}

export default function ProtectedRoute({ minRole = 'viewer', children }: Props) {
  const { accessToken, hasRole } = useAuthStore()
  if (!accessToken) return <Navigate to="/login" replace />
  if (minRole && !hasRole(minRole)) return <Navigate to="/" replace />
  return children ? <>{children}</> : <Outlet />
}
```

- [ ] **Step 2: Write SeverityBadge.tsx**

```tsx
// dashboard/src/components/SeverityBadge.tsx
const map: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
}
export default function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${map[severity] ?? 'bg-gray-400 text-white'}`}>
      {severity}
    </span>
  )
}
```

- [ ] **Step 3: Write StatusBadge.tsx**

```tsx
// dashboard/src/components/StatusBadge.tsx
const map: Record<string, string> = {
  new: 'bg-blue-600 text-white',
  in_progress: 'bg-yellow-500 text-black',
  resolved: 'bg-green-600 text-white',
  false_positive: 'bg-gray-500 text-white',
  online: 'bg-green-500 text-white',
  offline: 'bg-gray-600 text-white',
}
export default function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${map[status] ?? 'bg-gray-400 text-white'}`}>
      {status.replace('_', ' ')}
    </span>
  )
}
```

- [ ] **Step 4: Write DataTable.tsx**

```tsx
// dashboard/src/components/DataTable.tsx
import { useState } from 'react'

interface Column<T> {
  key: string
  header: string
  render: (row: T) => React.ReactNode
  sortable?: boolean
}

interface Props<T> {
  columns: Column<T>[]
  data: T[]
  total: number
  page: number
  pageSize: number
  onPageChange: (page: number) => void
  onSearch?: (q: string) => void
  searchPlaceholder?: string
  onRowClick?: (row: T) => void
}

export default function DataTable<T extends { id: string }>({
  columns, data, total, page, pageSize,
  onPageChange, onSearch, searchPlaceholder = 'Search...', onRowClick,
}: Props<T>) {
  const [search, setSearch] = useState('')
  const totalPages = Math.ceil(total / pageSize)

  const handleSearch = (v: string) => {
    setSearch(v)
    onSearch?.(v)
  }

  return (
    <div className="space-y-3">
      {onSearch && (
        <input
          value={search}
          onChange={(e) => handleSearch(e.target.value)}
          placeholder={searchPlaceholder}
          className="w-full px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
        />
      )}
      <div className="rounded border border-border overflow-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted text-muted-foreground">
            <tr>
              {columns.map((col) => (
                <th key={col.key} className="px-4 py-2 text-left font-medium whitespace-nowrap">
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr><td colSpan={columns.length} className="text-center py-8 text-muted-foreground">No data</td></tr>
            ) : data.map((row) => (
              <tr
                key={row.id}
                onClick={() => onRowClick?.(row)}
                className={`border-t border-border hover:bg-muted/50 transition-colors ${onRowClick ? 'cursor-pointer' : ''}`}
              >
                {columns.map((col) => (
                  <td key={col.key} className="px-4 py-2">{col.render(row)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <span>{total} total</span>
        <div className="flex gap-2">
          <button disabled={page <= 1} onClick={() => onPageChange(page - 1)}
            className="px-3 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted">Prev</button>
          <span className="px-2 py-1">{page} / {totalPages || 1}</span>
          <button disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}
            className="px-3 py-1 rounded border border-border disabled:opacity-40 hover:bg-muted">Next</button>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 5: Write Sidebar.tsx**

```tsx
// dashboard/src/components/Sidebar.tsx
import { Link, useLocation } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import {
  LayoutDashboard, Shield, FileText, Activity, Bell,
  BookOpen, Code, Users, Webhook, LogOut, Sun, Moon
} from 'lucide-react'
import { useState } from 'react'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, minRole: 'viewer' },
  { to: '/agents', label: 'Agents', icon: Shield, minRole: 'viewer' },
  { to: '/logs', label: 'Logs', icon: FileText, minRole: 'viewer' },
  { to: '/events', label: 'Events', icon: Activity, minRole: 'viewer' },
  { to: '/alerts', label: 'Alerts', icon: Bell, minRole: 'viewer' },
  { to: '/rules', label: 'Rules', icon: BookOpen, minRole: 'viewer' },
  { to: '/decoders', label: 'Decoders', icon: Code, minRole: 'viewer' },
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
```

- [ ] **Step 6: Write Layout.tsx**

```tsx
// dashboard/src/components/Layout.tsx
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'

export default function Layout() {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  )
}
```

- [ ] **Step 7: Commit**

```bash
git add dashboard/src/components/
git commit -m "feat: add shared components (Layout, Sidebar, DataTable, badges)"
```

---

## Task 5: React Query Hooks

**Files:**
- Create: `dashboard/src/hooks/useAlerts.ts`
- Create: `dashboard/src/hooks/useAgents.ts`
- Create: `dashboard/src/hooks/useLogs.ts`
- Create: `dashboard/src/hooks/useEvents.ts`
- Create: `dashboard/src/hooks/useRules.ts`
- Create: `dashboard/src/hooks/useDecoders.ts`
- Create: `dashboard/src/hooks/useUsers.ts`
- Create: `dashboard/src/hooks/useWebhooks.ts`

- [ ] **Step 1: Write useAlerts.ts**

```typescript
// dashboard/src/hooks/useAlerts.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Alert, PaginatedResponse } from '@/types'

export function useAlerts(page = 1, pageSize = 25, status?: string, severity?: string) {
  return useQuery<PaginatedResponse<Alert>>({
    queryKey: ['alerts', page, pageSize, status, severity],
    queryFn: () => api.get('/api/alerts', { params: { page, page_size: pageSize, status, severity } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}

export function useUpdateAlert() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: { status?: string; assignee_id?: string } }) =>
      api.put(`/api/alerts/${id}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}

export function useAddAlertNote() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, content }: { id: string; content: string }) =>
      api.post(`/api/alerts/${id}/notes`, { content }).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['alerts'] }),
  })
}
```

- [ ] **Step 2: Write useAgents.ts**

```typescript
// dashboard/src/hooks/useAgents.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Agent, LogSource, PaginatedResponse } from '@/types'

export function useAgents(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Agent>>({
    queryKey: ['agents', page, pageSize],
    queryFn: () => api.get('/api/agents', { params: { page, page_size: pageSize } }).then(r => r.data),
    refetchInterval: 30_000,
  })
}

export function useLogSources(agentId: string) {
  return useQuery<LogSource[]>({
    queryKey: ['log-sources', agentId],
    queryFn: () => api.get(`/api/agents/${agentId}/log-sources`).then(r => r.data),
  })
}

export function useAddLogSource(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { path: string; log_type: string; is_enabled: boolean }) =>
      api.post(`/api/agents/${agentId}/log-sources`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources', agentId] }),
  })
}

export function useUpdateLogSource(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ sourceId, data }: { sourceId: string; data: Partial<LogSource> }) =>
      api.put(`/api/agents/${agentId}/log-sources/${sourceId}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources', agentId] }),
  })
}

export function useDeleteLogSource(agentId: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (sourceId: string) =>
      api.delete(`/api/agents/${agentId}/log-sources/${sourceId}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['log-sources', agentId] }),
  })
}
```

- [ ] **Step 3: Write useLogs.ts, useEvents.ts, useRules.ts, useDecoders.ts, useUsers.ts, useWebhooks.ts**

```typescript
// dashboard/src/hooks/useLogs.ts
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, RawLog } from '@/types'
export function useLogs(page = 1, pageSize = 25, search?: string) {
  return useQuery<PaginatedResponse<RawLog>>({
    queryKey: ['logs', page, pageSize, search],
    queryFn: () => api.get('/api/logs', { params: { page, page_size: pageSize, search } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}
```

```typescript
// dashboard/src/hooks/useEvents.ts
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Event, PaginatedResponse } from '@/types'
export function useEvents(page = 1, pageSize = 25, source_ip?: string) {
  return useQuery<PaginatedResponse<Event>>({
    queryKey: ['events', page, pageSize, source_ip],
    queryFn: () => api.get('/api/events', { params: { page, page_size: pageSize, source_ip } }).then(r => r.data),
    refetchInterval: 15_000,
  })
}
```

```typescript
// dashboard/src/hooks/useRules.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, Rule } from '@/types'
export function useRules(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Rule>>({
    queryKey: ['rules', page, pageSize],
    queryFn: () => api.get('/api/rules', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}
export function useCreateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Rule>) => api.post('/api/rules', data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}
export function useUpdateRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Rule> }) =>
      api.put(`/api/rules/${id}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}
export function useDeleteRule() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/rules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
}
export function useTestRule() {
  return useMutation({
    mutationFn: (data: { content: string; sample_event: Record<string, unknown> }) =>
      api.post('/api/rules/test', data).then(r => r.data),
  })
}
```

```typescript
// dashboard/src/hooks/useDecoders.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { Decoder, PaginatedResponse } from '@/types'
export function useDecoders(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Decoder>>({
    queryKey: ['decoders', page, pageSize],
    queryFn: () => api.get('/api/decoders', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}
export function useCreateDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Decoder>) => api.post('/api/decoders', data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoders'] }),
  })
}
export function useUpdateDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Decoder> }) =>
      api.put(`/api/decoders/${id}`, data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoders'] }),
  })
}
export function useDeleteDecoder() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/decoders/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['decoders'] }),
  })
}
export function useTestDecoder() {
  return useMutation({
    mutationFn: (data: { content: string; raw_message: string }) =>
      api.post('/api/decoders/test', data).then(r => r.data),
  })
}
```

```typescript
// dashboard/src/hooks/useUsers.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, User } from '@/types'
export function useUsers(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<User>>({
    queryKey: ['users', page, pageSize],
    queryFn: () => api.get('/api/users', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}
export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { username: string; email: string; password: string; role_id: number; group_id: string }) =>
      api.post('/api/users', data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}
export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/users/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}
```

```typescript
// dashboard/src/hooks/useWebhooks.ts
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { PaginatedResponse, Webhook } from '@/types'
export function useWebhooks(page = 1, pageSize = 25) {
  return useQuery<PaginatedResponse<Webhook>>({
    queryKey: ['webhooks', page, pageSize],
    queryFn: () => api.get('/api/webhooks', { params: { page, page_size: pageSize } }).then(r => r.data),
  })
}
export function useCreateWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Webhook>) => api.post('/api/webhooks', data).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}
export function useDeleteWebhook() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.delete(`/api/webhooks/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })
}
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/hooks/
git commit -m "feat: add all React Query hooks for data fetching and mutations"
```

---

## Task 6: Login Page

**Files:**
- Create: `dashboard/src/pages/LoginPage.tsx`

- [ ] **Step 1: Write LoginPage.tsx**

```tsx
// dashboard/src/pages/LoginPage.tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { setAccessToken, setUser } = useAuthStore()
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await api.post('/api/auth/login', { username, password })
      setAccessToken(data.access_token)
      const me = await api.get('/api/auth/me')
      setUser(me.data)
      navigate('/')
    } catch {
      setError('Invalid username or password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-full max-w-sm p-8 rounded-lg border border-border bg-card shadow-lg">
        <h1 className="text-2xl font-bold mb-2">SIEM Platform</h1>
        <p className="text-sm text-muted-foreground mb-6">Sign in to your account</p>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Username</label>
            <input
              value={username} onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              required autoFocus
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Password</label>
            <input
              type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded border border-border bg-background text-sm focus:outline-none focus:ring-1 focus:ring-primary"
              required
            />
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <button
            type="submit" disabled={loading}
            className="w-full py-2 rounded bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60 hover:opacity-90 transition-opacity"
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add dashboard/src/pages/LoginPage.tsx
git commit -m "feat: add login page"
```

---

## Task 7: Dashboard, Agents & Log Sources Pages

**Files:**
- Create: `dashboard/src/pages/DashboardPage.tsx`
- Create: `dashboard/src/pages/AgentsPage.tsx`
- Create: `dashboard/src/pages/LogSourcesPage.tsx`

- [ ] **Step 1: Write DashboardPage.tsx**

```tsx
// dashboard/src/pages/DashboardPage.tsx
import { useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export default function DashboardPage() {
  const { data: alertsNew } = useQuery({
    queryKey: ['alerts-summary', 'new'],
    queryFn: () => api.get('/api/alerts', { params: { status: 'new', page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })
  const { data: alertsHigh } = useQuery({
    queryKey: ['alerts-summary', 'high'],
    queryFn: () => api.get('/api/alerts', { params: { severity: 'high', page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })
  const { data: agentsTotal } = useQuery({
    queryKey: ['agents-summary'],
    queryFn: () => api.get('/api/agents', { params: { page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })
  const { data: logsTotal } = useQuery({
    queryKey: ['logs-summary'],
    queryFn: () => api.get('/api/logs', { params: { page_size: 1 } }).then(r => r.data.total),
    refetchInterval: 30_000,
  })

  const cards = [
    { label: 'New Alerts', value: alertsNew ?? '—', color: 'text-blue-400' },
    { label: 'High Severity', value: alertsHigh ?? '—', color: 'text-orange-400' },
    { label: 'Total Agents', value: agentsTotal ?? '—', color: 'text-green-400' },
    { label: 'Total Logs', value: logsTotal ?? '—', color: 'text-purple-400' },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Dashboard</h1>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="rounded-lg border border-border bg-card p-5">
            <div className={`text-3xl font-bold ${c.color}`}>{c.value}</div>
            <div className="text-sm text-muted-foreground mt-1">{c.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Write AgentsPage.tsx**

```tsx
// dashboard/src/pages/AgentsPage.tsx
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useAgents } from '@/hooks/useAgents'
import { useAuthStore } from '@/stores/auth'
import { formatDistanceToNow } from 'date-fns'
import type { Agent } from '@/types'

export default function AgentsPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useAgents(page)
  const { hasRole } = useAuthStore()
  const navigate = useNavigate()

  const columns = [
    { key: 'name', header: 'Name', render: (r: Agent) => r.name },
    { key: 'hostname', header: 'Hostname', render: (r: Agent) => r.hostname },
    { key: 'group', header: 'Group', render: (r: Agent) => r.group_id },
    { key: 'status', header: 'Status', render: (r: Agent) => <StatusBadge status={r.status} /> },
    { key: 'version', header: 'Version', render: (r: Agent) => r.version ?? '—' },
    { key: 'last_seen', header: 'Last Seen', render: (r: Agent) =>
      r.last_seen_at ? formatDistanceToNow(new Date(r.last_seen_at), { addSuffix: true }) : 'Never'
    },
    { key: 'sources', header: 'Sources', render: (r: Agent) => r.log_sources.length },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Agents</h1>
      {isLoading ? (
        <div className="text-muted-foreground">Loading...</div>
      ) : (
        <DataTable
          columns={columns}
          data={data?.items ?? []}
          total={data?.total ?? 0}
          page={page}
          pageSize={25}
          onPageChange={setPage}
          onRowClick={hasRole('admin') ? (r) => navigate(`/agents/${r.id}/sources`) : undefined}
        />
      )}
    </div>
  )
}
```

- [ ] **Step 3: Write LogSourcesPage.tsx**

```tsx
// dashboard/src/pages/LogSourcesPage.tsx
import { useState } from 'react'
import { useParams } from 'react-router-dom'
import { useLogSources, useAddLogSource, useUpdateLogSource, useDeleteLogSource } from '@/hooks/useAgents'
import StatusBadge from '@/components/StatusBadge'
import { Trash2, Plus } from 'lucide-react'
import type { LogSource } from '@/types'

export default function LogSourcesPage() {
  const { id } = useParams<{ id: string }>()
  const { data: sources, isLoading } = useLogSources(id!)
  const addSource = useAddLogSource(id!)
  const updateSource = useUpdateLogSource(id!)
  const deleteSource = useDeleteLogSource(id!)
  const [path, setPath] = useState('')
  const [logType, setLogType] = useState('')

  const handleAdd = () => {
    if (!path || !logType) return
    addSource.mutate({ path, log_type: logType, is_enabled: true })
    setPath('')
    setLogType('')
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Log Sources for Agent</h1>
      <div className="mb-4 flex gap-2">
        <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/var/log/auth.log"
          className="flex-1 px-3 py-2 rounded border border-border bg-background text-sm" />
        <input value={logType} onChange={(e) => setLogType(e.target.value)} placeholder="linux_auth"
          className="w-40 px-3 py-2 rounded border border-border bg-background text-sm" />
        <button onClick={handleAdd} className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-1">
          <Plus size={14} /> Add
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <div className="space-y-2">
          {(sources ?? []).map((s: LogSource) => (
            <div key={s.id} className="flex items-center justify-between px-4 py-3 rounded border border-border bg-card">
              <div>
                <div className="font-mono text-sm">{s.path}</div>
                <div className="text-xs text-muted-foreground">{s.log_type}</div>
              </div>
              <div className="flex items-center gap-3">
                <button onClick={() => updateSource.mutate({ sourceId: s.id, data: { ...s, is_enabled: !s.is_enabled } })}
                  className="text-xs underline text-muted-foreground hover:text-foreground">
                  {s.is_enabled ? 'Disable' : 'Enable'}
                </button>
                <StatusBadge status={s.is_enabled ? 'online' : 'offline'} />
                <button onClick={() => deleteSource.mutate(s.id)} className="text-destructive hover:opacity-70">
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/pages/DashboardPage.tsx dashboard/src/pages/AgentsPage.tsx dashboard/src/pages/LogSourcesPage.tsx
git commit -m "feat: add Dashboard, Agents, and LogSources pages"
```

---

## Task 8: Logs, Events, Alerts Pages

**Files:**
- Create: `dashboard/src/pages/LogsPage.tsx`
- Create: `dashboard/src/pages/EventsPage.tsx`
- Create: `dashboard/src/pages/AlertsPage.tsx`
- Create: `dashboard/src/components/AlertDetailModal.tsx`

- [ ] **Step 1: Write LogsPage.tsx**

```tsx
// dashboard/src/pages/LogsPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import { useLogs } from '@/hooks/useLogs'
import { format } from 'date-fns'
import type { RawLog } from '@/types'

export default function LogsPage() {
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const { data, isLoading } = useLogs(page, 25, search || undefined)

  const columns = [
    { key: 'time', header: 'Time', render: (r: RawLog) => format(new Date(r.received_at), 'yyyy-MM-dd HH:mm:ss') },
    { key: 'type', header: 'Type', render: (r: RawLog) => <span className="font-mono text-xs">{r.log_type}</span> },
    { key: 'message', header: 'Message', render: (r: RawLog) =>
      <span className="font-mono text-xs truncate max-w-xl block">{r.raw_message}</span>
    },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Raw Logs</h1>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage}
          onSearch={(q) => { setSearch(q); setPage(1) }} searchPlaceholder="Search logs..." />
      )}
    </div>
  )
}
```

- [ ] **Step 2: Write EventsPage.tsx**

```tsx
// dashboard/src/pages/EventsPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import { useEvents } from '@/hooks/useEvents'
import { format } from 'date-fns'
import type { Event } from '@/types'

export default function EventsPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useEvents(page)

  const columns = [
    { key: 'time', header: 'Time', render: (r: Event) => format(new Date(r.created_at), 'yyyy-MM-dd HH:mm:ss') },
    { key: 'category', header: 'Category', render: (r: Event) => r.event_category ?? '—' },
    { key: 'action', header: 'Action', render: (r: Event) => <span className="font-mono text-xs">{r.event_action ?? '—'}</span> },
    { key: 'source_ip', header: 'Source IP', render: (r: Event) => r.source_ip ?? '—' },
    { key: 'user', header: 'User', render: (r: Event) => r.user_name ?? '—' },
  ]

  return (
    <div>
      <h1 className="text-xl font-bold mb-6">Events</h1>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
    </div>
  )
}
```

- [ ] **Step 3: Write AlertDetailModal.tsx**

```tsx
// dashboard/src/components/AlertDetailModal.tsx
import { useState } from 'react'
import type { Alert } from '@/types'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'
import { useUpdateAlert, useAddAlertNote } from '@/hooks/useAlerts'
import { format } from 'date-fns'
import { X } from 'lucide-react'

interface Props { alert: Alert; onClose: () => void }

const STATUS_OPTIONS = ['new', 'in_progress', 'resolved', 'false_positive']

export default function AlertDetailModal({ alert, onClose }: Props) {
  const [note, setNote] = useState('')
  const updateAlert = useUpdateAlert()
  const addNote = useAddAlertNote()

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-border bg-card p-6 shadow-2xl max-h-[90vh] overflow-auto"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold">{alert.title}</h2>
            <div className="flex gap-2 mt-1">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={20} /></button>
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm mb-4">
          <div><span className="text-muted-foreground">Source IP:</span> {alert.source_ip ?? '—'}</div>
          <div><span className="text-muted-foreground">Hostname:</span> {alert.hostname ?? '—'}</div>
          <div><span className="text-muted-foreground">Created:</span> {format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')}</div>
          <div><span className="text-muted-foreground">Group:</span> {alert.group_id}</div>
        </div>

        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">Update Status</label>
          <select
            value={alert.status}
            onChange={(e) => updateAlert.mutate({ id: alert.id, data: { status: e.target.value } })}
            className="px-3 py-1.5 rounded border border-border bg-background text-sm"
          >
            {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
          </select>
        </div>

        <div className="mb-4">
          <h3 className="text-sm font-medium mb-2">Notes ({alert.notes.length})</h3>
          <div className="space-y-2 max-h-48 overflow-auto">
            {alert.notes.map((n) => (
              <div key={n.id} className="p-3 rounded bg-muted text-sm">
                <div className="text-xs text-muted-foreground mb-1">{format(new Date(n.created_at), 'yyyy-MM-dd HH:mm')}</div>
                {n.content}
              </div>
            ))}
          </div>
          <div className="flex gap-2 mt-2">
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note..."
              className="flex-1 px-3 py-1.5 rounded border border-border bg-background text-sm" />
            <button
              onClick={() => { addNote.mutate({ id: alert.id, content: note }); setNote('') }}
              disabled={!note} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm disabled:opacity-50">
              Add
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Write AlertsPage.tsx**

```tsx
// dashboard/src/pages/AlertsPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import SeverityBadge from '@/components/SeverityBadge'
import StatusBadge from '@/components/StatusBadge'
import AlertDetailModal from '@/components/AlertDetailModal'
import { useAlerts } from '@/hooks/useAlerts'
import { format } from 'date-fns'
import type { Alert } from '@/types'

export default function AlertsPage() {
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Alert | null>(null)
  const [statusFilter, setStatusFilter] = useState('')
  const { data, isLoading } = useAlerts(page, 25, statusFilter || undefined)

  const columns = [
    { key: 'severity', header: 'Severity', render: (r: Alert) => <SeverityBadge severity={r.severity} /> },
    { key: 'title', header: 'Title', render: (r: Alert) => <span className="font-medium">{r.title}</span> },
    { key: 'status', header: 'Status', render: (r: Alert) => <StatusBadge status={r.status} /> },
    { key: 'source_ip', header: 'Source IP', render: (r: Alert) => r.source_ip ?? '—' },
    { key: 'hostname', header: 'Hostname', render: (r: Alert) => r.hostname ?? '—' },
    { key: 'time', header: 'Time', render: (r: Alert) => format(new Date(r.created_at), 'yyyy-MM-dd HH:mm:ss') },
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Alerts</h1>
        <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
          className="px-3 py-1.5 rounded border border-border bg-background text-sm">
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} onRowClick={setSelected} />
      )}
      {selected && <AlertDetailModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}
```

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/pages/LogsPage.tsx dashboard/src/pages/EventsPage.tsx dashboard/src/pages/AlertsPage.tsx dashboard/src/components/AlertDetailModal.tsx
git commit -m "feat: add Logs, Events, Alerts pages and AlertDetailModal"
```

---

## Task 9: Rules, Decoders, Users, Webhooks Pages

**Files:**
- Create: `dashboard/src/components/YamlEditor.tsx`
- Create: `dashboard/src/pages/RulesPage.tsx`
- Create: `dashboard/src/pages/DecodersPage.tsx`
- Create: `dashboard/src/pages/UsersPage.tsx`
- Create: `dashboard/src/pages/WebhooksPage.tsx`

- [ ] **Step 1: Write YamlEditor.tsx**

```tsx
// dashboard/src/components/YamlEditor.tsx
import { useEffect, useRef } from 'react'
import { EditorState } from '@codemirror/state'
import { EditorView, basicSetup } from 'codemirror'
import { yaml } from '@codemirror/lang-yaml'
import { oneDark } from '@codemirror/theme-one-dark'
import { X } from 'lucide-react'

interface Props {
  title: string
  value: string
  onChange: (v: string) => void
  onSave: () => void
  onClose: () => void
  extraAction?: { label: string; onClick: () => void }
}

export default function YamlEditor({ title, value, onChange, onSave, onClose, extraAction }: Props) {
  const editorRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)

  useEffect(() => {
    if (!editorRef.current) return
    const state = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        yaml(),
        oneDark,
        EditorView.updateListener.of((u) => {
          if (u.docChanged) onChange(u.state.doc.toString())
        }),
      ],
    })
    const view = new EditorView({ state, parent: editorRef.current })
    viewRef.current = view
    return () => view.destroy()
  }, [])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-lg border border-border bg-card shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="font-semibold">{title}</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={18} /></button>
        </div>
        <div ref={editorRef} className="h-96 overflow-auto text-sm" />
        <div className="flex gap-2 justify-end px-4 py-3 border-t border-border">
          {extraAction && (
            <button onClick={extraAction.onClick}
              className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted">
              {extraAction.label}
            </button>
          )}
          <button onClick={onClose} className="px-4 py-1.5 rounded border border-border text-sm hover:bg-muted">Cancel</button>
          <button onClick={onSave} className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm">Save</button>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Write RulesPage.tsx**

```tsx
// dashboard/src/pages/RulesPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import YamlEditor from '@/components/YamlEditor'
import SeverityBadge from '@/components/SeverityBadge'
import { useRules, useCreateRule, useUpdateRule, useDeleteRule, useTestRule } from '@/hooks/useRules'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import type { Rule } from '@/types'

const DEFAULT_RULE = `title: New Rule
id: rule-new
logsource:
  product: linux
detection:
  selection:
    event.action: login_failed
  condition: selection
level: medium
tags: []
`

export default function RulesPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useRules(page)
  const createRule = useCreateRule()
  const updateRule = useUpdateRule()
  const deleteRule = useDeleteRule()
  const testRule = useTestRule()
  const [editing, setEditing] = useState<Rule | null>(null)
  const [creating, setCreating] = useState(false)
  const [yamlContent, setYamlContent] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)

  const handleSave = () => {
    if (editing) {
      updateRule.mutate({ id: editing.id, data: { content: yamlContent } })
    } else {
      createRule.mutate({ content: yamlContent, title: 'New Rule' })
    }
    setEditing(null)
    setCreating(false)
  }

  const handleTest = () => {
    testRule.mutate(
      { content: yamlContent, sample_event: { 'event.action': 'login_failed' } },
      { onSuccess: (r) => setTestResult(r.matched ? '✓ Matched' : '✗ No match') }
    )
  }

  const columns = [
    { key: 'title', header: 'Title', render: (r: Rule) => r.title },
    { key: 'level', header: 'Level', render: (r: Rule) => <SeverityBadge severity={r.level} /> },
    { key: 'enabled', header: 'Enabled', render: (r: Rule) => (
      <span className={r.is_enabled ? 'text-green-400' : 'text-muted-foreground'}>
        {r.is_enabled ? 'Yes' : 'No'}
      </span>
    )},
    { key: 'version', header: 'Version', render: (r: Rule) => `v${r.version}` },
    { key: 'actions', header: '', render: (r: Rule) => (
      <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => { setEditing(r); setYamlContent(r.content); setTestResult(null) }}
          className="text-muted-foreground hover:text-foreground"><Pencil size={14} /></button>
        <button onClick={() => deleteRule.mutate(r.id)} className="text-destructive hover:opacity-70">
          <Trash2 size={14} /></button>
      </div>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Rules</h1>
        <button onClick={() => { setCreating(true); setYamlContent(DEFAULT_RULE); setTestResult(null) }}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Rule
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.title}` : 'New Rule'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={() => { setEditing(null); setCreating(false) }}
          extraAction={{ label: testResult ?? 'Test Rule', onClick: handleTest }}
        />
      )}
    </div>
  )
}
```

- [ ] **Step 3: Write DecodersPage.tsx**

```tsx
// dashboard/src/pages/DecodersPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import YamlEditor from '@/components/YamlEditor'
import { useDecoders, useCreateDecoder, useUpdateDecoder, useDeleteDecoder, useTestDecoder } from '@/hooks/useDecoders'
import { Plus, Pencil, Trash2 } from 'lucide-react'
import type { Decoder } from '@/types'

const DEFAULT_DECODER = `name: new_decoder
log_type: linux_auth
type: regex
priority: 100
enabled: true
pattern: 'Failed password for (?P<user>\\S+) from (?P<src_ip>\\S+)'
fields:
  event.category: authentication
  event.action: login_failed
  user.name: user
  source.ip: src_ip
`

export default function DecodersPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useDecoders(page)
  const createDecoder = useCreateDecoder()
  const updateDecoder = useUpdateDecoder()
  const deleteDecoder = useDeleteDecoder()
  const testDecoder = useTestDecoder()
  const [editing, setEditing] = useState<Decoder | null>(null)
  const [creating, setCreating] = useState(false)
  const [yamlContent, setYamlContent] = useState('')
  const [testInput, setTestInput] = useState('')
  const [testResult, setTestResult] = useState<string | null>(null)

  const handleSave = () => {
    if (editing) {
      updateDecoder.mutate({ id: editing.id, data: { content: yamlContent } })
    } else {
      createDecoder.mutate({ content: yamlContent, name: 'new', log_type: 'unknown' })
    }
    setEditing(null); setCreating(false)
  }

  const handleTest = () => {
    const raw = prompt('Enter a raw log line to test:') ?? ''
    if (!raw) return
    testDecoder.mutate(
      { content: yamlContent, raw_message: raw },
      { onSuccess: (r) => setTestResult(r.matched ? `✓ ${JSON.stringify(r.decoded_fields)}` : '✗ No match') }
    )
  }

  const columns = [
    { key: 'name', header: 'Name', render: (r: Decoder) => r.name },
    { key: 'log_type', header: 'Log Type', render: (r: Decoder) => <span className="font-mono text-xs">{r.log_type}</span> },
    { key: 'priority', header: 'Priority', render: (r: Decoder) => r.priority },
    { key: 'enabled', header: 'Enabled', render: (r: Decoder) => (
      <span className={r.is_enabled ? 'text-green-400' : 'text-muted-foreground'}>{r.is_enabled ? 'Yes' : 'No'}</span>
    )},
    { key: 'actions', header: '', render: (r: Decoder) => (
      <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
        <button onClick={() => { setEditing(r); setYamlContent(r.content); setTestResult(null) }}
          className="text-muted-foreground hover:text-foreground"><Pencil size={14} /></button>
        <button onClick={() => deleteDecoder.mutate(r.id)} className="text-destructive hover:opacity-70">
          <Trash2 size={14} /></button>
      </div>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Decoders</h1>
        <button onClick={() => { setCreating(true); setYamlContent(DEFAULT_DECODER); setTestResult(null) }}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Decoder
        </button>
      </div>
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
      {(editing || creating) && (
        <YamlEditor
          title={editing ? `Edit: ${editing.name}` : 'New Decoder'}
          value={yamlContent}
          onChange={setYamlContent}
          onSave={handleSave}
          onClose={() => { setEditing(null); setCreating(false) }}
          extraAction={{ label: testResult ?? 'Test Decoder', onClick: handleTest }}
        />
      )}
    </div>
  )
}
```

- [ ] **Step 4: Write UsersPage.tsx**

```tsx
// dashboard/src/pages/UsersPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useUsers, useCreateUser, useDeleteUser } from '@/hooks/useUsers'
import { Plus, Trash2 } from 'lucide-react'
import type { User } from '@/types'

export default function UsersPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useUsers(page)
  const createUser = useCreateUser()
  const deleteUser = useDeleteUser()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ username: '', email: '', password: '', role_id: 4, group_id: 'default' })

  const handleCreate = () => {
    createUser.mutate(form)
    setShowForm(false)
    setForm({ username: '', email: '', password: '', role_id: 4, group_id: 'default' })
  }

  const columns = [
    { key: 'username', header: 'Username', render: (r: User) => r.username },
    { key: 'email', header: 'Email', render: (r: User) => r.email },
    { key: 'role', header: 'Role', render: (r: User) => r.role },
    { key: 'group', header: 'Group', render: (r: User) => r.group_id },
    { key: 'active', header: 'Active', render: (r: User) => <StatusBadge status={r.is_active ? 'online' : 'offline'} /> },
    { key: 'actions', header: '', render: (r: User) => (
      <button onClick={() => deleteUser.mutate(r.id)} className="text-destructive hover:opacity-70">
        <Trash2 size={14} /></button>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Users</h1>
        <button onClick={() => setShowForm(true)}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New User
        </button>
      </div>
      {showForm && (
        <div className="mb-4 p-4 rounded border border-border bg-card space-y-3">
          <div className="grid grid-cols-2 gap-3">
            {(['username', 'email', 'password', 'group_id'] as const).map((f) => (
              <div key={f}>
                <label className="block text-xs mb-1 capitalize">{f.replace('_', ' ')}</label>
                <input type={f === 'password' ? 'password' : 'text'} value={form[f] as string}
                  onChange={(e) => setForm((p) => ({ ...p, [f]: e.target.value }))}
                  className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm" />
              </div>
            ))}
          </div>
          <div>
            <label className="block text-xs mb-1">Role</label>
            <select value={form.role_id} onChange={(e) => setForm((p) => ({ ...p, role_id: Number(e.target.value) }))}
              className="px-3 py-1.5 rounded border border-border bg-background text-sm">
              <option value={1}>superadmin</option>
              <option value={2}>admin</option>
              <option value={3}>analyst</option>
              <option value={4}>viewer</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm">Create</button>
            <button onClick={() => setShowForm(false)} className="px-4 py-1.5 rounded border border-border text-sm">Cancel</button>
          </div>
        </div>
      )}
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
    </div>
  )
}
```

- [ ] **Step 5: Write WebhooksPage.tsx**

```tsx
// dashboard/src/pages/WebhooksPage.tsx
import { useState } from 'react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useWebhooks, useCreateWebhook, useDeleteWebhook } from '@/hooks/useWebhooks'
import { Plus, Trash2 } from 'lucide-react'
import type { Webhook } from '@/types'

export default function WebhooksPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useWebhooks(page)
  const createWebhook = useCreateWebhook()
  const deleteWebhook = useDeleteWebhook()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: '', url: '' })

  const columns = [
    { key: 'name', header: 'Name', render: (r: Webhook) => r.name },
    { key: 'url', header: 'URL', render: (r: Webhook) => <span className="font-mono text-xs truncate max-w-xs block">{r.url}</span> },
    { key: 'enabled', header: 'Enabled', render: (r: Webhook) => <StatusBadge status={r.is_enabled ? 'online' : 'offline'} /> },
    { key: 'actions', header: '', render: (r: Webhook) => (
      <button onClick={() => deleteWebhook.mutate(r.id)} className="text-destructive hover:opacity-70">
        <Trash2 size={14} /></button>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Webhooks</h1>
        <button onClick={() => setShowForm(true)}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New Webhook
        </button>
      </div>
      {showForm && (
        <div className="mb-4 p-4 rounded border border-border bg-card space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs mb-1">Name</label>
              <input value={form.name} onChange={(e) => setForm(p => ({ ...p, name: e.target.value }))}
                className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm" />
            </div>
            <div>
              <label className="block text-xs mb-1">URL</label>
              <input value={form.url} onChange={(e) => setForm(p => ({ ...p, url: e.target.value }))}
                placeholder="https://hooks.example.com/..."
                className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm" />
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={() => { createWebhook.mutate(form); setShowForm(false); setForm({ name: '', url: '' }) }}
              className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm">Create</button>
            <button onClick={() => setShowForm(false)} className="px-4 py-1.5 rounded border border-border text-sm">Cancel</button>
          </div>
        </div>
      )}
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={25} onPageChange={setPage} />
      )}
    </div>
  )
}
```

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/
git commit -m "feat: add Rules, Decoders, Users, Webhooks pages and YamlEditor component"
```

---

## Task 10: Build & Verify

- [ ] **Step 1: TypeScript check**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: No type errors.

- [ ] **Step 2: Build**

```bash
npm run build
```

Expected: `dist/` created with no build errors.

- [ ] **Step 3: Run dev server against local API**

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

Open `http://localhost:5173` in browser. Verify:
- Login page loads in dark mode
- Login with `admin` / `admin123` works
- Dashboard shows summary cards
- Sidebar filters correctly by role

- [ ] **Step 4: Build Docker image**

```bash
docker build -t siem-dashboard:local .
```

Expected: Image builds successfully.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete React dashboard - all pages implemented and build verified"
```
