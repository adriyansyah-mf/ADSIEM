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
  }, [accessToken, setUser, logout])

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
