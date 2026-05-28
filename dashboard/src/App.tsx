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
import CasesPage from '@/pages/CasesPage'
import CaseDetailPage from '@/pages/CaseDetailPage'
import SettingsPage from '@/pages/SettingsPage'
import HygienePage from '@/pages/HygienePage'
import UEBAPage from '@/pages/UEBAPage'
import FimPage from '@/pages/FimPage'
import HuntsPage from '@/pages/HuntsPage'
import LiveResponsePage from '@/pages/LiveResponsePage'
import ArtifactsPage from '@/pages/ArtifactsPage'
import YaraPage from '@/pages/YaraPage'
import CorrelationPage from '@/pages/CorrelationPage'
import AuditLogsPage from '@/pages/AuditLogsPage'
import HandoverPage from '@/pages/HandoverPage'

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
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/cases/:id" element={<CaseDetailPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/decoders" element={<DecodersPage />} />
            <Route path="/users" element={<ProtectedRoute minRole="superadmin"><UsersPage /></ProtectedRoute>} />
            <Route path="/webhooks" element={<ProtectedRoute minRole="admin"><WebhooksPage /></ProtectedRoute>} />
            <Route path="/settings" element={<ProtectedRoute minRole="admin"><SettingsPage /></ProtectedRoute>} />
            <Route path="/hygiene" element={<HygienePage />} />
            <Route path="/ueba" element={<UEBAPage />} />
            <Route path="/fim" element={<FimPage />} />
            <Route path="/hunts" element={<HuntsPage />} />
            <Route path="/live-response" element={<LiveResponsePage />} />
            <Route path="/artifacts" element={<ArtifactsPage />} />
            <Route path="/yara" element={<YaraPage />} />
            <Route path="/correlation" element={<CorrelationPage />} />
            <Route path="/audit-logs" element={<ProtectedRoute minRole="admin"><AuditLogsPage /></ProtectedRoute>} />
            <Route path="/handover" element={<HandoverPage />} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
