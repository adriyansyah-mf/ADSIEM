import { Suspense, lazy, useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api/client'
import ProtectedRoute from '@/components/ProtectedRoute'
import Layout from '@/components/Layout'
import Toaster from '@/components/Toaster'
import LoginPage from '@/pages/LoginPage'

// Pages load on first visit: one bundle of every page was 733 kB gzipped
const DashboardPage = lazy(() => import('@/pages/DashboardPage'))
const CommandCenterPage = lazy(() => import('@/pages/CommandCenterPage'))
const AgentsPage = lazy(() => import('@/pages/AgentsPage'))
const LogSourcesPage = lazy(() => import('@/pages/LogSourcesPage'))
const FirewallPage = lazy(() => import('@/pages/FirewallPage'))
const AgentUpdatesPage = lazy(() => import('@/pages/AgentUpdatesPage'))
const LogsPage = lazy(() => import('@/pages/LogsPage'))
const EventsPage = lazy(() => import('@/pages/EventsPage'))
const LiveEventsPage = lazy(() => import('@/pages/LiveEventsPage'))
const AlertsPage = lazy(() => import('@/pages/AlertsPage'))
const AlertDetailPage = lazy(() => import('@/pages/AlertDetailPage'))
const RulesPage = lazy(() => import('@/pages/RulesPage'))
const DecodersPage = lazy(() => import('@/pages/DecodersPage'))
const UsersPage = lazy(() => import('@/pages/UsersPage'))
const WebhooksPage = lazy(() => import('@/pages/WebhooksPage'))
const CasesPage = lazy(() => import('@/pages/CasesPage'))
const CaseDetailPage = lazy(() => import('@/pages/CaseDetailPage'))
const SettingsPage = lazy(() => import('@/pages/SettingsPage'))
const HygienePage = lazy(() => import('@/pages/HygienePage'))
const UEBAPage = lazy(() => import('@/pages/UEBAPage'))
const FimPage = lazy(() => import('@/pages/FimPage'))
const HuntsPage = lazy(() => import('@/pages/HuntsPage'))
const ReportsPage = lazy(() => import('@/pages/ReportsPage'))
const SopPage = lazy(() => import('@/pages/SopPage'))
const KnowledgePage = lazy(() => import('@/pages/KnowledgePage'))
const HandoverPage = lazy(() => import('@/pages/HandoverPage'))
const LiveResponsePage = lazy(() => import('@/pages/LiveResponsePage'))
const YaraPage = lazy(() => import('@/pages/YaraPage'))
const PreventionPage = lazy(() => import('@/pages/PreventionPage'))
const MalwareHashesPage = lazy(() => import('@/pages/MalwareHashesPage'))
const ThreatIocsPage = lazy(() => import('@/pages/ThreatIocsPage'))
const WebProtectionPage = lazy(() => import('@/pages/WebProtectionPage'))
const PoliciesPage = lazy(() => import('@/pages/PoliciesPage'))
const AuditLogsPage = lazy(() => import('@/pages/AuditLogsPage'))
const SoarPage = lazy(() => import('@/pages/SoarPage'))
const SoarEditorPage = lazy(() => import('@/pages/SoarEditorPage'))
const MitreHeatmapPage = lazy(() => import('@/pages/MitreHeatmapPage'))

export default function App() {
  const { accessToken, setUser, logout } = useAuthStore()

  useEffect(() => {
    if (accessToken) {
      api.get('/api/auth/me').then((r) => setUser(r.data)).catch(() => logout())
    }
  }, [accessToken, setUser, logout])

  return (
    <BrowserRouter>
      <Suspense fallback={null}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute minRole="viewer" />}>
          <Route element={<Layout />}>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/command-center" element={<CommandCenterPage />} />
            <Route path="/agents" element={<AgentsPage />} />
            <Route path="/agents/:id/sources" element={<ProtectedRoute minRole="admin"><LogSourcesPage /></ProtectedRoute>} />
        <Route path="/agents/:id/firewall" element={<ProtectedRoute minRole="admin"><FirewallPage /></ProtectedRoute>} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/live-events" element={<LiveEventsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/alerts/:id" element={<AlertDetailPage />} />
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
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/sop" element={<SopPage />} />
            <Route path="/knowledge" element={<KnowledgePage />} />
            <Route path="/handover" element={<HandoverPage />} />
            <Route path="/mitre-heatmap" element={<MitreHeatmapPage />} />
            <Route path="/live-response" element={<LiveResponsePage />} />
            <Route path="/artifacts" element={<Navigate to="/live-response" replace />} />
            <Route path="/yara" element={<YaraPage />} />
            <Route path="/prevention" element={<PreventionPage />} />
            <Route path="/malware-hashes" element={<MalwareHashesPage />} />
            <Route path="/threat-iocs" element={<ThreatIocsPage />} />
            <Route path="/web-protection" element={<ProtectedRoute minRole="analyst"><WebProtectionPage /></ProtectedRoute>} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/agent-updates" element={<AgentUpdatesPage />} />
            <Route path="/soar" element={<ProtectedRoute minRole="analyst"><SoarPage /></ProtectedRoute>} />
            <Route path="/soar/:id" element={<ProtectedRoute minRole="analyst"><SoarEditorPage /></ProtectedRoute>} />
            <Route path="/audit-logs" element={<ProtectedRoute minRole="admin"><AuditLogsPage /></ProtectedRoute>} />
          </Route>
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </Suspense>
      <Toaster />
    </BrowserRouter>
  )
}
