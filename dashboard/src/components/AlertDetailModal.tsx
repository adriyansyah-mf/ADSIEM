import type { Alert } from '@/types'
import AlertDetailView from './AlertDetailView'

/** Quick look at an alert from dashboards, cases and graphs; "Open full page" goes to /alerts/:id. */
export default function AlertDetailModal({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  return <AlertDetailView alertId={alert.id} summary={alert} variant="modal" onClose={onClose} />
}
