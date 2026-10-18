import { useParams } from 'react-router-dom'
import AlertDetailView from '@/components/AlertDetailView'

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>()
  if (!id) return null
  return <AlertDetailView key={id} alertId={id} variant="page" />
}
