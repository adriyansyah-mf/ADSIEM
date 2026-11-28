import { Link, useParams } from 'react-router-dom'
import AlertDetailView from '@/components/AlertDetailView'
import { CanvasHeader, CanvasPage } from '@/components/canvas/Canvas'

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>()
  if (!id) return null
  const short = `ALR-${id.replace(/-/g, '').slice(0, 6).toUpperCase()}`
  return (
    <CanvasPage>
      <CanvasHeader title={short} tabs={[]} crumb={<><Link to="/alerts">Alerts</Link> / {short}</>}
        actions={<Link to={`/alerts?alert=${id}`} className="cv-btn">Open in queue</Link>} />
      <div className="cv-body cv-body--wide">
        <AlertDetailView key={id} alertId={id} variant="page" />
      </div>
    </CanvasPage>
  )
}
