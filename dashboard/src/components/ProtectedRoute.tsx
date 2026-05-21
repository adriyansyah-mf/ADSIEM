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
