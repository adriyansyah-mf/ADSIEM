import { create } from 'zustand'
import { persist } from 'zustand/middleware'
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

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
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
    }),
    {
      name: 'siem-auth',
      partialize: (state) => ({ accessToken: state.accessToken, user: state.user }),
    }
  )
)
