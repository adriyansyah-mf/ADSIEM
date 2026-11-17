import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from '@/api/client'

export type IocType = 'ip' | 'domain' | 'url' | 'sha256' | 'sha1' | 'md5' | 'email'
export const IOC_TYPES: IocType[] = ['ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email']

export interface Ioc {
  type: IocType
  value: string
  alerts: number
  hosts: number
  first_seen: string | null
  last_seen: string | null
  max_severity: string | null
  blocked: boolean | null
}

export interface IocList {
  total: number
  type_counts: Partial<Record<IocType, number>>
  items: Ioc[]
}

export interface IocAlert {
  id: string
  title: string
  severity: string
  status: string
  hostname: string | null
  created_at: string | null
  ai_verdict: string | null
}

export interface IocFilter {
  type: IocType | ''
  q: string
  days: number
  sort: 'last_seen' | 'alerts'
  offset: number
}

export const IOC_PAGE = 50

export function useIocs(f: IocFilter) {
  return useQuery<IocList>({
    queryKey: ['iocs', f],
    queryFn: () => api.get('/api/iocs', {
      params: {
        type: f.type || undefined,
        q: f.q || undefined,
        since: f.days ? new Date(Date.now() - f.days * 86400000).toISOString() : undefined,
        sort: f.sort,
        limit: IOC_PAGE,
        offset: f.offset,
      },
    }).then(r => r.data),
    placeholderData: keepPreviousData,
  })
}

export function useIocAlerts(ioc: Pick<Ioc, 'type' | 'value'> | null) {
  return useQuery<{ total: number; items: IocAlert[] }>({
    queryKey: ['iocs', 'alerts', ioc?.type, ioc?.value],
    queryFn: () => api.get('/api/iocs/alerts', { params: { type: ioc!.type, value: ioc!.value, limit: 50 } })
      .then(r => r.data),
    enabled: !!ioc,
  })
}
