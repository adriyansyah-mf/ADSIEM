import { useTelemetryRecords } from '@/hooks/useTelemetryRecords'
import type { Event } from '@/types'

export function useEvents(pageSize = 25, after: string | null, search?: string, filterTree?: string) {
  return useTelemetryRecords<Event>('events', pageSize, after, search, filterTree)
}
