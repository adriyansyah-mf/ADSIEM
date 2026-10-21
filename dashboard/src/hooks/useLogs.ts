import { useTelemetryRecords } from '@/hooks/useTelemetryRecords'
import type { RawLog } from '@/types'

export function useLogs(pageSize = 25, after: string | null, search?: string, filterTree?: string) {
  return useTelemetryRecords<RawLog>('logs', pageSize, after, search, filterTree)
}
