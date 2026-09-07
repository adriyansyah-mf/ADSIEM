import { useState } from 'react'
import { Search, Crosshair, Loader2 } from 'lucide-react'
import { useHunts, useStartHunt } from '@/hooks/useHunts'
import { PageHeader } from '@/components/ui/PageHeader'
import { HuntCard } from '@/components/hunts/HuntCard'
import { ScheduledHuntsPanel } from '@/components/hunts/ScheduledHuntsPanel'
import { SigmaHuntPanel } from '@/components/hunts/SigmaHuntPanel'
import { IOC_TYPES } from '@/components/hunts/constants'

export default function HuntsPage() {
  const { data: hunts = [], isLoading } = useHunts()
  const startHunt = useStartHunt()
  const [iocType, setIocType] = useState('ip')
  const [iocValue, setIocValue] = useState('')
  const [error, setError] = useState('')
  const [huntMode, setHuntMode] = useState<'ioc' | 'sigma'>('ioc')

  const handleHunt = () => {
    const val = iocValue.trim()
    if (!val) { setError('Enter an IoC value'); return }
    setError('')
    startHunt.mutate({ ioc_type: iocType, ioc_value: val }, {
      onSuccess: () => setIocValue(''),
      onError: (e: any) => setError(e?.response?.data?.detail ?? 'Failed to start hunt'),
    })
  }

  return (
    <div className="space-y-6">
      <PageHeader title={<><Crosshair aria-hidden="true" size={20} /> Threat Hunt</>} />

      <div className="flex w-fit rounded border border-border bg-card p-1" role="group" aria-label="Hunt type">
        <button type="button" aria-pressed={huntMode === 'ioc'} onClick={() => setHuntMode('ioc')}
          className={`min-h-11 rounded px-4 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${huntMode === 'ioc' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted'}`}>IoC hunt</button>
        <button type="button" aria-pressed={huntMode === 'sigma'} onClick={() => setHuntMode('sigma')}
          className={`min-h-11 rounded px-4 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${huntMode === 'sigma' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted'}`}>Sigma hunt</button>
      </div>

      {huntMode === 'sigma' && <SigmaHuntPanel />}

      {/* Hunt form */}
      {huntMode === 'ioc' && <div className="enterprise-panel rounded-lg border border-border bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">New Hunt</h2>
        <div className="flex gap-3 flex-wrap">
          <select
            value={iocType}
            onChange={e => setIocType(e.target.value)}
            className="bg-muted border border-border rounded px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {IOC_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
          <input
            value={iocValue}
            onChange={e => setIocValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleHunt()}
            placeholder={iocType === 'ip' ? '192.168.1.1' : iocType === 'hostname' ? 'server-01' : iocType === 'user' ? 'john.doe' : 'sha256hash...'}
            className="flex-1 min-w-[240px] bg-muted border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
          />
          <button
            onClick={handleHunt}
            disabled={startHunt.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
          >
            {startHunt.isPending ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
            Hunt
          </button>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <p className="text-xs text-muted-foreground">
          AI will trace the full alert/event history related to this IoC, then analyze the attack pattern.
        </p>
      </div>}

      {huntMode === 'ioc' && <ScheduledHuntsPanel />}

      {huntMode === 'ioc' && <div className="space-y-3">
        {isLoading && <div className="text-muted-foreground text-sm">Loading…</div>}
        {!isLoading && hunts.length === 0 && (
          <div className="enterprise-panel rounded-lg border border-border bg-card p-8 text-center text-muted-foreground text-sm">
            {huntMode === 'ioc' ? 'No hunts yet. Enter an IoC above to get started.' : 'No IoC hunts yet. Run a Sigma rule above to search events.'}
          </div>
        )}
        {hunts.map(h => <HuntCard key={h.id} hunt={h} />)}
      </div>}
    </div>
  )
}
