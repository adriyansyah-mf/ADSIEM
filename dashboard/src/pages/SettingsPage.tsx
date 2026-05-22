import { useState, useEffect } from 'react'
import { useSettings, useUpdateSetting } from '@/hooks/useSettings'
import type { Setting } from '@/types'

const SETTING_LABELS: Record<string, string> = {
  groq_api_key: 'Groq API Key',
  groq_model: 'Groq Model',
  searxng_url: 'SearXNG URL',
  ai_analyst_enabled: 'AI Analyst Enabled',
  virustotal_api_key: 'VirusTotal API Key',
  abuseipdb_api_key: 'AbuseIPDB API Key',
  otx_api_key: 'AlienVault OTX API Key',
  greynoise_api_key: 'GreyNoise API Key',
}

const SETTING_HINTS: Record<string, string> = {
  groq_api_key: 'Get your key at console.groq.com',
  groq_model: 'e.g. llama-3.3-70b-versatile',
  searxng_url: 'Internal URL of your SearXNG instance',
  ai_analyst_enabled: 'true or false',
  virustotal_api_key: 'Free tier: 500 req/day — virustotal.com/gui/my-apikey',
  abuseipdb_api_key: 'Free tier: 1000 req/day — abuseipdb.com/account/api',
  otx_api_key: 'Free — otx.alienvault.com/api',
  greynoise_api_key: 'Optional — community endpoint used if empty (greynoise.io)',
}

const MASKED = '••••••••'

function SettingRow({ setting }: { setting: Setting }) {
  const [value, setValue] = useState(setting.is_secret ? '' : setting.value)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')
  const update = useUpdateSetting()

  useEffect(() => {
    if (!setting.is_secret) setValue(setting.value)
  }, [setting.value, setting.is_secret])

  const handleSave = async () => {
    setError('')
    try {
      await update.mutateAsync({ key: setting.key, value })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Save failed'
      setError(msg)
    }
  }

  const label = SETTING_LABELS[setting.key] ?? setting.key
  const hint = SETTING_HINTS[setting.key] ?? setting.description ?? ''
  const placeholder = setting.is_secret ? 'Enter new value to update…' : ''

  return (
    <div style={{
      padding: '16px 20px',
      borderBottom: '1px solid var(--border)',
      display: 'grid',
      gridTemplateColumns: '240px 1fr',
      gap: '12px',
      alignItems: 'start',
    }}>
      <div>
        <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 600, fontSize: '14px', color: 'var(--text-primary)', letterSpacing: '0.5px' }}>
          {label}
          {setting.is_secret && (
            <span style={{ marginLeft: '6px', fontSize: '10px', color: 'var(--accent-yellow)', background: 'rgba(255,195,0,0.1)', padding: '1px 4px', borderRadius: '3px', fontFamily: 'Share Tech Mono, monospace' }}>
              SECRET
            </span>
          )}
        </div>
        {hint && (
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '11px', color: 'var(--text-muted)', marginTop: '3px' }}>
            {hint}
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <input
          type={setting.is_secret ? 'password' : 'text'}
          value={value}
          placeholder={setting.is_secret ? placeholder : ''}
          onChange={e => { setValue(e.target.value); setSaved(false) }}
          style={{
            flex: 1,
            background: 'var(--bg-base)',
            border: '1px solid var(--border)',
            borderRadius: '4px',
            padding: '7px 12px',
            color: 'var(--text-primary)',
            fontFamily: 'Share Tech Mono, monospace',
            fontSize: '13px',
            outline: 'none',
          }}
        />
        {setting.is_secret && setting.value && !value && (
          <span style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '13px', color: 'var(--text-muted)', letterSpacing: '2px' }}>
            {MASKED}
          </span>
        )}
        <button
          onClick={handleSave}
          disabled={update.isPending || !value}
          style={{
            padding: '7px 16px',
            borderRadius: '4px',
            border: '1px solid var(--accent-cyan)',
            background: saved ? 'rgba(0,255,136,0.15)' : 'rgba(0,212,255,0.1)',
            color: saved ? 'var(--accent-green)' : 'var(--accent-cyan)',
            fontFamily: 'Rajdhani, sans-serif',
            fontWeight: 700,
            fontSize: '12px',
            letterSpacing: '1px',
            cursor: update.isPending || !value ? 'not-allowed' : 'pointer',
            opacity: !value ? 0.5 : 1,
            transition: 'all 0.15s',
            whiteSpace: 'nowrap',
          }}
        >
          {update.isPending ? 'SAVING…' : saved ? 'SAVED ✓' : 'SAVE'}
        </button>
      </div>

      {error && (
        <div style={{ gridColumn: '2', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--accent-red)', marginTop: '-6px' }}>
          {error}
        </div>
      )}
    </div>
  )
}

export default function SettingsPage() {
  const { data: settings, isLoading, error } = useSettings()

  return (
    <div>
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '22px', color: 'var(--accent-cyan)', letterSpacing: '2px', textTransform: 'uppercase', margin: 0 }}>
          Platform Settings
        </h1>
        <p style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0' }}>
          Configure AI analyst, integrations, and platform behaviour. Changes take effect within 60 seconds.
        </p>
      </div>

      <div style={{ background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' }}>
        {isLoading && (
          <div style={{ padding: '40px', textAlign: 'center', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--text-muted)' }}>
            LOADING SETTINGS…
          </div>
        )}
        {error && (
          <div style={{ padding: '20px', fontFamily: 'Share Tech Mono, monospace', fontSize: '12px', color: 'var(--accent-red)' }}>
            Failed to load settings. You may not have permission (superadmin required).
          </div>
        )}
        {settings?.map(s => <SettingRow key={s.key} setting={s} />)}
      </div>
    </div>
  )
}
