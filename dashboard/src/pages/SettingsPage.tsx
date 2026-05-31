import { useState, useEffect } from 'react'
import { useSettings, useUpdateSetting } from '@/hooks/useSettings'
import type { Setting } from '@/types'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const SETTING_LABELS: Record<string, string> = {
  groq_api_key: 'Groq API Key',
  groq_model: 'Groq Model',
  searxng_url: 'SearXNG URL',
  ai_analyst_enabled: 'AI Analyst',
  virustotal_api_key: 'VirusTotal API Key',
  abuseipdb_api_key: 'AbuseIPDB API Key',
  otx_api_key: 'AlienVault OTX API Key',
  greynoise_api_key: 'GreyNoise API Key',
  retention_alerts_days: 'Alert Retention (days)',
  retention_events_days: 'Event Retention (days)',
  retention_raw_logs_days: 'Raw Log Retention (days)',
  smtp_enabled: 'Email Notifications',
  smtp_host: 'SMTP Host',
  smtp_port: 'SMTP Port',
  smtp_from: 'From Address',
  smtp_to: 'Recipient Address',
  smtp_user: 'SMTP Username',
  smtp_password: 'SMTP Password',
  smtp_min_severity: 'Minimum Alert Severity for Email',
  ueba_enabled: 'UEBA Engine',
  ueba_anomaly_threshold: 'UEBA Anomaly Threshold',
}

const SETTING_HINTS: Record<string, string> = {
  groq_api_key: 'Get your key at console.groq.com',
  groq_model: 'e.g. llama-3.3-70b-versatile',
  searxng_url: 'Internal URL of your SearXNG instance',
  ai_analyst_enabled: 'Enable or disable automated AI triage (true / false)',
  virustotal_api_key: 'Free tier: 500 req/day — virustotal.com/gui/my-apikey',
  abuseipdb_api_key: 'Free tier: 1000 req/day — abuseipdb.com/account/api',
  otx_api_key: 'Free — otx.alienvault.com/api',
  greynoise_api_key: 'Optional — community endpoint used if empty (greynoise.io)',
  retention_alerts_days: 'Delete closed alerts older than N days. 0 = keep forever.',
  retention_events_days: 'Delete events older than N days. 0 = keep forever.',
  retention_raw_logs_days: 'Delete raw ingested logs older than N days. 0 = keep forever.',
  smtp_enabled: 'Send email notifications for new alerts (true / false)',
  smtp_host: 'Hostname or IP of your SMTP server',
  smtp_port: 'SMTP port — typically 587 (STARTTLS) or 465 (SSL)',
  smtp_from: 'Sender email address shown to recipients',
  smtp_to: 'Recipient email for alert notifications',
  smtp_user: 'SMTP login username (leave empty if no auth required)',
  smtp_password: 'SMTP login password',
  smtp_min_severity: 'Only send email for alerts at this severity or above (low / medium / high / critical)',
  ueba_enabled: 'Enable User & Entity Behavior Analytics engine (true / false)',
  ueba_anomaly_threshold: 'Risk score threshold above which UEBA flags an anomaly (0–100, default 60)',
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

function MfaSection() {
  const { user, setUser } = useAuthStore()
  const isEnabled = user?.mfa_enabled ?? false
  const [qrCode, setQrCode] = useState<string | null>(null)
  const [secret, setSecret] = useState('')
  const [code, setCode] = useState('')
  const [phase, setPhase] = useState<'idle' | 'setup' | 'disable' | 'error'>('idle')
  const [msg, setMsg] = useState('')

  const refreshUser = async () => {
    try {
      const me = await api.get('/api/auth/me')
      setUser(me.data)
    } catch {}
  }

  const startSetup = async () => {
    setMsg('')
    try {
      const r = await api.post('/api/auth/mfa/setup')
      setQrCode(r.data.qr_code)
      setSecret(r.data.secret)
      setCode('')
      setPhase('setup')
    } catch {
      setMsg('Failed to generate MFA setup. Try again.')
      setPhase('error')
    }
  }

  const enableMfa = async () => {
    try {
      await api.post('/api/auth/mfa/enable', { code })
      await refreshUser()
      setPhase('idle')
      setQrCode(null)
      setCode('')
      setMsg('MFA enabled. Authenticator required on next login.')
    } catch {
      setMsg('Invalid code. Check your authenticator app and try again.')
      setPhase('error')
    }
  }

  const disableMfa = async () => {
    try {
      await api.post('/api/auth/mfa/disable', { code })
      await refreshUser()
      setPhase('idle')
      setCode('')
      setMsg('MFA disabled.')
    } catch {
      setMsg('Invalid code. MFA not disabled.')
      setPhase('error')
    }
  }

  return (
    <div style={{ padding: '20px', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <div style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 15, color: 'var(--text-primary)' }}>
          Two-Factor Authentication (TOTP)
        </div>
        <span style={{
          fontSize: 10, padding: '2px 7px', borderRadius: 3, fontFamily: 'Share Tech Mono, monospace',
          background: isEnabled ? 'rgba(0,255,136,0.15)' : 'rgba(100,116,139,0.15)',
          color: isEnabled ? 'var(--accent-green)' : 'var(--text-muted)',
        }}>
          {isEnabled ? 'ACTIVE' : 'INACTIVE'}
        </span>
      </div>
      <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--text-muted)', marginBottom: 14, lineHeight: 1.5 }}>
        Protect your account with an authenticator app (Google Authenticator, Authy, 1Password, etc.)
      </div>

      {phase === 'idle' && !isEnabled && (
        <button onClick={startSetup} style={{ padding: '7px 18px', background: 'rgba(0,212,255,0.1)', border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', borderRadius: 4, cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 13, letterSpacing: 1 }}>
          ENABLE MFA
        </button>
      )}

      {phase === 'idle' && isEnabled && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {msg && <div style={{ color: 'var(--accent-green)', fontFamily: 'Share Tech Mono, monospace', fontSize: 11 }}>✓ {msg}</div>}
          <button onClick={() => { setCode(''); setMsg(''); setPhase('disable') }} style={{ alignSelf: 'flex-start', padding: '7px 18px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.4)', color: '#f87171', borderRadius: 4, cursor: 'pointer', fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 13, letterSpacing: 1 }}>
            DISABLE MFA
          </button>
        </div>
      )}

      {phase === 'setup' && qrCode && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            1. Scan this QR code with your authenticator app.<br />
            2. Or enter the secret manually: <span style={{ color: 'var(--accent-cyan)' }}>{secret}</span>
          </div>
          <img src={qrCode} alt="MFA QR Code" style={{ width: 160, height: 160, border: '1px solid var(--border)', borderRadius: 4, background: '#fff' }} />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              value={code}
              onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="Enter 6-digit code"
              maxLength={6}
              autoFocus
              style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 12px', color: 'var(--text-primary)', fontFamily: 'Share Tech Mono, monospace', fontSize: 15, width: 160, letterSpacing: 3 }}
            />
            <button onClick={enableMfa} disabled={code.length !== 6}
              style={{ padding: '7px 18px', background: 'rgba(0,255,136,0.1)', border: '1px solid var(--accent-green)', color: 'var(--accent-green)', borderRadius: 4, cursor: code.length === 6 ? 'pointer' : 'not-allowed', opacity: code.length === 6 ? 1 : 0.5, fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 13 }}>
              VERIFY & ENABLE
            </button>
          </div>
        </div>
      )}

      {phase === 'disable' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontFamily: 'Share Tech Mono, monospace', fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
            Enter your current TOTP code to confirm disabling MFA.
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              value={code}
              onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              maxLength={6}
              autoFocus
              inputMode="numeric"
              style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 4, padding: '7px 12px', color: 'var(--text-primary)', fontFamily: 'Share Tech Mono, monospace', fontSize: 15, width: 120, letterSpacing: 3 }}
            />
            <button onClick={disableMfa} disabled={code.length !== 6}
              style={{ padding: '7px 18px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.4)', color: '#f87171', borderRadius: 4, cursor: code.length === 6 ? 'pointer' : 'not-allowed', opacity: code.length === 6 ? 1 : 0.5, fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: 13 }}>
              CONFIRM DISABLE
            </button>
            <button onClick={() => { setPhase('idle'); setCode('') }}
              style={{ padding: '7px 12px', background: 'none', border: '1px solid #1e2028', color: 'var(--text-muted)', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {phase === 'error' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ color: 'var(--accent-red)', fontFamily: 'Share Tech Mono, monospace', fontSize: 12 }}>{msg}</div>
          <button onClick={() => { setPhase(isEnabled ? 'disable' : 'setup'); setMsg('') }} style={{ alignSelf: 'flex-start', padding: '5px 12px', background: 'none', border: '1px solid #1e2028', color: 'var(--text-muted)', borderRadius: 4, cursor: 'pointer', fontSize: 12 }}>
            Try again
          </button>
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
        <MfaSection />
        {settings?.map(s => <SettingRow key={s.key} setting={s} />)}
      </div>
    </div>
  )
}
