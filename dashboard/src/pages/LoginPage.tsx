import { useEffect, useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, ArrowLeft, Eye, EyeOff, Info, ShieldCheck } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

// Canvas "Sign in · AD-SIEM". Only what the server supports is shown: there is
// no single sign-on, self-service reset or remember-me yet, so those controls
// from the mockup are left out rather than drawn as dead buttons.

// Demo deployment: the account shown on the sign-in page.
const DEMO_USER = 'admin'
const DEMO_PASSWORD = 'admin123'

interface Health { status: 'ok' | 'degraded'; postgres: string; redis: string; elasticsearch: string; uptime_seconds: number }
type HealthState = { kind: 'loading' } | { kind: 'down' } | { kind: 'ok'; data: Health }
const SERVICE_LABEL: Readonly<Record<string, string>> = { postgres: 'database', redis: 'queue', elasticsearch: 'search' }

function uptime(seconds: number) {
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${Math.floor((seconds % 3_600) / 60)}m` : `${Math.max(1, Math.floor(seconds / 60))}m`
}

function usePlatformHealth(): HealthState {
  const [state, setState] = useState<HealthState>({ kind: 'loading' })
  useEffect(() => {
    let live = true
    fetch('/health', { headers: { Accept: 'application/json' } })
      .then(r => r.ok ? r.json() as Promise<Health> : Promise.reject(new Error(String(r.status))))
      .then(data => { if (live) setState({ kind: 'ok', data }) })
      .catch(() => { if (live) setState({ kind: 'down' }) })
    return () => { live = false }
  }, [])
  return state
}

function PlatformStatus() {
  const health = usePlatformHealth()
  const failing = health.kind === 'ok'
    ? (['postgres', 'redis', 'elasticsearch'] as const).filter(name => health.data[name] !== 'ok').map(name => SERVICE_LABEL[name])
    : []
  const [dot, label] = health.kind === 'loading' ? ['', 'Checking…']
    : health.kind === 'down' ? ['login-dot--down', 'Unreachable']
    : health.data.status === 'ok' ? ['login-dot--ok', 'Operational'] : ['login-dot--degraded', 'Degraded']
  return (
    <dl className="login-stats" aria-live="polite">
      <div><dt>Platform status</dt><dd><span className={`login-dot ${dot}`} aria-hidden="true" />{label}</dd></div>
      <div><dt>Services</dt><dd>{health.kind !== 'ok' ? '—' : failing.length ? `${failing.join(', ')} down` : 'All running'}</dd></div>
      <div><dt>Uptime</dt><dd className="eg-mono">{health.kind === 'ok' ? uptime(health.data.uptime_seconds) : '—'}</dd></div>
    </dl>
  )
}

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [mfaCode, setMfaCode] = useState('')
  const [mfaRequired, setMfaRequired] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { setAccessToken, setUser } = useAuthStore()
  const navigate = useNavigate()

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const body: Record<string, string> = { username, password }
      if (mfaRequired) body.mfa_code = mfaCode
      const { data } = await api.post('/api/auth/login', body)
      if (data.mfa_required) {
        setMfaRequired(true)
        setLoading(false)
        return
      }
      setAccessToken(data.access_token)
      const me = await api.get('/api/auth/me')
      setUser(me.data)
      navigate('/')
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number } })?.response?.status
      if (status === 429) {
        setError('Too many sign-in attempts. Wait a minute and try again.')
      } else if (mfaRequired) {
        setError('That code didn’t work. Check your authenticator app and try again.')
        setMfaCode('')
      } else {
        setError('Invalid username or password.')
      }
    } finally {
      setLoading(false)
    }
  }

  const useDemo = () => {
    setUsername(DEMO_USER)
    setPassword(DEMO_PASSWORD)
    setError('')
  }

  const backToPassword = () => {
    setMfaRequired(false)
    setMfaCode('')
    setPassword('')
    setError('')
  }

  return (
    <div className="login-shell">
      <section className="login-brand" aria-label="About this system">
        <div className="login-mark">
          <img src="/logo.png" alt="" width={36} height={36} />
          <div><strong>AD-SIEM</strong><span>Enterprise security operations</span></div>
        </div>
        <div className="login-pitch">
          <p className="login-pitch__eyebrow">Security Operations Center</p>
          <h1>Detection, investigation and response in one console.</h1>
          <p>SIEM, EDR telemetry and SOAR automation for every endpoint and log source in your estate.</p>
        </div>
        <PlatformStatus />
        <p className="login-notice">Authorized use only. This system is monitored and every session is recorded in the audit log. Unauthorized access is prohibited and may be prosecuted.</p>
      </section>

      <main className="login-main">
        <div className="login-card">
          <header className="login-card__header">
            <h2>{mfaRequired ? 'Two-step verification' : 'Sign in'}</h2>
            <p>{mfaRequired ? 'Enter the 6-digit code from your authenticator app.' : 'Use the account your administrator gave you.'}</p>
          </header>

          <form onSubmit={handleSubmit} className="login-form">
            {!mfaRequired ? (
              <>
                <div className="login-field">
                  <label htmlFor="login-username">Username</label>
                  <input id="login-username" className="login-input" value={username}
                    onChange={e => setUsername(e.target.value)} required autoFocus autoComplete="username" />
                </div>
                <div className="login-field">
                  <label htmlFor="login-password">Password</label>
                  <div className="login-pass">
                    <input id="login-password" type={showPassword ? 'text' : 'password'} value={password}
                      onChange={e => setPassword(e.target.value)} required autoComplete="current-password" />
                    <button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} aria-pressed={showPassword}
                      onClick={() => setShowPassword(v => !v)}>
                      {showPassword ? <EyeOff size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="login-field">
                <label htmlFor="login-mfa">Authentication code</label>
                <input id="login-mfa" className="login-input login-code" value={mfaCode}
                  onChange={e => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000" required autoFocus maxLength={6} inputMode="numeric"
                  autoComplete="one-time-code" />
              </div>
            )}

            {error && (
              <div className="login-error" role="alert">
                <AlertCircle size={16} aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <button type="submit" className="login-submit"
              disabled={loading || (mfaRequired && mfaCode.length !== 6)} aria-busy={loading}>
              {mfaRequired && <ShieldCheck size={16} aria-hidden="true" />}
              {loading ? (mfaRequired ? 'Verifying…' : 'Signing in…') : (mfaRequired ? 'Verify' : 'Sign in')}
            </button>
            {mfaRequired ? (
              <button type="button" className="login-quiet" onClick={backToPassword} disabled={loading}>
                <ArrowLeft size={16} aria-hidden="true" /> Use a different account
              </button>
            ) : (
              <p className="login-hint"><Info size={14} aria-hidden="true" />If two-step verification is on for your account, a code from your authenticator app is asked next.</p>
            )}
          </form>

          {!mfaRequired && (
            <div className="login-demo" role="note" aria-label="Demo access">
              <Info size={16} aria-hidden="true" />
              <div className="login-demo__body">
                <strong>Demo access</strong>
                <span>Username <code>{DEMO_USER}</code> · Password <code>{DEMO_PASSWORD}</code></span>
              </div>
              <button type="button" onClick={useDemo} disabled={loading}>Use demo account</button>
            </div>
          )}

          <p className="login-access">Need access or a password reset? Ask your AD-SIEM administrator.</p>
        </div>

        <footer className="login-footer">
          <span>Sessions are recorded in the audit log.</span>
          <a href="https://deerflow.tech" target="_blank" rel="noopener noreferrer">Built by Deerflow</a>
        </footer>
      </main>
    </div>
  )
}
