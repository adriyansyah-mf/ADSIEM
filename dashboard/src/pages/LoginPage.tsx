import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, ArrowLeft, KeyRound, ShieldCheck } from 'lucide-react'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

// Same surfaces, type and controls as the workspace (DESIGN.md): neutral
// panels, system fonts, the blue action accent, no decorative motion.

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
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
    } catch {
      if (mfaRequired) {
        setError('That code didn’t work. Check your authenticator app and try again.')
        setMfaCode('')
      } else {
        setError('Invalid username or password.')
      }
    } finally {
      setLoading(false)
    }
  }

  const backToPassword = () => {
    setMfaRequired(false)
    setMfaCode('')
    setPassword('')
    setError('')
  }

  return (
    <div className="login-shell">
      <section className="login-brand" aria-label="AD-SIEM">
        <img src="/logo.png" alt="" width={96} height={96} className="login-brand__logo" />
        <div>
          <div className="login-brand__name">AD-SIEM</div>
          <div className="login-brand__tagline">Security operations</div>
        </div>
        <p className="login-brand__copy">
          Detection, investigation and response for your fleet: alerts, cases, live response and
          AI-assisted investigations in one workspace.
        </p>
      </section>

      <main className="login-main">
        <div className="login-card panel">
          <header className="login-card__header">
            <img src="/logo.png" alt="" width={40} height={40} className="login-card__mark" />
            <div>
              <h1>{mfaRequired ? 'Two-step verification' : 'Sign in'}</h1>
              <p className="page-description">
                {mfaRequired
                  ? 'Enter the 6-digit code from your authenticator app.'
                  : 'Use your AD-SIEM account to continue.'}
              </p>
            </div>
          </header>

          <form onSubmit={handleSubmit} className="login-form">
            {!mfaRequired ? (
              <>
                <div className="field">
                  <label htmlFor="login-username">Username</label>
                  <input id="login-username" className="ui-input" value={username}
                    onChange={e => setUsername(e.target.value)} required autoFocus autoComplete="username" />
                </div>
                <div className="field">
                  <label htmlFor="login-password">Password</label>
                  <input id="login-password" className="ui-input" type="password" value={password}
                    onChange={e => setPassword(e.target.value)} required autoComplete="current-password" />
                </div>
              </>
            ) : (
              <div className="field">
                <label htmlFor="login-mfa">Authentication code</label>
                <input id="login-mfa" className="ui-input login-form__code" value={mfaCode}
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

            <button type="submit" className="ui-button ui-button--primary login-form__submit"
              disabled={loading || (mfaRequired && mfaCode.length !== 6)} aria-busy={loading}>
              {mfaRequired ? <ShieldCheck size={16} aria-hidden="true" /> : <KeyRound size={16} aria-hidden="true" />}
              {loading ? (mfaRequired ? 'Verifying…' : 'Signing in…') : (mfaRequired ? 'Verify' : 'Sign in')}
            </button>
            {mfaRequired && (
              <button type="button" className="ui-button ui-button--quiet" onClick={backToPassword} disabled={loading}>
                <ArrowLeft size={16} aria-hidden="true" /> Use a different account
              </button>
            )}
          </form>
        </div>

        <footer className="login-footer">
          <span>Authorized use only. Sessions are audited.</span>
          <a href="https://deerflow.tech" target="_blank" rel="noopener noreferrer">Built by Deerflow</a>
        </footer>
      </main>
    </div>
  )
}
