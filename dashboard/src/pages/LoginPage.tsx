import { useState } from 'react'
import type { CSSProperties, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

@keyframes ring-pulse {
  0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.5; }
  50% { transform: translate(-50%, -50%) scale(1.1); opacity: 0.1; }
}

@keyframes ring-pulse-2 {
  0%, 100% { transform: translate(-50%, -50%) scale(1); opacity: 0.3; }
  50% { transform: translate(-50%, -50%) scale(1.18); opacity: 0.06; }
}

@keyframes scanline {
  0% { top: -3px; }
  100% { top: 100%; }
}

@keyframes blink-cursor {
  0%, 49% { opacity: 1; }
  50%, 100% { opacity: 0; }
}

@keyframes fade-up {
  from { opacity: 0; transform: translateY(20px); }
  to   { opacity: 1; transform: translateY(0); }
}

@keyframes fade-up-delay {
  0%, 20% { opacity: 0; transform: translateY(20px); }
  100%     { opacity: 1; transform: translateY(0); }
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20%       { transform: translateX(-7px); }
  40%       { transform: translateX(7px); }
  60%       { transform: translateX(-4px); }
  80%       { transform: translateX(4px); }
}

@keyframes shimmer {
  0%   { left: -100%; }
  100% { left: 200%; }
}

.soc-input {
  width: 100%;
  min-height: 44px;
  background: rgba(7,17,29,0.7);
  border: 1px solid rgba(148,197,255,0.16);
  border-radius: 8px;
  color: #e8f0fa;
  font-family: 'Public Sans', sans-serif;
  font-size: 15px;
  padding: 10px 12px;
  transition: border-color 0.2s, background 0.2s;
  box-sizing: border-box;
}

.soc-input:focus {
  outline: none;
  border-color: #2C6E8E;
  background: rgba(7,17,29,0.9);
  box-shadow: 0 0 0 3px rgba(44,110,142,0.14);
}

.soc-input::placeholder {
  color: rgba(100,116,139,0.4);
  font-size: 13px;
}

.soc-btn {
  position: relative;
  overflow: hidden;
  transition: box-shadow 0.25s, background 0.25s !important;
}

.soc-btn:hover:not(:disabled) {
  box-shadow: 0 8px 24px rgba(44,110,142,0.24) !important;
  background: rgba(44,110,142,0.24) !important;
}

.soc-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

.error-shake {
  animation: shake 0.4s ease-in-out;
}

@media (max-width: 48rem) {
  .login-brand-panel {
    display: none !important;
  }

  .login-form-panel {
    padding: 24px 16px !important;
  }
}
`

const STATUS_ITEMS = [
  { label: 'SYSTEM STATUS', value: 'OPERATIONAL',      color: '#10b981' },
  { label: 'THREAT MONITOR', value: 'ACTIVE',          color: '#f59e0b' },
  { label: 'ENCRYPTION',     value: 'AES-256-GCM',     color: '#2C6E8E' },
]

const CORNERS: CSSProperties[] = [
  { top: 24, left: 24, borderTop: '1px solid rgba(44,110,142,0.35)', borderLeft: '1px solid rgba(44,110,142,0.35)' },
  { top: 24, right: 24, borderTop: '1px solid rgba(44,110,142,0.35)', borderRight: '1px solid rgba(44,110,142,0.35)' },
  { bottom: 24, left: 24, borderBottom: '1px solid rgba(44,110,142,0.35)', borderLeft: '1px solid rgba(44,110,142,0.35)' },
  { bottom: 24, right: 24, borderBottom: '1px solid rgba(44,110,142,0.35)', borderRight: '1px solid rgba(44,110,142,0.35)' },
]

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaRequired, setMfaRequired] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [errKey, setErrKey] = useState(0)
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
        setError('INVALID MFA CODE — Check your authenticator app')
        setMfaCode('')
      } else {
        setError('ACCESS DENIED — Invalid credentials')
      }
      setErrKey(k => k + 1)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <style>{CSS}</style>

      <div style={{
        minHeight: '100dvh',
        display: 'flex',
        background: 'var(--bg-base)',
        fontFamily: "'Public Sans', sans-serif",
        overflow: 'hidden',
      }}>

        {/* ── Left panel — brand ── */}
        <div className="login-brand-panel" style={{
          width: '44%',
          minWidth: 320,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          position: 'relative',
          overflow: 'hidden',
          background: 'var(--bg-panel)',
          borderRight: '1px solid var(--border)',
        }}>

          {/* Corner brackets */}
          {CORNERS.map((s, i) => (
            <div key={i} style={{ position: 'absolute', width: 20, height: 20, ...s }} />
          ))}

          {/* Shield emblem */}
          <div style={{ position: 'relative', width: 100, height: 100, marginBottom: 36 }}>
            <div style={{
              position: 'absolute', inset: 0,
              borderRadius: 'var(--radius, 0.25rem)',
              background: 'var(--bg-sunken, var(--bg-base))',
              border: '1px solid var(--border-strong, var(--border))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              overflow: 'hidden',
            }}>
              <img src="/favicon.jpeg" alt="AD-SIEM" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
            </div>
          </div>

          {/* Brand text */}
          <div style={{ textAlign: 'center', position: 'relative', zIndex: 1 }}>
            <div style={{
              fontFamily: "'Archivo', sans-serif",
              fontSize: 40,
              fontWeight: 800,
              color: 'var(--text-primary)',
              letterSpacing: '0.06em',
              lineHeight: 1,
            }}>AD-SIEM</div>
            <div style={{
              fontFamily: "'Public Sans', sans-serif",
              fontSize: 13,
              fontWeight: 400,
              color: 'var(--text-muted)',
              letterSpacing: '0.42em',
              marginTop: 8,
            }}>PLATFORM</div>
            <div style={{ marginTop: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ height: 1, width: 40, background: 'var(--border)' }} />
              <div style={{ fontSize: 10, letterSpacing: '0.18em', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                SECURITY OPERATIONS CENTER
              </div>
              <div style={{ height: 1, width: 40, background: 'var(--border)' }} />
            </div>
          </div>

          {/* Status items */}
          <div style={{
            position: 'absolute', bottom: 40,
            display: 'flex', flexDirection: 'column', gap: 10,
            animation: 'fade-up-delay 1.2s ease-out both',
          }}>
            {STATUS_ITEMS.map(({ label, value, color }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, letterSpacing: '0.1em' }}>
                <div style={{ width: 5, height: 5, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0 }} />
                <span style={{ color: 'rgba(100,116,139,0.7)' }}>{label}:</span>
                <span style={{ color, fontWeight: 600 }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Right panel — form ── */}
        <div className="login-form-panel" style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '48px 56px',
          background: 'transparent',
          position: 'relative',
        }}>
          {/* Ambient glow */}
          <div style={{
            position: 'absolute',
            top: '30%', left: '20%',
            width: 300, height: 300,
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(44,110,142,0.04) 0%, transparent 70%)',
            pointerEvents: 'none',
          }} />

          <div style={{ width: '100%', maxWidth: 420, padding: '36px', borderRadius: 12, border: '1px solid var(--glass-border)', background: 'var(--glass-bg)', backdropFilter: 'var(--glass-blur)', WebkitBackdropFilter: 'var(--glass-blur)', boxShadow: '0 18px 48px rgba(0,0,0,.34), inset 0 1px 0 rgba(255,255,255,.04)', animation: 'fade-up 0.7s ease-out 0.15s both' }}>

            {/* Form header */}
            <div style={{ marginBottom: 44 }}>
              <div style={{
                fontFamily: "'Public Sans', sans-serif",
                fontSize: 12,
                letterSpacing: '0.32em',
                color: 'rgba(100,116,139,0.6)',
                marginBottom: 10,
              }}>Secure access</div>
              <div style={{
                fontFamily: "'Public Sans', sans-serif",
                fontSize: 24,
                fontWeight: 700,
                color: 'var(--text-primary)',
                letterSpacing: '0.08em',
              }}>Sign in to AD-SIEM</div>
              <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  height: 1, flex: 1,
                  background: 'linear-gradient(to right, rgba(44,110,142,0.5), transparent)',
                }} />
                <div style={{ width: 4, height: 4, transform: 'rotate(45deg)', background: 'rgba(44,110,142,0.5)' }} />
              </div>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 32, marginBottom: 40 }}>
                {!mfaRequired ? (
                  <>
                    <div>
                      <label htmlFor="username" style={{
                        fontSize: 12, letterSpacing: '0.18em',
                        color: 'rgba(44,110,142,0.7)', marginBottom: 6, textTransform: 'uppercase',
                        display: 'block',
                      }}>Username</label>
                      <input
                        id="username"
                        className="soc-input"
                        value={username}
                        onChange={e => setUsername(e.target.value)}
                        placeholder="Enter your username"
                        required
                        autoFocus
                        autoComplete="username"
                      />
                    </div>
                    <div>
                      <label htmlFor="password" style={{
                        fontSize: 12, letterSpacing: '0.18em',
                        color: 'rgba(44,110,142,0.7)', marginBottom: 6, textTransform: 'uppercase',
                        display: 'block',
                      }}>Password</label>
                      <input
                        id="password"
                        className="soc-input"
                        type="password"
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        placeholder="••••••••••••"
                        required
                        autoComplete="current-password"
                      />
                    </div>
                  </>
                ) : (
                  <div>
                    <div style={{
                      fontSize: 11, letterSpacing: '0.14em',
                      color: 'rgba(44,110,142,0.5)', marginBottom: 14, lineHeight: 1.6,
                    }}>
                      MFA REQUIRED — Enter the 6-digit code from your authenticator app.
                    </div>
                    <label htmlFor="mfa-code" style={{
                      fontSize: 12, letterSpacing: '0.18em',
                      color: 'rgba(44,110,142,0.7)', marginBottom: 6, textTransform: 'uppercase',
                      display: 'block',
                    }}>Authenticator code</label>
                    <input
                      id="mfa-code"
                      className="soc-input"
                      value={mfaCode}
                      onChange={e => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      required
                      autoFocus
                      maxLength={6}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                    />
                  </div>
                )}
              </div>

              {error && (
                <div
                  key={errKey}
                  className="error-shake"
                  style={{
                    marginBottom: 24,
                    padding: '11px 14px',
                    background: 'rgba(239,68,68,0.07)',
                    border: '1px solid rgba(239,68,68,0.28)',
                    borderLeft: '3px solid #ef4444',
                    color: '#f87171',
                    fontSize: 11,
                    letterSpacing: '0.1em',
                    display: 'flex', alignItems: 'center', gap: 8,
                  }}
                >
                  <span style={{ color: '#ef4444', fontSize: 14, lineHeight: 1 }}>▮</span>
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="soc-btn"
                style={{
                  width: '100%',
                  padding: '15px',
                  background: 'rgba(44,110,142,0.12)',
                  border: '1px solid rgba(44,110,142,0.4)',
                  color: '#2C6E8E',
                  fontFamily: "'Public Sans', sans-serif",
                  fontSize: 12,
                  letterSpacing: '0.28em',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                {loading ? (
                  <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
                    <span style={{ animation: 'blink-cursor 0.7s step-end infinite' }}>▮</span>
                    AUTHENTICATING
                    <span style={{ animation: 'blink-cursor 0.7s step-end infinite 0.35s' }}>▮</span>
                  </span>
                ) : mfaRequired ? 'Verify code' : 'Sign in'}
              </button>
            </form>

            {/* Footer note */}
            <div style={{
              marginTop: 40,
              fontSize: 10,
              color: 'rgba(51,65,85,0.75)',
              letterSpacing: '0.09em',
              textAlign: 'center',
              lineHeight: 1.7,
            }}>
              Authorized personnel only<br />
              Sessions are monitored and recorded
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
