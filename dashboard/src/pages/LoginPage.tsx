import { useState, CSSProperties, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap');

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
  background: transparent;
  border: none;
  border-bottom: 1px solid rgba(6,182,212,0.25);
  color: #e2e8f0;
  font-family: 'Share Tech Mono', monospace;
  font-size: 15px;
  padding: 10px 0;
  transition: border-color 0.25s, background 0.25s;
  letter-spacing: 0.06em;
  box-sizing: border-box;
}

.soc-input:focus {
  outline: none;
  border-bottom-color: #06b6d4;
  background: linear-gradient(to bottom, transparent 90%, rgba(6,182,212,0.04) 100%);
  box-shadow: 0 2px 0 rgba(6,182,212,0.5);
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

.soc-btn::after {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 60%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(6,182,212,0.12), transparent);
  animation: shimmer 2.4s ease-in-out infinite;
}

.soc-btn:hover:not(:disabled) {
  box-shadow: 0 0 28px rgba(6,182,212,0.45), inset 0 0 20px rgba(6,182,212,0.08) !important;
  background: rgba(6,182,212,0.22) !important;
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
`

const STATUS_ITEMS = [
  { label: 'SYSTEM STATUS', value: 'OPERATIONAL',      color: '#10b981' },
  { label: 'THREAT MONITOR', value: 'ACTIVE',          color: '#f59e0b' },
  { label: 'ENCRYPTION',     value: 'AES-256-GCM',     color: '#06b6d4' },
]

const CORNERS: CSSProperties[] = [
  { top: 24, left: 24, borderTop: '1px solid rgba(6,182,212,0.35)', borderLeft: '1px solid rgba(6,182,212,0.35)' },
  { top: 24, right: 24, borderTop: '1px solid rgba(6,182,212,0.35)', borderRight: '1px solid rgba(6,182,212,0.35)' },
  { bottom: 24, left: 24, borderBottom: '1px solid rgba(6,182,212,0.35)', borderLeft: '1px solid rgba(6,182,212,0.35)' },
  { bottom: 24, right: 24, borderBottom: '1px solid rgba(6,182,212,0.35)', borderRight: '1px solid rgba(6,182,212,0.35)' },
]

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
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
      const { data } = await api.post('/api/auth/login', { username, password })
      setAccessToken(data.access_token)
      const me = await api.get('/api/auth/me')
      setUser(me.data)
      navigate('/')
    } catch {
      setError('ACCESS DENIED — Invalid credentials')
      setErrKey(k => k + 1)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <style>{CSS}</style>

      <div style={{
        minHeight: '100vh',
        display: 'flex',
        background: '#020408',
        fontFamily: "'Share Tech Mono', monospace",
        overflow: 'hidden',
      }}>

        {/* ── Left panel — brand ── */}
        <div style={{
          width: '44%',
          minWidth: 320,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          position: 'relative',
          overflow: 'hidden',
          backgroundImage: [
            'linear-gradient(rgba(6,182,212,0.035) 1px, transparent 1px)',
            'linear-gradient(90deg, rgba(6,182,212,0.035) 1px, transparent 1px)',
          ].join(','),
          backgroundSize: '44px 44px',
          borderRight: '1px solid rgba(6,182,212,0.12)',
        }}>

          {/* Horizontal scanline */}
          <div style={{
            position: 'absolute', left: 0, right: 0, height: 2,
            background: 'linear-gradient(to right, transparent, rgba(6,182,212,0.25), transparent)',
            animation: 'scanline 5s linear infinite',
            pointerEvents: 'none',
          }} />

          {/* Corner brackets */}
          {CORNERS.map((s, i) => (
            <div key={i} style={{ position: 'absolute', width: 20, height: 20, ...s }} />
          ))}

          {/* Radial vignette */}
          <div style={{
            position: 'absolute', inset: 0,
            background: 'radial-gradient(ellipse at center, transparent 40%, rgba(2,4,8,0.7) 100%)',
            pointerEvents: 'none',
          }} />

          {/* Shield emblem + rings */}
          <div style={{ position: 'relative', width: 100, height: 100, marginBottom: 36 }}>
            <div style={{
              position: 'absolute', top: '50%', left: '50%',
              width: 170, height: 170, borderRadius: '50%',
              border: '1px solid rgba(6,182,212,0.18)',
              animation: 'ring-pulse-2 4s ease-in-out infinite',
            }} />
            <div style={{
              position: 'absolute', top: '50%', left: '50%',
              width: 128, height: 128, borderRadius: '50%',
              border: '1px solid rgba(6,182,212,0.28)',
              animation: 'ring-pulse 3s ease-in-out infinite',
            }} />
            <div style={{
              position: 'absolute', inset: 0,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(6,182,212,0.12) 0%, rgba(6,182,212,0.04) 60%, transparent 100%)',
              border: '1px solid rgba(6,182,212,0.45)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 32px rgba(6,182,212,0.2), inset 0 0 24px rgba(6,182,212,0.08)',
            }}>
              <svg width="42" height="42" viewBox="0 0 24 24" fill="none" stroke="#06b6d4" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="M9 12l2 2 4-4" />
              </svg>
            </div>
          </div>

          {/* Brand text */}
          <div style={{ textAlign: 'center', animation: 'fade-up 0.9s ease-out both', position: 'relative', zIndex: 1 }}>
            <div style={{
              fontFamily: "'Rajdhani', sans-serif",
              fontSize: 52,
              fontWeight: 900,
              color: '#06b6d4',
              letterSpacing: '0.14em',
              textShadow: '0 0 25px rgba(6,182,212,0.55), 0 0 60px rgba(6,182,212,0.2)',
              lineHeight: 1,
            }}>SIEM</div>
            <div style={{
              fontFamily: "'Rajdhani', sans-serif",
              fontSize: 13,
              fontWeight: 400,
              color: 'rgba(6,182,212,0.55)',
              letterSpacing: '0.42em',
              marginTop: 8,
            }}>PLATFORM</div>
            <div style={{ marginTop: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ height: 1, width: 40, background: 'linear-gradient(to left, rgba(6,182,212,0.4), transparent)' }} />
              <div style={{ fontSize: 10, letterSpacing: '0.18em', color: 'rgba(100,116,139,0.65)', whiteSpace: 'nowrap' }}>
                SECURITY OPERATIONS CENTER
              </div>
              <div style={{ height: 1, width: 40, background: 'linear-gradient(to right, rgba(6,182,212,0.4), transparent)' }} />
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
        <div style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '48px 56px',
          background: 'linear-gradient(135deg, #030609 0%, #020508 100%)',
          position: 'relative',
        }}>
          {/* Ambient glow */}
          <div style={{
            position: 'absolute',
            top: '30%', left: '20%',
            width: 300, height: 300,
            borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(6,182,212,0.04) 0%, transparent 70%)',
            pointerEvents: 'none',
          }} />

          <div style={{ width: '100%', maxWidth: 380, animation: 'fade-up 0.7s ease-out 0.15s both' }}>

            {/* Form header */}
            <div style={{ marginBottom: 44 }}>
              <div style={{
                fontFamily: "'Rajdhani', sans-serif",
                fontSize: 12,
                letterSpacing: '0.32em',
                color: 'rgba(100,116,139,0.6)',
                marginBottom: 10,
              }}>SECURE ACCESS PORTAL</div>
              <div style={{
                fontFamily: "'Rajdhani', sans-serif",
                fontSize: 24,
                fontWeight: 700,
                color: '#e2e8f0',
                letterSpacing: '0.08em',
              }}>AUTHENTICATION</div>
              <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  height: 1, flex: 1,
                  background: 'linear-gradient(to right, rgba(6,182,212,0.5), transparent)',
                }} />
                <div style={{ width: 4, height: 4, transform: 'rotate(45deg)', background: 'rgba(6,182,212,0.5)' }} />
              </div>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 32, marginBottom: 40 }}>
                <div>
                  <div style={{
                    fontSize: 12, letterSpacing: '0.18em',
                    color: 'rgba(6,182,212,0.7)', marginBottom: 6, textTransform: 'uppercase',
                  }}>[ USERNAME ]</div>
                  <input
                    className="soc-input"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    placeholder="ENTER IDENTIFIER"
                    required
                    autoFocus
                    autoComplete="username"
                  />
                </div>
                <div>
                  <div style={{
                    fontSize: 12, letterSpacing: '0.18em',
                    color: 'rgba(6,182,212,0.7)', marginBottom: 6, textTransform: 'uppercase',
                  }}>[ PASSWORD ]</div>
                  <input
                    className="soc-input"
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    required
                    autoComplete="current-password"
                  />
                </div>
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
                  background: 'rgba(6,182,212,0.12)',
                  border: '1px solid rgba(6,182,212,0.4)',
                  color: '#06b6d4',
                  fontFamily: "'Rajdhani', sans-serif",
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
                ) : 'INITIATE ACCESS'}
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
              UNAUTHORIZED ACCESS IS PROHIBITED<br />
              ALL SESSIONS ARE MONITORED AND RECORDED
            </div>
          </div>

          {/* Deerflow branding */}
          <a
            href="https://deerflow.tech"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              position: 'absolute',
              bottom: 20, right: 24,
              fontSize: 10,
              color: 'rgba(51,65,85,0.5)',
              letterSpacing: '0.12em',
              textDecoration: 'none',
              fontFamily: "'Share Tech Mono', monospace",
              transition: 'color 0.2s',
            }}
            onMouseEnter={e => (e.currentTarget.style.color = 'rgba(6,182,212,0.5)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'rgba(51,65,85,0.5)')}
          >
            ✦ DEERFLOW
          </a>
        </div>
      </div>
    </>
  )
}
