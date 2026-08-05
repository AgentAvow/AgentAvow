import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'

/**
 * Rebrand-styled sign-in / sign-up. Reuses the real auth (useAuth().login/register)
 * so it's fully functional — just re-skinned into the AgentAvow shell. Account is the
 * earned, secondary action (change alerts / claim your repo), never the front door.
 * Sign-up is handled in-brand here rather than bouncing to the old /register page.
 */
export default function RebrandLogin() {
  const { login, register } = useAuth()
  const navigate = useNavigate()
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      if (mode === 'signup') {
        await register(email, password, name.trim() || email.split('@')[0])
      } else {
        await login(email, password)
      }
      navigate('/rebrand')
    } catch {
      setError(mode === 'signup'
        ? 'Could not create your account — that email may already be registered.'
        : 'Sign in failed — check your email and password.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="max-w-[420px] mx-auto px-6 py-20">
      <div className="text-center">
        <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight">
          {mode === 'signup' ? 'Create your ' : 'Sign in to '}<span className="gradient-text">AgentAvow</span>{mode === 'signup' ? ' account' : ''}
        </h1>
        <p className="mt-2 text-text-muted text-[14px]">To watch tools and get change alerts. Checking is always free and anonymous.</p>
      </div>
      <form onSubmit={submit} className="glass rounded-2xl p-7 mt-7 flex flex-col gap-4">
        {mode === 'signup' && (
          <div>
            <label htmlFor="rb-name" className="block text-[13px] text-text-muted mb-1">Display name</label>
            <input
              id="rb-name" type="text" autoComplete="name"
              value={name} onChange={(e) => setName(e.target.value)}
              className="w-full bg-surface border border-border rounded-xl px-3.5 py-2.5 text-[15px] text-text outline-none focus:border-primary-light"
            />
          </div>
        )}
        <div>
          <label htmlFor="rb-email" className="block text-[13px] text-text-muted mb-1">Email</label>
          <input
            id="rb-email" type="email" required autoComplete="email"
            value={email} onChange={(e) => setEmail(e.target.value)}
            className="w-full bg-surface border border-border rounded-xl px-3.5 py-2.5 text-[15px] text-text outline-none focus:border-primary-light"
          />
        </div>
        <div>
          <label htmlFor="rb-pw" className="block text-[13px] text-text-muted mb-1">Password</label>
          <input
            id="rb-pw" type="password" required autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
            value={password} onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-surface border border-border rounded-xl px-3.5 py-2.5 text-[15px] text-text outline-none focus:border-primary-light"
          />
        </div>
        {error && <div className="text-[13px] text-danger">{error}</div>}
        <button
          type="submit" disabled={busy}
          className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow disabled:opacity-60"
        >
          {busy ? (mode === 'signup' ? 'Creating…' : 'Signing in…') : (mode === 'signup' ? 'Create account' : 'Sign in')}
        </button>
      </form>

      <div className="flex items-center gap-3 my-5">
        <div className="flex-1 h-px bg-border" />
        <span className="text-[12px] text-text-muted">or</span>
        <div className="flex-1 h-px bg-border" />
      </div>
      <div className="flex flex-col gap-2.5">
        <a href="/api/v1/auth/google" className="flex items-center justify-center gap-2.5 border border-border rounded-xl py-2.5 text-[14px] font-medium text-text hover:bg-surface transition-colors">
          <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
            <path fill="#4285F4" d="M23.52 12.27c0-.79-.07-1.54-.2-2.27H12v4.51h6.47a5.53 5.53 0 0 1-2.4 3.63v3h3.88c2.27-2.09 3.57-5.17 3.57-8.87z"/>
            <path fill="#34A853" d="M12 24c3.24 0 5.96-1.07 7.95-2.91l-3.88-3c-1.08.72-2.45 1.16-4.07 1.16-3.13 0-5.78-2.11-6.73-4.96H1.29v3.09A12 12 0 0 0 12 24z"/>
            <path fill="#FBBC05" d="M5.27 14.29a7.2 7.2 0 0 1 0-4.58V6.62H1.29a12 12 0 0 0 0 10.76l3.98-3.09z"/>
            <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.44-3.44C17.95 1.19 15.24 0 12 0A12 12 0 0 0 1.29 6.62l3.98 3.09C6.22 6.86 8.87 4.75 12 4.75z"/>
          </svg>
          Continue with Google
        </a>
        <a href="/api/v1/auth/github" className="flex items-center justify-center gap-2.5 border border-border rounded-xl py-2.5 text-[14px] font-medium text-text hover:bg-surface transition-colors">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true">
            <path d="M12 .5A11.5 11.5 0 0 0 .5 12a11.5 11.5 0 0 0 7.86 10.92c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.34-1.3-1.7-1.3-1.7-1.06-.72.08-.71.08-.71 1.17.08 1.79 1.2 1.79 1.2 1.04 1.79 2.73 1.27 3.4.97.1-.76.41-1.27.74-1.56-2.55-.29-5.23-1.28-5.23-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.43-2.69 5.41-5.25 5.69.42.37.8 1.1.8 2.22v3.29c0 .31.21.67.8.56A11.5 11.5 0 0 0 23.5 12 11.5 11.5 0 0 0 12 .5z"/>
          </svg>
          Continue with GitHub
        </a>
      </div>

      <p className="mt-5 text-center text-[13.5px] text-text-muted">
        {mode === 'signup' ? (
          <>Already have an account? <button type="button" onClick={() => { setMode('signin'); setError('') }} className="text-primary-light hover:text-primary">Sign in</button></>
        ) : (
          <>New here? <button type="button" onClick={() => { setMode('signup'); setError('') }} className="text-primary-light hover:text-primary">Create an account</button>
          {' · '}
          <a href="/forgot-password" className="text-primary-light hover:text-primary">Forgot password?</a></>
        )}
      </p>
    </div>
  )
}
