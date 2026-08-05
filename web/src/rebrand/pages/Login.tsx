import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'

/**
 * Rebrand-styled sign-in. Reuses the real auth (useAuth().login) so it's fully
 * functional — just re-skinned into the AgentAvow shell. Account is the earned,
 * secondary action (change alerts / claim your repo), never the front door.
 */
export default function RebrandLogin() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(email, password)
      navigate('/rebrand')
    } catch {
      setError('Sign in failed — check your email and password.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="max-w-[420px] mx-auto px-6 py-20">
      <div className="text-center">
        <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight">Sign in to <span className="gradient-text">AgentAvow</span></h1>
        <p className="mt-2 text-text-muted text-[14px]">To watch tools and get change alerts. Checking is always free and anonymous.</p>
      </div>
      <form onSubmit={submit} className="glass rounded-2xl p-7 mt-7 flex flex-col gap-4">
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
            id="rb-pw" type="password" required autoComplete="current-password"
            value={password} onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-surface border border-border rounded-xl px-3.5 py-2.5 text-[15px] text-text outline-none focus:border-primary-light"
          />
        </div>
        {error && <div className="text-[13px] text-danger">{error}</div>}
        <button
          type="submit" disabled={busy}
          className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow disabled:opacity-60"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <div className="flex items-center gap-3 my-5">
        <div className="flex-1 h-px bg-border" />
        <span className="text-[12px] text-text-muted">or</span>
        <div className="flex-1 h-px bg-border" />
      </div>
      <div className="flex flex-col gap-2.5">
        <a href="/api/v1/auth/google" className="flex items-center justify-center gap-2 border border-border rounded-xl py-2.5 text-[14px] text-text hover:bg-surface transition-colors">Continue with Google</a>
        <a href="/api/v1/auth/github" className="flex items-center justify-center gap-2 border border-border rounded-xl py-2.5 text-[14px] text-text hover:bg-surface transition-colors">Continue with GitHub</a>
      </div>

      <p className="mt-5 text-center text-[13.5px] text-text-muted">
        New here? <a href="/register" className="text-primary-light hover:text-primary">Create an account</a>
        {' · '}
        <a href="/forgot-password" className="text-primary-light hover:text-primary">Forgot password?</a>
      </p>
      <p className="mt-2 text-center"><Link to="/rebrand" className="text-[13px] text-text-muted hover:text-text">← Back to AgentAvow</Link></p>
    </div>
  )
}
