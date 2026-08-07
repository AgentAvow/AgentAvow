import { useState, useEffect, useRef, type FormEvent } from 'react'
import { Link, useSearchParams, useNavigate } from 'react-router-dom'
import api from '../lib/api'
import SEOHead from '../components/SEOHead'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const navigate = useNavigate()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [showPass, setShowPass] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const redirectTimer = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => { document.title = 'Reset Password - AgentAvow' }, [])
  useEffect(() => () => clearTimeout(redirectTimer.current), [])

  if (!token) {
    return (
      <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0 text-center space-y-4">
        <h1 className="text-xl font-bold">Invalid Reset Link</h1>
        <p className="text-sm text-text-muted">This password reset link is invalid or missing a token.</p>
        <Link to="/forgot-password" className="inline-block text-primary-light hover:underline text-sm">
          Request a new reset link
        </Link>
      </div>
    )
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (password !== confirm) {
      setError('Passwords do not match')
      return
    }
    setError('')
    setLoading(true)
    try {
      await api.post('/auth/reset-password', { token, new_password: password })
      setSuccess(true)
      redirectTimer.current = setTimeout(() => navigate('/login'), 3000)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Reset failed. The token may be invalid or expired.')
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0 text-center space-y-4">
        <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto">
          <span className="text-success text-2xl">&#10003;</span>
        </div>
        <h1 className="text-xl font-bold">Password Reset</h1>
        <p className="text-sm text-text-muted">Your password has been reset. Redirecting to login...</p>
      </div>
    )
  }

  return (
    <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0">
      <SEOHead title="Reset Password" path="/reset-password" noindex />
      <h1 className="text-xl font-bold mb-6">Set New Password</h1>
      {error && (
        <div role="alert" className="bg-danger/10 text-danger text-sm px-4 py-2 rounded mb-4">{error}</div>
      )}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="reset-password" className="block text-sm text-text-muted mb-1">New Password</label>
          <div className="relative">
            <input
              id="reset-password"
              type={showPass ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
              className="w-full bg-surface border border-border rounded-md px-3 py-2 pr-16 text-text focus:outline-none focus:border-primary"
            />
            <button
              type="button"
              onClick={() => setShowPass(!showPass)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-text-muted hover:text-text cursor-pointer px-1.5 py-0.5"
              aria-label={showPass ? 'Hide password' : 'Show password'}
            >
              {showPass ? 'Hide' : 'Show'}
            </button>
          </div>
          <p className="text-xs text-text-muted mt-1">Must be at least 8 characters</p>
        </div>
        <div>
          <label htmlFor="reset-confirm" className="block text-sm text-text-muted mb-1">Confirm Password</label>
          <div className="relative">
            <input
              id="reset-confirm"
              type={showConfirm ? 'text' : 'password'}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
              className="w-full bg-surface border border-border rounded-md px-3 py-2 pr-16 text-text focus:outline-none focus:border-primary"
            />
            <button
              type="button"
              onClick={() => setShowConfirm(!showConfirm)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-text-muted hover:text-text cursor-pointer px-1.5 py-0.5"
              aria-label={showConfirm ? 'Hide password' : 'Show password'}
            >
              {showConfirm ? 'Hide' : 'Show'}
            </button>
          </div>
        </div>
        <button
          type="submit"
          disabled={loading || password.length < 8}
          className="w-full bg-primary hover:bg-primary-dark text-white py-2 rounded-md transition-colors disabled:opacity-50 cursor-pointer"
        >
          {loading ? 'Resetting...' : 'Reset Password'}
        </button>
      </form>
    </div>
  )
}
