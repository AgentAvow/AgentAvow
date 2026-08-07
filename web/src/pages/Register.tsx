import { useState, useEffect, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { trackEvent, getSessionId } from '../lib/analytics'
import SEOHead from '../components/SEOHead'

export default function Register() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPass, setShowPass] = useState(false)
  const { register } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const returnTo = searchParams.get('returnTo')
  const intent = searchParams.get('intent')

  useEffect(() => {
    document.title = 'Create Account - AgentAvow'
    trackEvent('register_start', '/register', intent || undefined)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const hasUpper = /[A-Z]/.test(password)
  const hasLower = /[a-z]/.test(password)
  const hasNumber = /[0-9]/.test(password)
  const hasLength = password.length >= 8
  const passwordValid = hasUpper && hasLower && hasNumber && hasLength
  const strengthCount = [hasUpper, hasLower, hasNumber, hasLength].filter(Boolean).length

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await register(email, password, displayName, getSessionId())
      trackEvent('register_complete', '/register', intent || undefined)
      const destination = returnTo || '/onboarding?welcome=1'
      navigate(destination, { state: { showVerifyBanner: true } })
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0">
      <SEOHead title="Create Account" path="/register" noindex />
      <h1 className="text-xl sm:text-2xl font-bold mb-6">Create your account</h1>
      {error && (
        <div role="alert" className="bg-danger/10 text-danger text-sm px-4 py-2 rounded mb-4">
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="register-name" className="block text-sm text-text-muted mb-1">Display Name <span className="text-danger">*</span></label>
          <input
            id="register-name"
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            required
            minLength={2}
            maxLength={50}
            autoComplete="name"
            className="w-full bg-surface border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
          />
        </div>
        <div>
          <label htmlFor="register-email" className="block text-sm text-text-muted mb-1">Email <span className="text-danger">*</span></label>
          <input
            id="register-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            className="w-full bg-surface border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
          />
        </div>
        <div>
          <label htmlFor="register-password" className="block text-sm text-text-muted mb-1">Password <span className="text-danger">*</span></label>
          <div className="relative">
            <input
              id="register-password"
              type={showPass ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
              aria-describedby="password-strength"
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
          {password && (
            <div className="mt-2" id="password-strength" role="status" aria-live="polite">
              <div className="flex gap-1 mb-1" aria-hidden="true">
                {[1, 2, 3, 4].map((i) => (
                  <div
                    key={i}
                    className={`h-1 flex-1 rounded-full transition-colors ${
                      i <= strengthCount
                        ? strengthCount <= 2 ? 'bg-danger' : strengthCount === 3 ? 'bg-warning' : 'bg-success'
                        : 'bg-border'
                    }`}
                  />
                ))}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px]">
                <span className={hasLength ? 'text-success' : 'text-text-muted'}>8+ chars</span>
                <span className={hasUpper ? 'text-success' : 'text-text-muted'}>Uppercase</span>
                <span className={hasLower ? 'text-success' : 'text-text-muted'}>Lowercase</span>
                <span className={hasNumber ? 'text-success' : 'text-text-muted'}>Number</span>
              </div>
            </div>
          )}
        </div>
        <button
          type="submit"
          disabled={loading || !passwordValid}
          className="w-full bg-primary hover:bg-primary-dark text-white py-2 rounded-md transition-colors disabled:opacity-50 cursor-pointer"
        >
          {loading ? 'Creating account...' : 'Create account'}
        </button>
      </form>

      {/* Google OAuth divider and button */}
      <div className="relative my-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-border" />
        </div>
        <div className="relative flex justify-center text-xs">
          <span className="bg-background px-3 text-text-muted">or</span>
        </div>
      </div>

      <div className="space-y-3">
        <a
          href="/api/v1/auth/google"
          className="w-full flex items-center justify-center gap-3 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 py-2 rounded-md transition-colors font-medium text-sm"
        >
          <svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615Z" fill="#4285F4"/><path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18Z" fill="#34A853"/><path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.997 8.997 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332Z" fill="#FBBC05"/><path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58Z" fill="#EA4335"/></svg>
          Sign up with Google
        </a>
        <a
          href="/api/v1/auth/github"
          className="w-full flex items-center justify-center gap-3 bg-[#24292f] hover:bg-[#32383f] text-white border border-[#1b1f23] py-2 rounded-md transition-colors font-medium text-sm"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          Sign up with GitHub
        </a>
      </div>

      <p className="text-xs text-text-muted mt-4 text-center leading-relaxed">
        By creating an account, you agree to our{' '}
        <Link to="/legal/terms" className="text-primary-light hover:underline">Terms of Service</Link>
        {' '}and{' '}
        <Link to="/legal/privacy" className="text-primary-light hover:underline">Privacy Policy</Link>.
      </p>

      <p className="text-sm text-text-muted mt-3 text-center">
        Already have an account?{' '}
        <Link to={`/login${returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ''}`} className="text-primary-light hover:underline">
          Sign in
        </Link>
      </p>

    </div>
  )
}
