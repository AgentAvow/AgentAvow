import { useState, useEffect, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import api from '../lib/api'
import SEOHead from '../components/SEOHead'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [loading, setLoading] = useState(false)

  useEffect(() => { document.title = 'Forgot Password - AgentAvow' }, [])

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.post('/auth/forgot-password', { email })
    } catch {
      // Don't reveal errors — always show success to prevent email enumeration
    } finally {
      setLoading(false)
      setSubmitted(true)
    }
  }

  if (submitted) {
    return (
      <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0 text-center space-y-4">
        <h1 className="text-xl font-bold">Check Your Email</h1>
        <p className="text-sm text-text-muted">
          If an account with that email exists, we've sent password reset instructions.
        </p>
        <Link to="/login" className="inline-block text-primary-light hover:underline text-sm">
          Back to login
        </Link>
      </div>
    )
  }

  return (
    <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0">
      <SEOHead title="Forgot Password" path="/forgot-password" noindex />
      <h1 className="text-xl font-bold mb-2">Reset your password</h1>
      <p className="text-sm text-text-muted mb-6">
        Enter your email address and we'll send you a link to reset your password.
      </p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="forgot-email" className="block text-sm text-text-muted mb-1">Email</label>
          <input
            id="forgot-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            className="w-full bg-surface border border-border rounded-md px-3 py-2 text-text focus:outline-none focus:border-primary"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-primary hover:bg-primary-dark text-white py-2 rounded-md transition-colors disabled:opacity-50 cursor-pointer"
        >
          {loading ? 'Sending...' : 'Send Reset Link'}
        </button>
      </form>
      <p className="text-sm text-text-muted mt-4 text-center">
        <Link to="/login" className="text-primary-light hover:underline">
          Back to login
        </Link>
      </p>
    </div>
  )
}
