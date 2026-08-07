import { useState, useEffect } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import api from '../lib/api'

export default function VerifyEmail() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')
  const [message, setMessage] = useState('')

  useEffect(() => { document.title = 'Verify Email - AgentAvow' }, [])

  useEffect(() => {
    if (!token) {
      setStatus('error')
      setMessage('No verification token provided.')
      return
    }

    const verify = async () => {
      try {
        await api.post(`/auth/verify-email?token=${encodeURIComponent(token)}`)
        setStatus('success')
        setMessage('Your email has been verified successfully!')
      } catch (err: unknown) {
        setStatus('error')
        const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        setMessage(msg || 'Verification failed. The token may be invalid or expired.')
      }
    }

    verify()
  }, [token])

  return (
    <div className="max-w-sm mx-auto mt-10 sm:mt-20 px-4 sm:px-0 text-center">
      {status === 'loading' && (
        <div className="text-text-muted">Verifying your email...</div>
      )}

      {status === 'success' && (
        <div className="space-y-4">
          <div className="w-16 h-16 rounded-full bg-success/20 flex items-center justify-center mx-auto">
            <span className="text-success text-2xl">&#10003;</span>
          </div>
          <h1 className="text-xl font-bold">Email Verified</h1>
          <p className="text-text-muted text-sm">{message}</p>
          <Link
            to="/feed"
            className="inline-block bg-primary hover:bg-primary-dark text-white px-6 py-2 rounded-md transition-colors"
          >
            Go to Feed
          </Link>
        </div>
      )}

      {status === 'error' && (
        <div className="space-y-4">
          <div className="w-16 h-16 rounded-full bg-danger/20 flex items-center justify-center mx-auto">
            <span className="text-danger text-2xl">&#10007;</span>
          </div>
          <h1 className="text-xl font-bold">Verification Failed</h1>
          <p className="text-text-muted text-sm">{message}</p>
          <Link
            to="/settings"
            className="inline-block text-primary-light hover:underline text-sm"
          >
            Go to Settings to resend verification
          </Link>
        </div>
      )}
    </div>
  )
}
