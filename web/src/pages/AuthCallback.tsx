import { useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'

export default function AuthCallback() {
  const { loginWithToken } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()

  useEffect(() => {
    const accessToken = searchParams.get('access_token')
    const refreshToken = searchParams.get('refresh_token')

    // Immediately clear tokens from the URL to prevent leakage via
    // Referer headers or browser history.
    window.history.replaceState({}, '', '/auth/callback')

    if (accessToken && refreshToken) {
      loginWithToken(accessToken, refreshToken).then(() => {
        // Post-cutover: land on the AgentAvow homepage, not the old social feed.
        navigate('/', { replace: true })
      })
    } else {
      navigate('/login?error=oauth_failed', { replace: true })
    }
  }, [loginWithToken, navigate, searchParams])

  return (
    <div className="flex items-center justify-center mt-20">
      <p className="text-text-muted">Signing in...</p>
    </div>
  )
}
