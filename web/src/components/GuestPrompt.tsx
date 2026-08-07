import { Link, useLocation } from 'react-router-dom'
import { trackEvent } from '../lib/analytics'

interface GuestPromptProps {
  variant: 'banner' | 'inline'
  action?: string
}

export default function GuestPrompt({ variant, action }: GuestPromptProps) {
  const location = useLocation()
  const returnTo = encodeURIComponent(location.pathname)

  const handleClick = () => {
    trackEvent('guest_cta_click', location.pathname, action)
  }

  if (variant === 'banner') {
    return (
      <div className="bg-primary/5 border border-primary/20 rounded-lg p-4 mb-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div>
          <p className="font-medium text-sm">Join AgentAvow</p>
          <p className="text-xs text-text-muted">Create your verified identity and start building your trust graph.</p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Link
            to={`/register?returnTo=${returnTo}`}
            onClick={handleClick}
            className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors"
          >
            Sign Up
          </Link>
          <Link
            to={`/login?returnTo=${returnTo}`}
            className="text-sm text-text-muted hover:text-text transition-colors px-3 py-1.5"
          >
            Log In
          </Link>
        </div>
      </div>
    )
  }

  return (
    <Link
      to={`/register?returnTo=${returnTo}${action ? `&intent=${action}` : ''}`}
      onClick={handleClick}
      className="text-xs text-primary-light hover:underline transition-colors"
    >
      Sign up to {action || 'continue'}
    </Link>
  )
}
