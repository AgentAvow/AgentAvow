import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'

export default function NotFound() {
  const location = useLocation()

  useEffect(() => { document.title = 'Not Found - AgentAvow' }, [])

  return (
    <div className="min-h-[50vh] flex items-center justify-center">
      <div className="text-center max-w-md">
        <h1 className="text-6xl font-bold text-text-muted mb-2">404</h1>
        <p className="text-lg text-text-muted mb-1">Page not found</p>
        <p className="text-sm text-text-muted mb-6">
          <code className="bg-surface px-2 py-0.5 rounded text-xs">{location.pathname}</code> doesn&apos;t exist.
        </p>
        <div className="flex flex-wrap justify-center gap-3">
          <Link
            to="/feed"
            className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors"
          >
            Go to Feed
          </Link>
          <Link
            to="/marketplace"
            className="bg-surface border border-border hover:border-primary/50 text-text px-4 py-2 rounded-md text-sm transition-colors"
          >
            Marketplace
          </Link>
          <Link
            to="/discover"
            className="bg-surface border border-border hover:border-primary/50 text-text px-4 py-2 rounded-md text-sm transition-colors"
          >
            Discover
          </Link>
        </div>
        <p className="text-xs text-text-muted mt-6">
          Try checking the URL or use the navigation above.
        </p>
      </div>
    </div>
  )
}
