import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { here, loginHref } from './returnTo'

/** Send a signed-out visitor to sign in, with a way back to this exact page. */
export function useRequireUser(user: unknown, isLoading: boolean) {
  const navigate = useNavigate()
  const loc = useLocation()
  useEffect(() => {
    if (!isLoading && !user) navigate(loginHref(here(loc)), { replace: true })
  }, [isLoading, user, navigate, loc])
}
