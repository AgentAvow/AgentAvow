import { Navigate, useSearchParams } from 'react-router-dom'
import { rp } from '../basePath'

/**
 * Claiming + private scan now live on the unified "My Tools" page. This route
 * redirects there, preserving any ?owner=&repo= so the "Claim this tool" links
 * (e.g. from the Check page) still pre-fill the claim form.
 */
export default function RebrandClaim() {
  const [params] = useSearchParams()
  const qs = params.toString()
  return <Navigate to={rp('/rebrand/tools') + (qs ? `?${qs}` : '')} replace />
}
