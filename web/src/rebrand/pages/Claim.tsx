import { Navigate, useSearchParams } from 'react-router-dom'
import { rp } from '../basePath'

/**
 * Claiming + private scan now live on the unified "My Tools" page. This route
 * redirects there. Old "Claim this tool" links carry ?owner=&repo=; My Tools
 * pre-fills its claim box from ?coord=, so translate the pair into coord=owner/repo.
 */
export default function RebrandClaim() {
  const [params] = useSearchParams()
  const next = new URLSearchParams(params)
  const owner = next.get('owner')
  const repo = next.get('repo')
  if (owner && repo && !next.get('coord')) {
    next.set('coord', `${owner}/${repo}`)
    next.delete('owner')
    next.delete('repo')
  }
  const qs = next.toString()
  return <Navigate to={rp('/rebrand/tools') + (qs ? `?${qs}` : '')} replace />
}
