import { Navigate } from 'react-router-dom'
import { rp } from '../basePath'

/**
 * /badge moved into /for-developers (#badge) on 2026-11-11: one developer page for
 * claiming a tool, its badge, and private repos. This route stays so old links keep
 * working; nginx answers /badge with a 301 to the same place. README badges never
 * pointed here (they use /api/v1/public/scan/…/badge), so no embed changes.
 */
export default function RebrandBadge() {
  return <Navigate to={{ pathname: rp('/rebrand/for-developers'), hash: '#badge' }} replace />
}
