import { Navigate } from 'react-router-dom'
import { rp } from '../basePath'

/**
 * /submit ("List your tool") moved into /for-developers (#list) on 2026-11-11: the
 * form is components/ListToolForm.tsx now. This route stays so old links keep
 * working; nginx answers /submit with a 301 to the same place.
 */
export default function RebrandSubmit() {
  return <Navigate to={{ pathname: rp('/rebrand/for-developers'), hash: '#list' }} replace />
}
