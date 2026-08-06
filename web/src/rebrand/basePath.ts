/**
 * Cutover base-path.
 *
 * Before cutover the rebrand lives under /rebrand (a preview alongside the old
 * site). At cutover it becomes the root site (/check, /browse, …). Rather than
 * hard-rewrite every link, all rebrand links pass through `rp()`:
 *
 *   - VITE_CUTOVER unset/false → `rp('/rebrand/check')` === '/rebrand/check'  (identical to today)
 *   - VITE_CUTOVER === 'true'  → `rp('/rebrand/check')` === '/check'          (root site)
 *
 * So deploying with the flag OFF changes nothing for users; flipping it at cutover
 * promotes the whole rebrand to the root with clean URLs. App.tsx mounts the route
 * tree at REBRAND_BASE (or '/') the same way.
 */
export const REBRAND_BASE = import.meta.env.VITE_CUTOVER === 'true' ? '' : '/rebrand'

/** Rewrite a `/rebrand/...` path for the current mode. Pass the full preview path. */
export function rp(path: string): string {
  if (REBRAND_BASE) return path // preview mode — leave /rebrand/... untouched
  const stripped = path.replace(/^\/rebrand/, '')
  return stripped || '/'
}
