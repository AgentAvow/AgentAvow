import { rp } from '../basePath'

/**
 * Sign-in return paths. A page that needs an account sends people to
 * `/login?returnTo=<where they were>`, and Login sends them back there after sign-in.
 *
 * Only same-site paths are honoured: a returnTo must start with a single "/" (no
 * "//host" or "/\host", which browsers treat as another origin), and it never points
 * back at the login page itself.
 */
export function safeReturnTo(raw: string | null | undefined): string | null {
  if (!raw) return null
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) return null
  if ([...raw].some((ch) => ch.charCodeAt(0) < 0x20)) return null
  const path = raw.split(/[?#]/)[0]
  if (path === rp('/rebrand/login')) return null
  return raw
}

/** The login link that brings the user back to `returnTo` (pathname + search + hash). */
export function loginHref(returnTo?: string): string {
  const safe = safeReturnTo(returnTo)
  return rp('/rebrand/login') + (safe ? `?returnTo=${encodeURIComponent(safe)}` : '')
}

/** The current location as a returnTo value. */
export function here(loc: { pathname: string; search: string; hash: string }): string {
  return loc.pathname + loc.search + loc.hash
}
