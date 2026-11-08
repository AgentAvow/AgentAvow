// Meta Pixel, on /claude-code only (the page our Meta ads lead to).
//
// What it sends: a PageView when the page opens, and one custom event the first time
// someone copies the install command. Nothing else:
//   - no Advanced Matching (init gets no user data, and the page has no form to read),
//   - automatic events off (autoConfig false: no button-click or page-metadata events),
//   - no SPA page views (disablePushState), and no Conversions API on our servers.
//
// Where it runs: only in a document nginx served for /claude-code, because that is the
// only location whose Content-Security-Policy allows connect.facebook.net and
// www.facebook.com (nginx/nginx.conf). A visit that reaches /claude-code by in-app
// navigation keeps the policy of the page it started on, so the pixel is not loaded
// there either. Production, agentavow.com only, and never when the browser sends
// Global Privacy Control or Do Not Track. Disclosed in the privacy policy, section 5.
//
// The standard Meta snippet is an inline script, which our CSP forbids, so this builds
// the same queue stub in the bundle and adds the script tag itself.

export const META_PIXEL_ID = '1727269052296184'
export const META_PIXEL_PATH = '/claude-code'
const PIXEL_SRC = 'https://connect.facebook.net/en_US/fbevents.js'
const PIXEL_HOSTS = new Set(['agentavow.com'])
const COPY_EVENT = 'CopyInstallCommand'

type Fbq = ((...args: unknown[]) => void) & {
  callMethod?: (...args: unknown[]) => void
  queue: unknown[]
  push: Fbq
  loaded: boolean
  version: string
  disablePushState?: boolean
}

let fbq: Fbq | null = null
let copySent = false

/** The path of the document the browser loaded, which is what its CSP was sent for. */
function documentPath(): string | null {
  try {
    const nav = performance.getEntriesByType('navigation')[0]
    return nav ? new URL(nav.name).pathname : null
  } catch {
    return null
  }
}

function optedOut(): boolean {
  const nav = navigator as Navigator & { globalPrivacyControl?: boolean }
  return nav.globalPrivacyControl === true || nav.doNotTrack === '1'
}

/** Call from the /claude-code page with the router's pathname. Safe to call more than once. */
export function startMetaPixel(pathname: string): void {
  try {
    if (fbq || typeof window === 'undefined' || !import.meta.env.PROD) return
    if (pathname !== META_PIXEL_PATH || documentPath() !== META_PIXEL_PATH) return
    if (!PIXEL_HOSTS.has(window.location.hostname) || optedOut()) return

    const w = window as unknown as { fbq?: Fbq; _fbq?: Fbq }
    if (w.fbq) return
    const stub = function (...args: unknown[]) {
      if (stub.callMethod) stub.callMethod(...args)
      else stub.queue.push(args)
    } as Fbq
    stub.push = stub
    stub.loaded = true
    stub.version = '2.0'
    stub.queue = []
    stub.disablePushState = true
    w.fbq = stub
    w._fbq = stub
    fbq = stub

    stub('set', 'autoConfig', false, META_PIXEL_ID)
    stub('init', META_PIXEL_ID)
    stub('track', 'PageView')

    const script = document.createElement('script')
    script.async = true
    script.src = PIXEL_SRC
    document.head.appendChild(script)
  } catch {
    // An ad pixel must never break the page.
  }
}

/** The install command was copied. Sent once per page load, with no parameters. */
export function trackMetaInstallCopy(): void {
  try {
    if (!fbq || copySent) return
    copySent = true
    fbq('trackCustom', COPY_EVENT)
  } catch {
    // Silently ignore
  }
}
