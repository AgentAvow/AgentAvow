// Cloudflare Web Analytics, kept off check pages.
//
// A check page's address names the tool checked, and for a one-time private scan that
// is a private repository (/check/<owner>/<repo>). Cloudflare must never receive one.
//
// The beacon reports in two ways, and both read the address at the time they send:
//   1. a page load, once the window's load event has fired;
//   2. a performance (web vitals) report when the tab is hidden or closed.
// The second is sent even with "spa": false, from whatever path the app shows then. So
// skipping the beacon on pages that start on /check is not enough: someone can land on
// /my-tools, run a private scan, and switch tabs on its result page.
//
// So:
//   - On a page that starts under /check/ the beacon is never loaded.
//   - Elsewhere it loads with "spa": false, so in-app navigation is not reported.
//   - The moment the app is about to show a /check/ path, before the address changes, we
//     add a stricter Content-Security-Policy to the page that leaves cloudflareinsights.com
//     out of connect-src. The browser then refuses every later beacon request from this
//     page, whichever API it uses. A policy can only be tightened, never relaxed, so this
//     lasts until the page is reloaded. Nothing else is blocked: the list below is the
//     nginx connect-src minus Cloudflare (tests/test_cloudflare_beacon.py holds them in step).
//
// Loaded from the bundle rather than index.html, so no inline script is needed and every
// prerendered page (built from the same shell) behaves the same way.

const BEACON_SRC = 'https://static.cloudflareinsights.com/beacon.min.js'
// Public by design: it ships in the page. Manage at dash.cloudflare.com, Analytics, Web Analytics.
const BEACON_TOKEN = '37a4346b3e4546e6975f2ba3bf43dd4b'
export const CONNECT_SRC_WITHOUT_BEACON =
  "'self' wss://agentavow.com wss://agentgraph.co https://accounts.google.com"

/** True for a check result page: /check/<anything>, also under the pre-cutover /rebrand base. */
export function isCheckPath(pathname: string): boolean {
  let path = pathname
  try {
    path = decodeURIComponent(pathname)
  } catch {
    // Keep it as written.
  }
  // The router matches case-insensitively and tolerates repeated slashes.
  path = path.replace(/\/{2,}/g, '/').toLowerCase()
  return /^\/(?:rebrand\/)?check\//.test(path)
}

let blocked = false

function blockBeacon(): void {
  if (blocked) return
  blocked = true
  const meta = document.createElement('meta')
  meta.httpEquiv = 'Content-Security-Policy'
  meta.content = `connect-src ${CONNECT_SRC_WITHOUT_BEACON}`
  document.head.prepend(meta)
}

function guard(url: string | URL | null | undefined): void {
  if (blocked || url == null) return
  try {
    if (isCheckPath(new URL(String(url), window.location.href).pathname)) blockBeacon()
  } catch {
    // An address the browser can't parse won't navigate either.
  }
}

/** Call once, before the router starts. Production builds only. */
export function startCloudflareAnalytics(): void {
  if (typeof window === 'undefined' || !import.meta.env.PROD) return

  // Every way a page changes its address without reloading: the router's pushState and
  // replaceState (checked before the change), Back and Forward (popstate), and the
  // Navigation API where the browser has it (its navigate event fires before the change).
  const { pushState, replaceState } = window.history
  window.history.pushState = function (data: unknown, unused: string, url?: string | URL | null) {
    guard(url)
    return pushState.call(this, data, unused, url)
  }
  window.history.replaceState = function (data: unknown, unused: string, url?: string | URL | null) {
    guard(url)
    return replaceState.call(this, data, unused, url)
  }
  window.addEventListener('popstate', () => guard(window.location.href), true)
  const navigation = (window as unknown as { navigation?: EventTarget }).navigation
  navigation?.addEventListener('navigate', (event) => {
    guard((event as Event & { destination?: { url?: string } }).destination?.url)
  })

  if (isCheckPath(window.location.pathname)) {
    blockBeacon()
    return
  }
  const script = document.createElement('script')
  script.defer = true
  script.src = BEACON_SRC
  script.setAttribute('data-cf-beacon', JSON.stringify({ token: BEACON_TOKEN, spa: false }))
  document.head.appendChild(script)
}
