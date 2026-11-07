import api from './api'

const SESSION_KEY = 'ag_session_id'
const UTM_KEY = 'ag_utm'
const LANDED_KEY = 'ag_landed'
const UTM_FIELDS = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'] as const
const MAX_PAGE_LENGTH = 200 // TrackEventRequest.page
const MAX_UTM_LENGTH = 200 // analytics_first_touch columns
// A one-time private scan promises that nothing is stored, so its repo name stays out of events.
const PRIVATE_SCAN_PATH = '/check/private'
const PLUGIN_COMMAND = /\/plugin\s+(?:marketplace\s+add\s+AgentAvow\/AgentAvow|install\s+agentavow-trust@agentavow)/i

export type CtaDestination = 'copy_plugin_cmd' | 'open_plugin_dir' | 'add_claude' | 'add_chatgpt'
export type BadgeFormat = 'badge' | 'card' | 'widget'

// Browsers can block storage outright, and analytics must never break the page because of it.
// Values also live here, so a session id stays stable for the page load when storage is off.
const memory = new Map<string, string>()

function readStored(store: () => Storage, key: string): string | null {
  try {
    const value = store().getItem(key)
    if (value !== null) return value
  } catch {
    // Fall through to the in-memory copy
  }
  return memory.get(key) ?? null
}

function writeStored(store: () => Storage, key: string, value: string): void {
  memory.set(key, value)
  try {
    store().setItem(key, value)
  } catch {
    // The in-memory copy is enough
  }
}

const local = () => window.localStorage
const session = () => window.sessionStorage

export function getSessionId(): string {
  let id = readStored(local, SESSION_KEY)
  if (!id) {
    id = typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2) + Date.now().toString(36)
    writeStored(local, SESSION_KEY, id)
  }
  return id
}

/**
 * Capture UTM params from the current URL and store in sessionStorage.
 * Should be called once on app mount. Overwrites only if UTM params are present.
 * The server keeps the first set per session, so a later visit keeps its campaign.
 */
export function captureUtmParams(): void {
  try {
    const params = new URLSearchParams(window.location.search)
    const utm: Record<string, string> = {}
    for (const field of UTM_FIELDS) {
      const value = params.get(field)?.replace(/\p{Cc}/gu, '').trim().slice(0, MAX_UTM_LENGTH)
      if (value) utm[field] = value
    }
    if (Object.keys(utm).length > 0) writeStored(session, UTM_KEY, JSON.stringify(utm))
  } catch {
    // Silently ignore
  }
}

/**
 * Retrieve stored UTM params from sessionStorage.
 * Returns empty object if none captured.
 */
export function getUtmParams(): Record<string, string> {
  try {
    const raw = readStored(session, UTM_KEY)
    if (raw) return JSON.parse(raw) as Record<string, string>
  } catch {
    // Silently ignore
  }
  return {}
}

/**
 * The path to report for this page. Never includes the query string: /check/mcp carries the
 * server being checked in ?endpoint=.
 */
export function currentPath(): string {
  try {
    if (window.history.state?.usr?.privateResult) return PRIVATE_SCAN_PATH
    return window.location.pathname
  } catch {
    return '/'
  }
}

export function trackEvent(
  type: string,
  page: string,
  intent?: string,
  metadata?: Record<string, unknown>,
): void {
  try {
    const utm = getUtmParams()
    const mergedMetadata = { ...utm, ...metadata }

    const body: Record<string, unknown> = {
      event_type: type,
      session_id: getSessionId(),
      page: page.slice(0, MAX_PAGE_LENGTH),
    }
    if (intent) body.intent = intent
    if (Object.keys(mergedMetadata).length > 0) body.metadata = mergedMetadata

    // Fire and forget — don't block UI
    api.post('/analytics/event', body).catch(() => {
      // Silently ignore analytics failures
    })
  } catch {
    // Silently ignore analytics failures
  }
}

/**
 * The page a visit starts on. Fires once per tab, and again if a new campaign link brings the
 * same tab back. Call on every route change; it decides for itself.
 */
export function trackLandingView(): void {
  const utm = readStored(session, UTM_KEY) ?? ''
  if (readStored(session, LANDED_KEY) === utm) return
  writeStored(session, LANDED_KEY, utm)
  trackEvent('lp_view', currentPath())
}

/** Someone submitted a check box. Never pass the input: what they typed stays out of analytics. */
export function trackCheckSubmit(): void {
  trackEvent('check_submit', currentPath())
}

/** A check result is on screen. Sends no verdict or score. */
export function trackResultView(): void {
  trackEvent('result_view', currentPath())
}

export function trackCta(destination: CtaDestination): void {
  trackEvent('cta_click', currentPath(), destination)
}

export function trackBadgeCopied(format: BadgeFormat): void {
  trackEvent('badge_copied', currentPath(), format)
}

export function trackContactSubmit(): void {
  trackEvent('contact_submit', currentPath())
}

/**
 * For onCopy on text that shows the /plugin commands: fires when the copied selection has one.
 * The selection itself is not sent.
 */
export function trackPluginCommandCopy(): void {
  try {
    if (PLUGIN_COMMAND.test(String(window.getSelection()))) trackCta('copy_plugin_cmd')
  } catch {
    // Silently ignore
  }
}

/** The CTA a link to one of our assistant listings counts as, if it is one. */
export function listingCta(href: string): CtaDestination | null {
  if (href.startsWith('https://claude.ai/directory/connectors/agentavow')) return 'add_claude'
  if (href.startsWith('https://chatgpt.com/plugins/plugin_asdk_app_')) return 'add_chatgpt'
  return null
}
