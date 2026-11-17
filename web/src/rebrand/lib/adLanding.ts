import { getUtmParams } from '../../lib/analytics'
import { rp } from '../basePath'

/** The two lines that install the Claude Code plugin. */
export const PLUGIN_LINES = [
  '/plugin marketplace add AgentAvow/AgentAvow',
  '/plugin install agentavow-trust@agentavow',
]

const UTM_NAMES = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term'] as const

/** The ad's tags: the page URL's first, else the ones this tab arrived with. */
export function adTags(search: string): Record<string, string> {
  const tags: Record<string, string> = {}
  let stored: Record<string, string> = {}
  try {
    stored = getUtmParams()
  } catch {
    // None stored
  }
  let q: URLSearchParams | null = null
  try {
    q = new URLSearchParams(search)
  } catch {
    // Bad query string
  }
  for (const name of UTM_NAMES) {
    const v = q?.get(name) || stored[name]
    if (v) tags[name] = v
  }
  return tags
}

/**
 * The X wallet-key ads: x3-do-not-connect and x5-wallet-home (2026-11-test-x, see
 * docs/internal/ads-deep-dive-2026-11-16.md). Their homepage opens on the check and
 * the real results, the ad's finding among them.
 *
 * Reads the page URL only, not the tags stored for this tab (unlike adTags): after one
 * ad visit, the logo leads to the usual homepage. public/ad-hero.js does the same.
 */
export function isWalletKeyAd(search: string): boolean {
  let content = ''
  try {
    content = new URLSearchParams(search).get('utm_content') ?? ''
  } catch {
    // Bad query string
  }
  return /^x[35](?:-|$)/i.test(content)
}

/** /claude-code with the ad's tags, so an install made later on a computer still counts for the ad. */
export function setupUrl(search: string): string {
  const origin = typeof window === 'undefined' ? 'https://agentavow.com' : window.location.origin
  const q = new URLSearchParams(adTags(search)).toString()
  return `${origin}${rp('/rebrand/claude-code')}${q ? `?${q}` : ''}`
}
