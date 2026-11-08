import { currentPath, listingCta, trackCta, trackEvent } from '../../lib/analytics'

export const CLAUDE_LISTING = 'https://claude.ai/directory/connectors/agentavow'
export const CHATGPT_LISTING = 'https://chatgpt.com/plugins/plugin_asdk_app_6ac830ccc2d48191ac27974dec7d8344'

/** A click on one of our assistant listings, counted the same way as on Home. */
export function trackListingClick(href: string): void {
  const cta = listingCta(href)
  if (!cta) return
  trackEvent('guest_cta_click', currentPath(), cta)
  trackCta(cta)
}
