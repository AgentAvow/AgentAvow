import { currentPath, listingCta, trackCta, trackEvent } from '../../lib/analytics'

/** The two assistant listings. */
export const CLAUDE_LISTING = 'https://claude.ai/directory/connectors/agentavow'
export const CHATGPT_LISTING = 'https://chatgpt.com/plugins/plugin_asdk_app_6ac830ccc2d48191ac27974dec7d8344'

/** Count a click on a listing link: the #253 cta_click, plus the older guest funnel event. */
export function trackListing(href: string) {
  const cta = listingCta(href)
  if (!cta) return
  trackEvent('guest_cta_click', currentPath(), cta)
  trackCta(cta)
}
