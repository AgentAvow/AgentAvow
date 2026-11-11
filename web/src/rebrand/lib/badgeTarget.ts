/**
 * What the badge maker on /for-developers accepts, and where each kind's badge lives.
 * The endpoints already exist (src/api/public_scan_router.py):
 *   repo     /api/v1/public/scan/{owner}/{repo}/badge
 *   package  /api/v1/public/scan/package/{surface}/{name}/badge   (npm, pypi, crates)
 *   mcp      /api/v1/public/scan/mcp/badge?endpoint=…             (no "classic" style)
 */

export type BadgeStyle = 'compact' | 'card' | 'classic'

export interface BadgeTarget {
  kind: 'repo' | 'package' | 'mcp'
  /** What the user means, in our coordinate form: owner/repo, npm:name, or the URL. */
  label: string
  /** Badge image path (no origin), for a style. */
  badgePath: (style: BadgeStyle) => string
  /** The report page path (no origin, no /rebrand prefix). */
  reportPath: string
  /** The widget's data-tool value, or null when the widget can't show this kind. */
  widgetSlug: string | null
  /** The styles this kind's badge endpoint serves. */
  styles: BadgeStyle[]
}

const PKG = /^(npm|pypi|crates)[:/](@?[\w.-]+(?:\/[\w.-]+)?)$/i
const REPO = /^(?:https?:\/\/)?(?:www\.)?(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i

const qs = (style: BadgeStyle) => (style === 'compact' ? '' : `?style=${style}`)

/** Parse the badge box input. Null when it isn't a repo, package or MCP URL. */
export function parseBadgeTarget(raw: string): BadgeTarget | null {
  const s = raw.trim()
  if (!s) return null
  let m = s.match(PKG)
  if (m) {
    const surface = m[1].toLowerCase()
    const name = m[2]
    return {
      kind: 'package',
      label: `${surface}:${name}`,
      badgePath: (style) => `/api/v1/public/scan/package/${surface}/${name}/badge${qs(style)}`,
      reportPath: `/check/pkg/${surface}/${name}`,
      widgetSlug: `${surface}/${name}`,
      styles: ['compact', 'card', 'classic'],
    }
  }
  // A github.com link is a repo, not an MCP server.
  if (/^https?:\/\//i.test(s) && !/^https?:\/\/(?:www\.)?github\.com\//i.test(s)) {
    let url: URL
    try { url = new URL(s) } catch { return null }
    if (url.protocol !== 'https:') return null
    const endpoint = url.toString()
    const enc = encodeURIComponent(endpoint)
    return {
      kind: 'mcp',
      label: endpoint,
      badgePath: (style) => `/api/v1/public/scan/mcp/badge?endpoint=${enc}${style === 'card' ? '&style=card' : ''}`,
      reportPath: `/check/mcp?endpoint=${enc}`,
      widgetSlug: null,
      styles: ['compact', 'card'],
    }
  }
  m = s.match(REPO)
  if (m) {
    const owner = m[1], repo = m[2]
    return {
      kind: 'repo',
      label: `${owner}/${repo}`,
      badgePath: (style) => `/api/v1/public/scan/${owner}/${repo}/badge${qs(style)}`,
      reportPath: `/check/${owner}/${repo}`,
      widgetSlug: `${owner}/${repo}`,
      styles: ['compact', 'card', 'classic'],
    }
  }
  return null
}
