import { rp } from '../basePath'

/**
 * One place that turns a stored tool coordinate into a readable label, a surface chip
 * and the right score-page route. Watches and watch alerts store tools by coordinate
 * (src/api/watch_router.py): github → owner/repo · npm/pypi/crates/docker/huggingface →
 * owner=surface, repo=package · mcp → owner='mcp', repo=endpoint URL · openclaw →
 * owner/repo of the skill.
 */

const PKG_SURFACES = new Set(['npm', 'pypi', 'crates', 'docker', 'huggingface'])
const CHIP: Record<string, string> = { huggingface: 'hf', openclaw: 'skill' }

export interface ToolLink { label: string; badge: string; href: string }

export function toolLink(surface: string | undefined, owner: string, repo: string): ToolLink {
  const s = (surface || 'github').toLowerCase()
  if (PKG_SURFACES.has(s)) return { label: repo, badge: CHIP[s] ?? s, href: rp(`/rebrand/check/pkg/${s}/${repo}`) }
  if (s === 'mcp') return { label: repo, badge: 'mcp', href: rp('/rebrand/check/mcp') + `?endpoint=${encodeURIComponent(repo)}` }
  if (s === 'openclaw') return { label: `${owner}/${repo}`, badge: 'skill', href: rp(`/rebrand/check/skill/${owner}/${repo}`) }
  if (s === 'a2a') return { label: repo, badge: 'a2a', href: rp('/rebrand/check/a2a') + `?card=${encodeURIComponent(repo)}` }
  return { label: `${owner}/${repo}`, badge: 'github', href: rp(`/rebrand/check/${owner}/${repo}`) }
}

/** Label, chip and route for a watch alert's tool. `surface` is the API's resolved
 * surface (notification.tool.surface) when known, so a skill isn't shown as a repo. */
export function referenceLink(referenceId: string, surface?: string | null): ToolLink {
  const i = referenceId.indexOf('/')
  if (i <= 0) return toolLink('github', referenceId, '')
  const head = referenceId.slice(0, i)
  const rest = referenceId.slice(i + 1)
  const s = (surface || head).toLowerCase()
  if (PKG_SURFACES.has(s) || s === 'mcp') return toolLink(s, head, rest)
  return toolLink(s === 'openclaw' ? 'openclaw' : 'github', head, rest)
}

/** A watch alert's reference_id is the watch's "owner/repo"; the owner names the
 * surface for packages ("npm/@scope/pkg") and MCP ("mcp/https://…"). */
export function referenceHref(referenceId: string): string {
  const i = referenceId.indexOf('/')
  if (i <= 0) return rp(`/rebrand/check/${referenceId}`)
  const head = referenceId.slice(0, i)
  const rest = referenceId.slice(i + 1)
  const s = head.toLowerCase()
  if (PKG_SURFACES.has(s) || s === 'mcp') return toolLink(s, head, rest).href
  return toolLink('github', head, rest).href
}
