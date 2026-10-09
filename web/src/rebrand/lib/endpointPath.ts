/** `/check/mcp.deepwiki.com/mcp` → `https://mcp.deepwiki.com/mcp`.
 *
 * A check path whose first segment is a hostname is an MCP endpoint someone typed
 * or pasted into the address bar, not a GitHub `owner/repo`: GitHub user and org
 * names are letters, digits and single hyphens only, so they never contain a dot.
 * Returns null for every other check path. */
export function endpointFromCheckPath(pathname: string): string | null {
  const i = pathname.indexOf('/check/')
  if (i < 0) return null
  let rest = pathname.slice(i + '/check/'.length).replace(/^\/+/, '')
  // A pasted full URL ("/check/https://host/path") arrives as "https:/host/path".
  rest = rest.replace(/^https?:\/*/i, '')
  const first = rest.split('/')[0] ?? ''
  if (!first.includes('.')) return null
  // host[:port] made of hostname characters only, with a dot-separated TLD.
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d{1,5})?$/i.test(first)) return null
  return `https://${rest.replace(/\/+$/, '')}`
}
