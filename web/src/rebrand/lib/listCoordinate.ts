/** The coordinate parser for the "add a tool to the catalog" form (components/ListToolForm). */

/** Parse a pasted coordinate into {surface, identifier} for the submit endpoint —
 * mirrors the Check page's router logic, but returns the coordinate instead of routing. */
export function parseCoordinate(raw: string): { surface: string; identifier: string } | null {
  const v = raw.trim()
  if (!v) return null
  const pkg = v.match(/^(npm|pypi|python|crates|cargo|rust|hf|huggingface|docker|container|oci)\s*:\s*(.+)$/i)
  if (pkg) {
    const k = pkg[1].toLowerCase()
    const surface = k === 'python' ? 'pypi'
      : (k === 'cargo' || k === 'rust') ? 'crates'
      : k === 'hf' ? 'huggingface'
      : (k === 'container' || k === 'oci') ? 'docker' : k
    return { surface, identifier: pkg[2].trim() }
  }
  let m
  // mcp:https://… (the Check page's prefix); without this the URL fell through to owner/repo.
  if ((m = v.match(/^mcp\s*:\s*(https?:\/\/\S+)$/i))) return { surface: 'mcp', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/(?:www\.)?crates\.io\/crates\/([\w-]+)/i))) return { surface: 'crates', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/(?:www\.)?npmjs\.com\/package\/((?:@[\w.-]+\/)?[\w.-]+)/i))) return { surface: 'npm', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/pypi\.org\/project\/([\w.-]+)/i))) return { surface: 'pypi', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/huggingface\.co\/([\w.-]+\/[\w.-]+)(?:$|[/?#])/i)) &&
      !/^(datasets|spaces|models|organizations|settings)\//i.test(m[1])) return { surface: 'huggingface', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/hub\.docker\.com\/_\/([\w.-]+)/i))) return { surface: 'docker', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/hub\.docker\.com\/r\/([\w.-]+\/[\w.-]+)/i))) return { surface: 'docker', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/ghcr\.io\/([\w.-]+\/[\w.-]+)/i))) return { surface: 'docker', identifier: `ghcr.io/${m[1]}` }
  // A bare non-GitHub URL → a live MCP endpoint.
  if (/^https?:\/\/\S+$/i.test(v) && !/^https?:\/\/(www\.)?(github|gitlab)\.com\//i.test(v)) {
    return { surface: 'mcp', identifier: v }
  }
  // owner/repo (optionally a github URL) → a repo.
  const g = v.match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
  if (g) return { surface: 'github', identifier: `${g[1]}/${g[2]}` }
  return null
}
