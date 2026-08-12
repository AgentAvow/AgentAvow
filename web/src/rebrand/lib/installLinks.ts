/**
 * "Add to your agent" install-link builders (research-verified 2026-08).
 *
 * Deeplinks that pre-fill arbitrary config exist for Cursor, VS Code, and Goose;
 * everyone else is a copy-paste command or config snippet. The grade "travels
 * with the install" because these affordances live on the signed score page.
 *
 *   Cursor : cursor.com/install-mcp?name=&config=<url-encoded base64(JSON)>
 *   VS Code: vscode:mcp/install?<url-encoded JSON with name flattened in>
 *   Goose  : goose://extension?url=&type=streamable_http&id=&name=&description=
 */

/** A remote (Streamable-HTTP) MCP server — what our live MCP scan produces. */
export interface McpTarget {
  name: string
  url: string
}

// Generic labels that make a useless server name (a leading `mcp.` subdomain, an
// `@scope/mcp` package). We skip/qualify them so the install names the server
// something meaningful — "deepwiki", "playwright-mcp" — not "mcp".
const _GENERIC_NAMES = new Set(['mcp', 'server', 'mcp-server', 'api', 'www', 'app', 'cli', 'io', 'sh'])

/** Derive a short, safe, MEANINGFUL server name from an endpoint URL — the first
 * non-generic host label (so `mcp.deepwiki.com` → "deepwiki", not "mcp"). */
export function mcpNameFromUrl(url: string): string {
  try {
    const h = new URL(url).hostname.replace(/^www\./, '')
    const labels = h.split('.').filter(Boolean)
    // drop the public suffix (last label, usually the TLD) before picking
    const meaningful = labels.slice(0, Math.max(1, labels.length - 1))
    const pick = meaningful.find((l) => !_GENERIC_NAMES.has(l.toLowerCase())) || meaningful[0] || 'mcp-server'
    return pick.replace(/[^a-zA-Z0-9_-]/g, '') || 'mcp-server'
  } catch {
    return 'mcp-server'
  }
}

// ── deeplinks (true 1-click) ──────────────────────────────────────────────────

export function cursorInstall(t: McpTarget): string {
  const b64 = btoa(JSON.stringify({ url: t.url })) // config object WITHOUT the name
  return `https://cursor.com/install-mcp?name=${encodeURIComponent(t.name)}&config=${encodeURIComponent(b64)}`
}

export function vscodeInstall(t: McpTarget, insiders = false): string {
  const obj = { name: t.name, type: 'http', url: t.url } // name FLATTENED in, not base64
  const scheme = insiders ? 'vscode-insiders' : 'vscode'
  return `${scheme}:mcp/install?${encodeURIComponent(JSON.stringify(obj))}`
}

export function gooseInstall(t: McpTarget): string {
  const p = new URLSearchParams({
    url: t.url,
    type: 'streamable_http',
    id: t.name,
    name: t.name,
    description: `${t.name} — safety-graded by AgentAvow`,
  })
  return `goose://extension?${p.toString()}`
}

// ── copy-paste commands / configs ─────────────────────────────────────────────

export function claudeCodeCmd(t: McpTarget): string {
  return `claude mcp add --transport http ${t.name} ${t.url}`
}

export function geminiCmd(t: McpTarget): string {
  return `gemini mcp add ${t.name} --transport http ${t.url}`
}

export function codexCmd(t: McpTarget): string {
  return `codex mcp add ${t.name} --url ${t.url}`
}

/** Claude Desktop reaches a REMOTE server through the mcp-remote stdio bridge. */
export function claudeDesktopConfig(t: McpTarget): string {
  return JSON.stringify(
    { mcpServers: { [t.name]: { command: 'npx', args: ['-y', 'mcp-remote', t.url] } } },
    null,
    2,
  )
}

/** VS Code / Cursor project config file (mcpServers block, remote). */
export function mcpServersConfig(t: McpTarget): string {
  return JSON.stringify({ mcpServers: { [t.name]: { type: 'http', url: t.url } } }, null, 2)
}

// ── stdio MCP servers shipped as a package (the common case) ──────────────────
// Most MCP servers are run with `npx -y <pkg>` (npm) or `uvx <pkg>` (PyPI). Those
// get REAL 1-click deeplinks too — the client spawns the command locally.

export interface StdioTarget { name: string; command: string; args: string[] }

function pkgShortName(name: string): string {
  const scope = (name.match(/^@([^/]+)\//) || [])[1] || ''
  const base = name.replace(/^@[^/]+\//, '').replace(/[^a-zA-Z0-9_-]/g, '')
  // A generic base ("@playwright/mcp" → "mcp") gets qualified with its scope so the
  // server is named "playwright-mcp", not a colliding "mcp".
  if (scope && _GENERIC_NAMES.has(base.toLowerCase())) {
    return `${scope}-${base}`.replace(/[^a-zA-Z0-9_-]/g, '') || 'mcp-server'
  }
  return base || (scope ? scope.replace(/[^a-zA-Z0-9_-]/g, '') : 'mcp-server')
}

export function packageStdioTarget(surface: string, name: string): StdioTarget {
  if (surface === 'pypi') return { name: pkgShortName(name), command: 'uvx', args: [name] }
  return { name: pkgShortName(name), command: 'npx', args: ['-y', name] }
}

export function cursorStdio(t: StdioTarget): string {
  const b64 = btoa(JSON.stringify({ command: t.command, args: t.args }))
  return `https://cursor.com/install-mcp?name=${encodeURIComponent(t.name)}&config=${encodeURIComponent(b64)}`
}
export function vscodeStdio(t: StdioTarget): string {
  const obj = { name: t.name, command: t.command, args: t.args }
  return `vscode:mcp/install?${encodeURIComponent(JSON.stringify(obj))}`
}
export function claudeCodeStdio(t: StdioTarget): string {
  return `claude mcp add ${t.name} -- ${t.command} ${t.args.join(' ')}`
}
export function stdioServersConfig(t: StdioTarget): string {
  return JSON.stringify({ mcpServers: { [t.name]: { command: t.command, args: t.args } } }, null, 2)
}

// ── package + skill install one-liners ────────────────────────────────────────

export function packageInstallCommands(surface: string, name: string): Array<{ label: string; cmd: string }> {
  if (surface === 'npm') {
    return [
      { label: 'npm', cmd: `npm install ${name}` },
      { label: 'pnpm', cmd: `pnpm add ${name}` },
      { label: 'yarn', cmd: `yarn add ${name}` },
      { label: 'run (no install)', cmd: `npx -y ${name}` },
    ]
  }
  if (surface === 'crates') {
    return [
      { label: 'cargo', cmd: `cargo add ${name}` },
      { label: 'Cargo.toml', cmd: `${name} = "*"` },
    ]
  }
  if (surface === 'huggingface') {
    // A HF model is loaded, not package-installed — the graded coordinate goes
    // straight into from_pretrained / the hub CLI.
    return [
      { label: 'transformers', cmd: `AutoModel.from_pretrained("${name}")` },
      { label: 'hub CLI', cmd: `huggingface-cli download ${name}` },
      { label: 'git', cmd: `git clone https://huggingface.co/${name}` },
    ]
  }
  // pypi
  return [
    { label: 'pip', cmd: `pip install ${name}` },
    { label: 'pipx', cmd: `pipx install ${name}` },
    { label: 'uv', cmd: `uv pip install ${name}` },
    { label: 'run (no install)', cmd: `uvx ${name}` },
  ]
}

export function skillInstallCommands(owner: string, repo: string): Array<{ label: string; cmd: string }> {
  return [
    { label: 'Personal (all projects)', cmd: `git clone https://github.com/${owner}/${repo} ~/.claude/skills/${repo}` },
    { label: 'This project (committable)', cmd: `git clone https://github.com/${owner}/${repo} .claude/skills/${repo}` },
  ]
}
