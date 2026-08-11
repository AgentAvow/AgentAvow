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

/** Derive a short, safe server name from an endpoint URL (host's first label). */
export function mcpNameFromUrl(url: string): string {
  try {
    const h = new URL(url).hostname.replace(/^www\./, '')
    const label = h.split('.')[0] || 'mcp-server'
    return label.replace(/[^a-zA-Z0-9_-]/g, '') || 'mcp-server'
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
