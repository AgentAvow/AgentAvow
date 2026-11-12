/**
 * Every place AgentAvow installs, as data: the /get page lists them in full, and the
 * score page's "Check tools like this automatically" step offers them as one compact
 * chooser (approved score-page mock, 2026-11-10). Keep the two in step (pages/Get.tsx
 * keeps its own copy, which its tests read): a path added
 * to /get belongs here too.
 */
import { CHATGPT_LISTING, CLAUDE_LISTING } from './listings'
import { codexCmd, cursorInstall, vscodeInstall } from './installLinks'

export const AGENTAVOW_MCP = { name: 'agentavow', url: 'https://agentavow.com/mcp' }

export const GITLAB_SNIPPET = `include:
  - component: gitlab.com/agentavow/agentavow-scan/scan@0.1.0
    inputs:
      fail_on: do_not_connect`

export const PLUGIN_COMMANDS = '/plugin marketplace add AgentAvow/AgentAvow\n/plugin install agentavow-trust@agentavow'

export interface PathLink {
  label: string
  href: string
  /** 'primary' renders as a filled button; the default is a text link */
  style?: 'primary' | 'claude' | 'chatgpt'
}

export interface AgentAvowPath {
  key: string
  /** the chooser pill */
  label: string
  /** how the check runs there */
  tag: string
  text: string
  /** the line on a Do not connect result, where it differs */
  dncText?: string
  /** a copyable command or config */
  snippet?: string
  links: PathLink[]
}

export const AGENTAVOW_PATHS: AgentAvowPath[] = [
  {
    key: 'claude-code', label: 'Claude Code', tag: 'Checks by itself',
    text: 'The plugin checks new MCP servers and packages automatically, and warns you before your agent uses one.',
    dncText: "On a Do not connect answer, the plugin asks before you install it, and stops calls to a server that's already connected, unless you allow that server.",
    snippet: PLUGIN_COMMANDS,
    links: [{ label: 'Full steps →', href: '/rebrand/claude-code' }],
  },
  {
    key: 'claude', label: 'Claude', tag: 'Checks when you ask',
    text: 'Add the AgentAvow connector, then ask before you connect anything, right in the chat.',
    links: [{ label: 'Add to Claude ↗', href: CLAUDE_LISTING, style: 'claude' }],
  },
  {
    key: 'chatgpt', label: 'ChatGPT', tag: 'Checks when you ask',
    text: 'Add the AgentAvow app, then ask before you connect anything, right in the chat.',
    links: [{ label: 'Add to ChatGPT ↗', href: CHATGPT_LISTING, style: 'chatgpt' }],
  },
  {
    key: 'codex', label: 'Codex', tag: 'Checks when you ask',
    text: 'Add the connector to Codex.',
    snippet: codexCmd(AGENTAVOW_MCP),
    links: [{ label: 'Setup →', href: '/rebrand/docs/mcp-connector' }],
  },
  {
    key: 'cursor', label: 'Cursor', tag: 'Checks when you ask',
    text: 'One-click install of the connector.',
    links: [{ label: 'Add to Cursor ↗', href: cursorInstall(AGENTAVOW_MCP), style: 'primary' }],
  },
  {
    key: 'vscode', label: 'VS Code', tag: 'Checks when you ask',
    text: 'One-click install of the connector.',
    links: [{ label: 'Install in VS Code', href: vscodeInstall(AGENTAVOW_MCP), style: 'primary' }],
  },
  {
    key: 'gemini', label: 'Gemini CLI', tag: 'Checks when you ask',
    text: 'Install the extension.',
    snippet: 'gemini extensions install https://github.com/AgentAvow/agentavow-gemini',
    links: [{ label: 'Open ↗', href: 'https://github.com/AgentAvow/agentavow-gemini' }],
  },
  {
    key: 'mcp', label: 'Any MCP client', tag: 'Checks when you ask',
    text: 'Point any MCP client at the AgentAvow server, so your agent can run this check itself before it connects a tool.',
    snippet: AGENTAVOW_MCP.url,
    links: [{ label: 'Setup →', href: '/rebrand/docs/mcp-connector' }, { label: 'How it works →', href: '/rebrand/how-it-works#mcp-check' }],
  },
  {
    key: 'npm', label: 'npm gates', tag: 'Checks in your agent',
    text: 'Gates for the Vercel AI SDK, Flue, Claude Agent SDK and OpenAI Agents SDK check each tool before the call.',
    snippet: 'npm install agentavow-trust',
    links: [{ label: 'Gate docs →', href: '/rebrand/docs/gate-on-the-grade' }],
  },
  {
    key: 'pypi', label: 'PyPI', tag: 'Checks when you ask',
    text: 'The AgentAvow MCP server for Python setups. The LangChain and Google ADK gates are in the repo.',
    snippet: 'pip install agentavow-trust',
    links: [{ label: 'PyPI ↗', href: 'https://pypi.org/project/agentavow-trust/' }],
  },
  {
    key: 'github-action', label: 'GitHub Action', tag: 'Checks in your pipeline',
    text: 'Fail the build on Do not connect.',
    snippet: '- uses: AgentAvow/AgentAvow/github-action@main\n  with:\n    fail_on: do_not_connect',
    links: [{ label: 'Open ↗', href: 'https://github.com/AgentAvow/AgentAvow/tree/main/github-action' }],
  },
  {
    key: 'gitlab', label: 'GitLab CI/CD', tag: 'Checks in your pipeline',
    text: 'Gate merge requests on the answer, from the GitLab CI/CD Catalog. Runs in your own runner.',
    snippet: GITLAB_SNIPPET,
    links: [
      { label: 'Open in the Catalog ↗', href: 'https://gitlab.com/explore/catalog/agentavow/agentavow-scan' },
      { label: 'Setup →', href: '/rebrand/docs/run-locally#gitlab-ci' },
    ],
  },
  {
    key: 'api', label: 'API', tag: 'Checks from your code',
    text: 'The answer, both scores and the findings as JSON. No key needed for public tools.',
    snippet: 'curl https://agentavow.com/api/v1/public/scan/package/npm/zod',
    links: [{ label: 'API docs ↗', href: '/api/v1/redoc' }],
  },
]

/** Where the chooser remembers the visitor's pick (this device only). */
export const PATH_STORAGE_KEY = 'agentavow-install-path'

export function readPathPick(): string | null {
  try {
    const v = window.localStorage.getItem(PATH_STORAGE_KEY)
    return v && AGENTAVOW_PATHS.some((p) => p.key === v) ? v : null
  } catch {
    return null
  }
}

export function savePathPick(key: string): void {
  try { window.localStorage.setItem(PATH_STORAGE_KEY, key) } catch { /* private mode: not remembered */ }
}
