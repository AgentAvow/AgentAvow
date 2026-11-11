/** Where AgentAvow is listed: the single source for the admin "Listings live" card.
 *
 * Edit this file when a listing goes live or a submission is filed; nothing else needs
 * to change. Keep it in step with docs/internal/listings-audit-*.md. VS Code is not a
 * listing of its own: it reads the official MCP registry. `url` is null where there is
 * no public page to link to. */

export type ListingStatus = 'live' | 'pending'

export interface Listing {
  name: string
  status: ListingStatus
  url: string | null
  /** YYYY-MM-DD the listing went live, or the submission was filed when pending. */
  since: string | null
  note?: string
}

export const LISTINGS: Listing[] = [
  { name: 'Claude plugin directory', status: 'live', url: null, since: null, note: 'plugin v0.1.34' },
  { name: 'Claude.ai connector directory', status: 'live', url: 'https://claude.ai/directory/connectors/agentavow', since: null },
  { name: 'ChatGPT app', status: 'live', url: 'https://chatgpt.com/plugins/plugin_asdk_app_6ac830ccc2d48191ac27974dec7d8344', since: '2026-10-23', note: 'agentavow v1.1.2' },
  { name: 'Codex', status: 'live', url: null, since: '2026-11-10', note: 'same public plugin catalog as ChatGPT' },
  { name: 'Cursor (cursor.directory)', status: 'live', url: 'https://cursor.directory', since: null },
  { name: 'Glama', status: 'live', url: 'https://glama.ai/mcp/servers/AgentAvow/AgentAvow', since: '2026-11-10', note: 'claimed 11-10' },
  { name: 'Official MCP registry', status: 'live', url: 'https://registry.modelcontextprotocol.io/v0/servers?search=com.agentavow/agentavow-trust', since: null, note: '0.6.5; VS Code reads from it' },
  { name: 'awesome-mcp-servers', status: 'live', url: 'https://github.com/punkpeye/awesome-mcp-servers', since: null },
  { name: 'TensorBlock awesome-mcp-servers (security)', status: 'live', url: 'https://github.com/TensorBlock/awesome-mcp-servers/blob/main/docs/security.md', since: null },
  { name: 'awesome-ai-catalogs', status: 'live', url: 'https://agent-card.github.io/awesome-ai-catalogs/', since: null },
  { name: 'GitLab CI/CD Catalog', status: 'live', url: 'https://gitlab.com/explore/catalog/agentavow/agentavow-scan', since: '2026-11-11' },
  { name: 'npm agentavow-trust', status: 'live', url: 'https://www.npmjs.com/package/agentavow-trust', since: null, note: '0.4.2' },
  { name: 'PyPI agentavow-trust', status: 'live', url: 'https://pypi.org/project/agentavow-trust/', since: null, note: '0.6.5' },

  { name: 'Docker MCP Catalog', status: 'pending', url: 'https://github.com/docker/mcp-registry/pull/6763', since: '2026-11-08', note: 'PR #6763' },
  { name: 'Gemini CLI extensions gallery', status: 'pending', url: 'https://geminicli.com/extensions', since: null, note: 'gallery feed frozen since Oct 16' },
  { name: 'awesome-agent-skills-security', status: 'pending', url: 'https://github.com/LLMSecurity/awesome-agent-skills-security/pull/117', since: '2026-11-08', note: 'PR #117' },
  { name: 'awesome-claude-code', status: 'pending', url: 'https://github.com/hesreallyhim/awesome-claude-code/issues/3598', since: '2026-11-11', note: 'filed by Kenne' },
  { name: 'OWASP GenAI landscape', status: 'pending', url: 'https://genai.owasp.org/solution-submission/', since: '2026-11-10' },
]

export const liveListings = () => LISTINGS.filter((l) => l.status === 'live')
export const pendingListings = () => LISTINGS.filter((l) => l.status === 'pending')
