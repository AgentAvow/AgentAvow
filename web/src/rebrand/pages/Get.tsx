import SEOHead from '../../components/SEOHead'
import { currentPath, trackEvent } from '../../lib/analytics'
import { rp } from '../basePath'
import { AppsStrip } from '../components/AppsStrip'
import { CHATGPT_LISTING, CLAUDE_LISTING, trackListing } from '../lib/listings'
import { cursorInstall } from '../lib/installLinks'

/**
 * /get: every place AgentAvow is listed, grouped by what it does for you. Only listings
 * that exist go here (link check 2026-11-07). Not listed yet, add when live: Codex,
 * Docker. Left off: PulseMCP (unconfirmed) and the GitHub Marketplace (old name, until
 * the Action is re-released as AgentAvow).
 */

const MCP_URL = 'https://agentavow.com/mcp'

interface Item {
  name: string
  text: React.ReactNode
  href: string
  label: string
  recommended?: boolean
  /** A same-site page that must load as a full page (it has its own CSP). */
  fullLoad?: boolean
}

const code = (s: string) => <code className="font-mono text-[12.5px] text-primary-light [overflow-wrap:anywhere]">{s}</code>

const GROUPS: { title: string; sub: string; items: Item[] }[] = [
  {
    title: 'Checks by itself',
    sub: 'Install once. It runs while you work.',
    items: [
      { name: 'Claude Code and Cowork plugin', recommended: true, text: 'In the Claude plugin directory. Checks servers and packages automatically.', href: rp('/rebrand/claude-code'), label: 'Install →', fullLoad: true },
    ],
  },
  {
    title: 'Checks when you ask',
    sub: 'Add the connector, then ask before you connect something.',
    items: [
      { name: 'Claude', text: 'Connector in the Claude directory.', href: CLAUDE_LISTING, label: 'Open listing ↗' },
      { name: 'ChatGPT', text: 'App in the ChatGPT directory.', href: CHATGPT_LISTING, label: 'Open listing ↗' },
      { name: 'Cursor', text: 'One-click install of the connector. Also listed on cursor.directory.', href: cursorInstall({ name: 'agentavow', url: MCP_URL }), label: 'Add to Cursor ↗' },
      { name: 'VS Code', text: 'Through the official MCP Registry.', href: 'https://registry.modelcontextprotocol.io/v0/servers?search=agentavow', label: 'Open listing ↗' },
      { name: 'Gemini CLI', text: <>Extension: {code('gemini extensions install https://github.com/AgentAvow/agentavow-gemini')}</>, href: 'https://github.com/AgentAvow/agentavow-gemini', label: 'Open ↗' },
      { name: 'Any MCP client', text: code(MCP_URL), href: 'https://agentavow.com/docs/mcp-connector', label: 'Setup →' },
    ],
  },
  {
    title: 'Checks in your pipeline',
    sub: 'Fail the build on Do not connect.',
    items: [
      { name: 'GitHub Action', text: code('AgentAvow/AgentAvow/github-action@main'), href: 'https://github.com/AgentAvow/AgentAvow/tree/main/github-action', label: 'Open ↗' },
      { name: 'GitLab, Bitbucket and Azure DevOps', text: 'Run the scanner in your own pipeline.', href: 'https://agentavow.com/docs/run-locally', label: 'Setup →' },
      { name: 'Agent runtime gates', text: 'npm gates for the Vercel AI SDK, Flue, Claude Agent SDK and OpenAI Agents SDK; LangChain and Google ADK in the repo.', href: 'https://agentavow.com/docs/gate-on-the-grade', label: 'Setup →' },
    ],
  },
  {
    title: 'Packages and directories',
    sub: 'Install the server yourself, or find us in a directory you already use.',
    items: [
      { name: 'npm', text: code('agentavow-trust'), href: 'https://www.npmjs.com/package/agentavow-trust', label: 'Open ↗' },
      { name: 'PyPI', text: code('agentavow-trust'), href: 'https://pypi.org/project/agentavow-trust/', label: 'Open ↗' },
      { name: 'Glama', text: 'MCP server directory.', href: 'https://glama.ai/mcp/servers/AgentAvow/AgentAvow', label: 'Open ↗' },
      { name: 'awesome-mcp-servers', text: 'Community list on GitHub.', href: 'https://github.com/punkpeye/awesome-mcp-servers', label: 'Open ↗' },
    ],
  },
]

function onItemClick(item: Item): void {
  if (item.href.startsWith('https://claude.ai/') || item.href.startsWith('https://chatgpt.com/')) {
    trackListing(item.href)
  } else {
    trackEvent('guest_cta_click', currentPath(), `get:${item.name}`)
  }
}

export default function RebrandGet() {
  return (
    <div>
      <SEOHead
        title="Install for Claude Code, Claude, ChatGPT, Cursor, VS Code, Gemini CLI and CI"
        description="Every way to install AgentAvow: the Claude Code plugin, the Claude connector, the ChatGPT app, Cursor, VS Code, Gemini CLI, npm and PyPI, and CI on GitHub, GitLab, Bitbucket and Azure DevOps."
        path="/get"
      />
      <div className="relative pt-14 pb-[34px]">
        <div className="relative z-[2] max-w-[1080px] mx-auto px-6">
          <h1 className="text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">Get AgentAvow where you work.</h1>
          <p className="mt-[18px] max-w-[58ch] text-[18px] font-light text-text-muted">
            The same check everywhere: <b className="font-medium text-text">Safe to connect</b>, <b className="font-medium text-text">Review before you connect</b>, or <b className="font-medium text-text">Do not connect</b>, with a signed 0-100 trust score, an adoption score, and the Certified mark where a tool has earned it. Free, no account.
          </p>
          <AppsStrip align="start" className="mt-5" />
        </div>
      </div>

      <div className="relative z-[2] py-[60px] border-t border-border/60">
        <div className="max-w-[860px] mx-auto px-6 flex flex-col gap-[34px]">
          {GROUPS.map((g) => (
            <section key={g.title}>
              <h2 className="text-[21px] font-bold tracking-tight">{g.title}</h2>
              <p className="mt-1 text-[14.5px] text-text-muted">{g.sub}</p>
              <div className="mt-3 glass rounded-[14px] border border-white/10 overflow-hidden">
                {g.items.map((item, i) => {
                  const external = !item.fullLoad
                  return (
                    <div key={item.name} className={`grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-x-4 gap-y-1 px-[18px] py-3.5 items-center ${i ? 'border-t border-border/60' : ''} ${item.recommended ? 'bg-primary/10' : ''}`}>
                      <b className="font-semibold text-[15.5px]">
                        {item.name}
                        {item.recommended && <span className="ml-2 font-mono text-[10.5px] tracking-[.08em] uppercase text-primary-light">Start here</span>}
                      </b>
                      <a
                        href={item.href}
                        {...(external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
                        onClick={() => onItemClick(item)}
                        className="sm:col-start-2 sm:row-start-1 sm:row-span-2 text-[14px] font-semibold whitespace-nowrap text-primary-light hover:underline order-last sm:order-none mt-1 sm:mt-0"
                      >
                        {item.label}
                      </a>
                      <p className="sm:col-start-1 text-text-muted text-[14px]">{item.text}</p>
                    </div>
                  )
                })}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  )
}
