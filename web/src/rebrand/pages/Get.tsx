import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import SEOHead from '../../components/SEOHead'
import { currentPath, trackEvent } from '../../lib/analytics'
import { rp } from '../basePath'
import { AppsButtons } from '../components/AppsStrip'
import { trackListing } from '../lib/listings'
import { codexCmd, cursorInstall, vscodeInstall, vscodeWebInstall } from '../lib/installLinks'

/**
 * /get: every place AgentAvow is listed, in one left-aligned 860px column (approved
 * mock "/get v2", 2026-11-10). Claude Code leads (Kenne's pick, the same order as
 * Home), then the Claude and ChatGPT apps as one row, then the other clients, the
 * packages and gates, the pipelines and the API. Only listings that exist go here.
 * Left off: Docker (not listed yet), PulseMCP (unconfirmed) and the GitHub Marketplace
 * (old name, until the Action is re-released as AgentAvow).
 */

const MCP = { name: 'agentavow', url: 'https://agentavow.com/mcp' }

type Action =
  | { kind: 'link'; label: string; href: string }
  | { kind: 'apps' }
  | { kind: 'vscode' }

interface Item {
  name: string
  /** Small caps label beside the name: how the check runs there. */
  tag?: string
  text: ReactNode
  /** A config snippet shown under the line. */
  snippet?: string
  actions: Action[]
  tone?: 'rec' | 'apps'
}

const code = (s: string) => <code className="font-mono text-[12.5px] text-primary-light [overflow-wrap:anywhere]">{s}</code>

const GITLAB_SNIPPET = `include:
  - component: gitlab.com/agentavow/agentavow-scan/scan@0.1.0
    inputs:
      fail_on: do_not_connect`

const GROUPS: { title: string; sub: string; items: Item[] }[] = [
  {
    title: 'Where you work',
    sub: 'Install once, or add the connector and ask before you connect something.',
    items: [
      { name: 'Claude Code and Cowork plugin', tag: 'Start here · checks by itself', tone: 'rec', text: 'In the Claude plugin directory. Checks new MCP servers and packages automatically, and warns you before your agent uses one.', actions: [{ kind: 'link', label: 'Install →', href: '/rebrand/claude-code' }] },
      { name: 'Claude and ChatGPT', tag: 'Checks when you ask', tone: 'apps', text: 'The connector in Claude and the app in ChatGPT. Ask before you connect anything, right in the chat.', actions: [{ kind: 'apps' }] },
      { name: 'Codex', tag: 'Checks when you ask', text: code(codexCmd(MCP)), actions: [{ kind: 'link', label: 'Setup →', href: '/rebrand/docs/mcp-connector' }] },
      { name: 'Cursor', tag: 'Checks when you ask', text: 'One-click install of the connector. Also listed on cursor.directory.', actions: [{ kind: 'link', label: 'Add to Cursor ↗', href: cursorInstall(MCP) }] },
      { name: 'VS Code', tag: 'Checks when you ask', text: 'One-click install of the connector.', actions: [{ kind: 'vscode' }] },
      { name: 'Gemini CLI', tag: 'Checks when you ask', text: <>Extension: {code('gemini extensions install https://github.com/AgentAvow/agentavow-gemini')}</>, actions: [{ kind: 'link', label: 'Open ↗', href: 'https://github.com/AgentAvow/agentavow-gemini' }] },
      { name: 'Any MCP client', text: code(MCP.url), actions: [{ kind: 'link', label: 'Setup →', href: '/rebrand/docs/mcp-connector' }] },
    ],
  },
  {
    title: 'In your agent',
    sub: 'Check each tool before the call, from your own code.',
    items: [
      { name: 'npm gates', text: <>{code('npm install agentavow-trust')}. Gates for the Vercel AI SDK, Flue, Claude Agent SDK and OpenAI Agents SDK check each tool before the call.</>, actions: [{ kind: 'link', label: 'Gate docs →', href: '/rebrand/docs/gate-on-the-grade' }, { kind: 'link', label: 'npm ↗', href: 'https://www.npmjs.com/package/agentavow-trust' }] },
      { name: 'PyPI', text: <>{code('pip install agentavow-trust')}. The AgentAvow MCP server for Python setups. The LangChain and Google ADK gates are in the repo.</>, actions: [{ kind: 'link', label: 'PyPI ↗', href: 'https://pypi.org/project/agentavow-trust/' }] },
    ],
  },
  {
    title: 'In your pipeline',
    sub: 'Fail the build on Do not connect, or ask the API from any script.',
    items: [
      { name: 'GitHub Action', text: code('AgentAvow/AgentAvow/github-action@main'), actions: [{ kind: 'link', label: 'Open ↗', href: 'https://github.com/AgentAvow/AgentAvow/tree/main/github-action' }] },
      { name: 'GitLab CI/CD Catalog', text: 'Gate merge requests on the answer. Runs in your own GitLab runner; nothing leaves your network.', snippet: GITLAB_SNIPPET, actions: [{ kind: 'link', label: 'Open in the Catalog ↗', href: 'https://gitlab.com/explore/catalog/agentavow/agentavow-scan' }, { kind: 'link', label: 'Setup →', href: '/rebrand/docs/run-locally#gitlab-ci' }] },
      { name: 'Bitbucket and Azure DevOps', text: 'Run the scanner in your own pipeline.', actions: [{ kind: 'link', label: 'Setup →', href: '/rebrand/docs/run-locally' }] },
      { name: 'API', text: <>The answer, both scores and the findings as JSON. No key needed for public tools. {code('curl https://agentavow.com/api/v1/public/scan/package/npm/zod')}</>, actions: [{ kind: 'link', label: 'API docs ↗', href: '/api/v1/redoc' }] },
    ],
  },
  {
    title: 'Directories',
    sub: 'Find us in a directory you already use.',
    items: [
      { name: 'Glama', text: 'MCP server directory.', actions: [{ kind: 'link', label: 'Open ↗', href: 'https://glama.ai/mcp/servers/AgentAvow/AgentAvow' }] },
      { name: 'awesome-mcp-servers', text: 'Community list on GitHub.', actions: [{ kind: 'link', label: 'Open ↗', href: 'https://github.com/punkpeye/awesome-mcp-servers' }] },
    ],
  },
]

function track(item: Item, href: string): void {
  if (href.startsWith('https://claude.ai/') || href.startsWith('https://chatgpt.com/')) trackListing(href)
  else trackEvent('guest_cta_click', currentPath(), `get:${item.name}`)
}

const LINK = 'text-[14px] font-semibold whitespace-nowrap text-primary-light hover:underline'

function ActionLink({ item, label, href }: { item: Item; label: string; href: string }) {
  // /claude-code has its own CSP, so it loads as a full page; other site pages route
  // in place; a custom-scheme deeplink opens the app; everything else, a new tab.
  if (href === '/rebrand/claude-code') return <a href={rp(href)} onClick={() => track(item, href)} className={LINK}>{label}</a>
  if (href.startsWith('/rebrand/')) return <Link to={rp(href)} onClick={() => track(item, href)} className={LINK}>{label}</Link>
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" onClick={() => track(item, href)} className={LINK}>
      {label}
    </a>
  )
}

/** "Install in VS Code": the vscode: deeplink, plus the vscode.dev https fallback. */
function VsCodeButtons({ item }: { item: Item }) {
  return (
    <span className="inline-flex items-center gap-3 flex-wrap">
      <a href={vscodeInstall(MCP)} onClick={() => track(item, 'vscode')}
        className="inline-flex items-center font-bold text-[13.5px] px-3.5 py-2 rounded-[10px] text-white bg-gradient-to-r from-primary to-primary-dark whitespace-nowrap">
        Install in VS Code
      </a>
      <a href={vscodeWebInstall(MCP)} target="_blank" rel="noopener noreferrer" onClick={() => track(item, 'vscode-web')}
        className="text-[12.5px] text-text-muted hover:text-primary-light whitespace-nowrap">
        or via vscode.dev ↗
      </a>
    </span>
  )
}

function Row({ item, first }: { item: Item; first: boolean }) {
  const tone = item.tone === 'rec' ? 'bg-primary/10'
    : item.tone === 'apps' ? 'bg-[linear-gradient(100deg,rgba(45,212,191,.10),rgba(232,121,249,.08)_70%)]' : ''
  return (
    <div className={`grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_auto] gap-x-4 gap-y-1 px-[18px] py-3.5 items-center ${first ? '' : 'border-t border-border/60'} ${tone}`}>
      <b className="font-semibold text-[15.5px] min-w-0">
        {item.name}
        {item.tag && <span className="ml-[7px] font-mono text-[10.5px] tracking-[.08em] uppercase text-primary-light font-normal">{item.tag}</span>}
      </b>
      <div className="sm:col-start-2 sm:row-start-1 sm:row-span-3 flex flex-wrap items-center gap-x-4 gap-y-2 sm:justify-end order-last sm:order-none mt-1.5 sm:mt-0">
        {item.actions.map((a, i) => a.kind === 'apps' ? <AppsButtons key={i} />
          : a.kind === 'vscode' ? <VsCodeButtons key={i} item={item} />
            : <ActionLink key={i} item={item} label={a.label} href={a.href} />)}
      </div>
      <p className="sm:col-start-1 text-text-muted text-[14px] min-w-0">{item.text}</p>
      {item.snippet && (
        <pre className="sm:col-start-1 mt-1.5 font-mono text-[12px] bg-surface border border-border rounded-xl px-3.5 py-2.5 text-text overflow-x-auto min-w-0">{item.snippet}</pre>
      )}
    </div>
  )
}

export default function RebrandGet() {
  return (
    <div>
      <SEOHead
        title="Install for Claude Code, Claude, ChatGPT, Codex, Cursor, VS Code and CI"
        description="Install AgentAvow: Claude Code, Claude, ChatGPT, Codex, Cursor, VS Code, Gemini CLI, npm, PyPI, and CI on GitHub, GitLab, Bitbucket and Azure DevOps."
        path="/get"
      />
      <div className="relative pt-14 pb-[30px]">
        <div className="relative z-[2] max-w-[860px] mx-auto px-6">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Get AgentAvow</span>
          <h1 className="mt-3 text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">Get AgentAvow where you work.</h1>
          <p className="mt-[18px] max-w-[58ch] text-[18px] font-light text-text-muted">
            The same check everywhere: <b className="font-medium text-text">Safe to connect</b>, <b className="font-medium text-text">Review before you connect</b>, or <b className="font-medium text-text">Do not connect</b>, with a signed 0-100 trust score, an adoption score, and the Certified mark where a tool has earned it. Free, no account.
          </p>
        </div>
      </div>

      <div className="relative z-[2] pt-[34px] pb-[60px] border-t border-border/60">
        <div className="max-w-[860px] mx-auto px-6 flex flex-col gap-[34px]">
          {GROUPS.map((g) => (
            <section key={g.title}>
              <h2 className="text-[21px] font-bold tracking-tight">{g.title}</h2>
              <p className="mt-1 text-[14.5px] text-text-muted">{g.sub}</p>
              <div className="mt-3 glass rounded-[14px] border border-border/60 overflow-hidden">
                {g.items.map((item, i) => <Row key={item.name} item={item} first={i === 0} />)}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  )
}
