import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { currentPath, trackEvent } from '../../lib/analytics'
import { cursorInstall, vscodeInstall } from '../lib/installLinks'
import { AppsButtons } from './AppsStrip'

/**
 * "Where it works": six tiles, Claude Code first and the only one that checks by
 * itself; the rest say plainly that you ask (or that it runs in your pipeline). Same
 * six, same order, as the strip on /get (mockup 2026-11-10).
 */

const MCP_URL = 'https://agentavow.com/mcp'

const BTN_SM = 'inline-flex items-center font-semibold text-[13.5px] px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow whitespace-nowrap'
const BTN_SM_GHOST = 'inline-flex items-center font-semibold text-[13.5px] px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors whitespace-nowrap'
const LINK = 'text-[14px] font-semibold text-primary-light hover:text-primary'

const track = (what: string) => () => trackEvent('guest_cta_click', currentPath(), `works:${what}`)

function Tile({ n, tag, title, children, act, lead = false }: {
  n: number; tag: string; title: string; children: ReactNode; act: ReactNode; lead?: boolean
}) {
  return (
    <div className={`glass rounded-2xl border px-[18px] py-4 min-w-0 ${lead
      ? 'md:col-span-2 lg:col-span-3 grid gap-x-5 gap-y-1.5 items-center sm:grid-cols-[minmax(0,1fr)_auto] border-primary-light/45'
      : 'flex flex-col gap-1.5 border-border/60'}`}
      style={lead ? { background: 'linear-gradient(100deg,rgba(13,148,136,.12),transparent 70%), var(--color-surface-glass)' } : undefined}>
      <span className="font-mono text-[11px] tracking-[.08em] uppercase text-primary-light">{tag}</span>
      <h3 className="text-[16.5px] font-bold flex items-baseline gap-2 flex-wrap sm:col-start-1">
        <span className="font-mono text-[11px] font-semibold text-primary-light">{n}</span>{title}
      </h3>
      <p className={`text-text-muted text-[14px] ${lead ? 'sm:col-start-1' : 'flex-1'}`}>{children}</p>
      <div className={lead
        ? 'flex flex-col gap-2 items-start mt-1.5 sm:mt-0 sm:col-start-2 sm:row-start-1 sm:row-span-3'
        : 'flex gap-2 flex-wrap mt-1.5'}>{act}</div>
    </div>
  )
}

export function WhereItWorks() {
  return (
    <>
      <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3 mt-[22px]">
        <Tile n={1} lead tag="Checks by itself" title="Claude Code" act={<>
          {/* /claude-code has its own CSP, so it loads as a full page */}
          <a href={rp('/rebrand/claude-code')} onClick={track('claude-code')} className={BTN_SM}>Add it to Claude Code</a>
          <a href={rp('/rebrand/claude-code')} className={LINK}>What you'll see →</a>
        </>}>
          Your servers at session start, and new servers and packages before they install. Safe to connect stays quiet; Review gets one line with the reason. On Do not connect, Claude Code asks before you install it, and stops calls to a server that's already connected, unless you allow that server. The checks run on your machine, so they cost Claude nothing.
        </Tile>
        <Tile n={2} tag="Checks when you ask" title="Claude and ChatGPT" act={<AppsButtons />}>
          Add AgentAvow and ask before you connect anything. Nothing runs by itself in chat.
        </Tile>
        <Tile n={3} tag="Checks when you ask" title="Cursor" act={
          <a href={cursorInstall({ name: 'agentavow', url: MCP_URL })} target="_blank" rel="noopener noreferrer" onClick={track('cursor')} className={BTN_SM_GHOST}>Add to Cursor ↗</a>
        }>
          One-click install of the connector; your agent checks when you ask.
        </Tile>
        <Tile n={4} tag="Checks when you ask" title="VS Code" act={
          <a href={vscodeInstall({ name: 'agentavow', url: MCP_URL })} onClick={track('vscode')} className={BTN_SM}>Install in VS Code</a>
        }>
          One-click install of the connector.
        </Tile>
        <Tile n={5} tag="Checks when you ask" title="Gemini CLI" act={
          <a href="https://github.com/AgentAvow/agentavow-gemini" target="_blank" rel="noopener noreferrer" onClick={track('gemini')} className={BTN_SM_GHOST}>Open ↗</a>
        }>
          Install the extension: <code className="font-mono text-[12px] text-primary-light [overflow-wrap:anywhere]">gemini extensions install https://github.com/AgentAvow/agentavow-gemini</code>
        </Tile>
        <Tile n={6} tag="Checks in your pipeline" title="CI" act={
          <Link to={rp('/rebrand/get')} className={BTN_SM_GHOST}>Set up CI →</Link>
        }>
          Fail the build on Do not connect. GitHub, GitLab, Bitbucket and Azure DevOps.
        </Tile>
      </div>
      <p className="mt-4 text-[14.5px] text-text-muted">Codex, npm and PyPI, the API and every directory listing: <Link to={rp('/rebrand/get')} className={LINK}>All the ways to get AgentAvow →</Link></p>
    </>
  )
}
