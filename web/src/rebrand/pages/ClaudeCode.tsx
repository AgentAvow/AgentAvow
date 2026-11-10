import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'

import SEOHead from '../../components/SEOHead'
import { getUtmParams, trackCta, trackPluginCommandCopy } from '../../lib/analytics'
import { startMetaPixel, trackMetaInstallCopy } from '../../lib/metaPixel'
import { rp } from '../basePath'

/**
 * /claude-code: the paid landing page for the Claude Code plugin. No nav and one goal,
 * copying the /plugin install. The H1 is the ad's headline, picked by utm_content from
 * the approved list (docs/internal/website-build-spec-2026-11-07.md); anything else
 * gets d1. The Meta Pixel loads here and nowhere else (lib/metaPixel.ts).
 */

const PLUGIN_LINES = [
  '/plugin marketplace add AgentAvow/AgentAvow',
  '/plugin install agentavow-trust@agentavow',
]

const HEADLINES: Record<string, string> = {
  'd1-automatic': 'Claude Code checks your MCP servers and packages before your agent uses them, automatically.',
  'd2-before-npx': 'Before you add that MCP server, get one clear answer.',
  'd3-do-not-connect': 'Here\'s what a Do not connect looks like, and why.',
  'd4-definition-changed': 'Know when an MCP server you approved changes its tools.',
}
const DEFAULT_HEADLINE = 'd1-automatic'

const SIGNED_DIGEST = 'sha256:811d1414506d36dccc1a273a29714fe29d1d2f7f2220dc16b61fec0f972d70da'
const SERVED_DIGEST = 'sha256:b2163bf3f4aa19a65db1fc25b9bcf0609d8116603226490a708f2d7860be174f'

function headlineFor(search: string): string {
  let tag: string | null | undefined = null
  try {
    tag = new URLSearchParams(search).get('utm_content') ?? getUtmParams().utm_content
  } catch {
    // Default below
  }
  return HEADLINES[tag ?? ''] ?? HEADLINES[DEFAULT_HEADLINE]
}

function copied(): void {
  trackCta('copy_plugin_cmd')
  trackMetaInstallCopy()
}

/** Someone selected the commands and copied them by hand. */
function selectionCopied(): void {
  trackPluginCommandCopy()
  try {
    if (/\/plugin\s/.test(String(window.getSelection()))) trackMetaInstallCopy()
  } catch {
    // Silently ignore
  }
}

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

function Install() {
  const [done, setDone] = useState<number | null>(null)
  const copy = async (i: number) => {
    if (!(await writeClipboard(PLUGIN_LINES[i]))) return
    copied()
    setDone(i)
    window.setTimeout(() => setDone((d) => (d === i ? null : d)), 1800)
  }
  return (
    <div onCopy={selectionCopied} className="mt-6 p-2 bg-[#0c1414] border border-border rounded-[14px] max-w-[720px]">
      {PLUGIN_LINES.map((line, i) => (
        <div key={line} className={`flex items-center gap-2.5 py-2 pr-2 pl-2.5 rounded-[9px] ${i ? 'border-t border-border/50' : ''}`}>
          <span className="font-mono text-[11.5px] text-text-muted w-3.5 flex-none">{i + 1}</span>
          <code className="flex-1 min-w-0 font-mono text-[14.5px] text-text [overflow-wrap:anywhere]">{line}</code>
          <button
            type="button"
            onClick={() => copy(i)}
            aria-label={`Copy line ${i + 1}`}
            className={`flex-none min-w-[76px] text-[13.5px] font-semibold px-[15px] py-2 rounded-[9px] ${done === i ? 'bg-surface-hover text-success' : 'text-white bg-gradient-to-r from-primary to-primary-dark'}`}
          >
            {done === i ? 'Copied' : 'Copy'}
          </button>
        </div>
      ))}
    </div>
  )
}

const ACTIONS: [string, string, string][] = [
  ['Safe to connect', 'text-success', 'Stays silent. A tool that cleared the full gate reads Safe to connect · Certified.'],
  ['Review before you connect', 'text-warning', 'One line with the reason. The install goes ahead.'],
  ['Do not connect', 'text-danger', 'Before an add or install, Claude Code asks you first. You decide.'],
  ['Tool definition changed', 'text-primary-light', 'Claude Code asks before the call.'],
]

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const section = 'relative z-[2] py-[60px] border-t border-border/60'

export default function RebrandClaudeCode() {
  const { pathname, search } = useLocation()
  const headline = headlineFor(search)

  useEffect(() => {
    startMetaPixel(pathname)
  }, [pathname])

  return (
    <div className="relative">
      <SEOHead
        title="Claude Code plugin: check MCP servers and packages automatically"
        description="Install the AgentAvow plugin and Claude Code checks your MCP servers and packages before your agent uses them: Safe to connect, Review before you connect, or Do not connect, with the reason."
        path="/claude-code"
      />

      <div className="relative pt-[22px] pb-[50px]">
        <div className="relative z-[2] max-w-[860px] mx-auto px-6">
          <div className="font-mono text-[12px] tracking-[.16em] uppercase text-primary-light font-semibold">AgentAvow for Claude Code</div>
          <h1 className="mt-3 text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">{headline}</h1>
          <p className="mt-[18px] max-w-[58ch] text-[18px] font-light text-text-muted">
            Install the plugin. In your next session, Claude tells you which ones read <b className="font-medium text-text">Safe to connect</b>, <b className="font-medium text-text">Review before you connect</b>, or <b className="font-medium text-text">Do not connect</b>, and why.
          </p>
          <Install />
          <p className="mt-3 text-[14px] text-text-muted">Run each line in Claude Code, then start a new session. Or open <code className="font-mono text-[13px] text-primary-light">/plugin</code> and find AgentAvow Trust under Discover.</p>
          <div className="flex flex-wrap gap-x-[18px] gap-y-1.5 mt-3.5 text-[13.5px] text-text-muted">
            {['Free, no account', 'The plugin is MIT licensed', 'Only the server URL or package name leaves your machine'].map((f) => (
              <span key={f}><span className="text-primary-light font-bold mr-1.5" aria-hidden="true">✓</span>{f}</span>
            ))}
          </div>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[860px] mx-auto px-6">
          <h2 className={h2}>Your first session opens with one line.</h2>
          <div className="mt-5 bg-[#0c1414] border border-border rounded-xl px-[18px] py-4 font-mono text-[13.5px] leading-relaxed overflow-x-auto">
            <span className="text-primary-light">AgentAvow pre-check:</span> graded 8 MCP servers. 5 Safe, 2 Review, <span className="text-danger">1 Do not connect</span>.<br />
            <span className="text-text-muted">Needs attention:</span> <span className="text-danger">&apos;example-server&apos; Do not connect</span>, one critical finding.<br />
            <span className="text-text-muted">Dependencies:</span> graded 12 of 38. 11 Safe, <span className="text-warning">1 Review</span>.
          </div>

          <h2 className={`${h2} mt-11`}>It stays quiet until it matters.</h2>
          <div className="mt-[22px] glass rounded-[14px] border border-white/10 overflow-hidden">
            {ACTIONS.map(([label, color, text], i) => (
              <div key={label} className={`grid sm:grid-cols-[minmax(0,270px)_1fr] gap-1 sm:gap-4 px-[18px] py-3.5 text-[15px] items-baseline ${i ? 'border-t border-border/60' : ''}`}>
                <b className={`font-bold ${color}`}>{label}</b>
                <span className="text-text-muted">{text}</span>
              </div>
            ))}
          </div>
          <p className="mt-2.5 text-[14.5px] text-text-muted max-w-[60ch]">Each result carries a signed 0-100 trust score and an adoption score, with a link to the full report.</p>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[860px] mx-auto px-6">
          <h2 className={h2}>A server you approved can change later.</h2>
          <p className="mt-2.5 text-text-muted max-w-[60ch]">In a rug-pull, a tool passes review, then its definition changes to do something else. The plugin compares what a remote server serves now with the signed definition from the check. If they differ, Claude Code asks you first.</p>
          <div className="mt-5 glass rounded-2xl border border-white/10 font-mono text-[12.5px] leading-[1.7] px-4 py-3.5 overflow-x-auto whitespace-nowrap">
            <span className="text-primary-light">signed</span> {SIGNED_DIGEST}<br />
            <span className="text-danger">served</span> {SERVED_DIGEST}
          </div>
          <p className="mt-2 text-[12.5px] text-text-muted">From our <a href="https://github.com/AgentAvow/AgentAvow/tree/main/demos/rugpull" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:underline">rug-pull demo ↗</a>, run on localhost with test data.</p>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[860px] mx-auto px-6">
          <h2 className={h2}>Why developers can trust the answer.</h2>
          <div className="grid gap-[7px] mt-3.5 text-[14.5px] text-text-muted max-w-[68ch]">
            <p><b className="text-text font-semibold">Hundreds of Claude Code machines connect each day.</b></p>
            <p>Each result is signed with Ed25519, and you can verify it offline against our public keys.</p>
            <p>Our tool definition digest is in the TRACE spec as <code className="font-mono text-[13px]">trace.mcp-tool-definition.v1</code>.</p>
            <p>An outside party reproduced our conformance vectors byte for byte in a Linux Foundation Decentralized Trust lab.</p>
            <p>Our founder co-authors the action-ref Internet-Draft, an individual submission to the IETF.</p>
          </div>
          <div className="grid sm:grid-cols-2 gap-3.5 mt-[22px]">
            <div className="glass rounded-2xl border border-white/10 p-5">
              <h3 className="text-[16px] font-bold">What it checks</h3>
              <ul className="mt-2 pl-[17px] list-disc text-text-muted text-[14.5px] grid gap-1">
                <li>MCP servers, at session start and on <code className="font-mono text-[13px]">claude mcp add</code></li>
                <li>Packages Claude installs by name with npm, pnpm, yarn, bun, pip, uv, pipx or poetry</li>
                <li>Your project&apos;s direct dependencies, up to 8 per session start</li>
              </ul>
            </div>
            <div className="glass rounded-2xl border border-white/10 p-5">
              <h3 className="text-[16px] font-bold">What it doesn&apos;t do</h3>
              <ul className="mt-2 pl-[17px] list-disc text-text-muted text-[14.5px] grid gap-1">
                <li>Lockfile installs, requirements files and URL installs are left alone</li>
                <li>If AgentAvow can&apos;t be reached, your work carries on with no check</li>
                <li>A check can miss things. It warns, and you decide</li>
              </ul>
            </div>
          </div>
          <div className="mt-[34px]">
            <h2 className={h2}>Add it now.</h2>
            <Install />
            <p className="mt-3 text-[14px] text-text-muted">Needs Claude Code and <code className="font-mono text-[13px] text-primary-light">python3</code>. Remove it any time from <code className="font-mono text-[13px] text-primary-light">/plugin</code>.</p>
          </div>
        </div>
      </div>

      <div className="relative z-[2] pt-[26px] pb-[30px] border-t border-border/60">
        <div className="max-w-[860px] mx-auto px-6">
          <p className="text-[12.5px] text-text-muted max-w-[70ch] leading-normal">
            <b>What this page measures:</b> page views and clicks on the copy buttons, with the campaign tag from your link and a random ID stored in your browser. This page also loads the Meta Pixel, so we can see how many people our Meta ads bring here and how many copy the install command. It tells Meta about the page view and the first copy, and Meta may set a cookie. No other page on agentavow.com loads it, and it stays off if your browser sends Global Privacy Control or Do Not Track. Details and how to opt out are in our privacy policy.
          </p>
          {/* Full page loads on purpose: this page's ad pixel must not ride along into the app. */}
          <div className="flex gap-4 mt-2.5 text-[13px]">
            <a href={rp('/rebrand/legal/privacy')} className="text-text-muted hover:text-text">Privacy</a>
            <a href={rp('/rebrand/legal/terms')} className="text-text-muted hover:text-text">Terms</a>
          </div>
        </div>
      </div>
    </div>
  )
}
