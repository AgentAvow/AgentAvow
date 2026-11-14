import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'

import SEOHead from '../../components/SEOHead'
import { getUtmParams, trackCta, trackPluginCommandCopy } from '../../lib/analytics'
import { startMetaPixel, trackMetaInstallCopy } from '../../lib/metaPixel'
import { rp } from '../basePath'
import { DIVIDER_CLASS } from '../components/PageBits'

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
  // The X campaign's ads (2026-11-test-x) tell the same stories as d1-d3.
  'x1-archived': 'Before you add that MCP server, get one clear answer.',
  'x2-automatic': 'Claude Code checks your MCP servers and packages before your agent uses them, automatically.',
  'x3-do-not-connect': 'Here\'s what a Do not connect looks like, and why.',
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

/** Select a line's text so the person can copy it by hand (in-app browsers, like
 * Reddit's, often refuse clipboard writes). A manual copy is tracked by onCopy. */
function selectLine(el: HTMLElement | null): void {
  try {
    if (!el) return
    const range = document.createRange()
    range.selectNodeContents(el)
    const sel = window.getSelection()
    sel?.removeAllRanges()
    sel?.addRange(range)
  } catch {
    // Nothing to do: the text is still visible
  }
}

function Install() {
  const [done, setDone] = useState<number | null>(null)
  const [manual, setManual] = useState<number | null>(null)
  const copy = async (i: number, code: HTMLElement | null) => {
    if (!(await writeClipboard(PLUGIN_LINES[i]))) {
      selectLine(code)
      setManual(i)
      return
    }
    setManual(null)
    copied()
    setDone(i)
    window.setTimeout(() => setDone((d) => (d === i ? null : d)), 1800)
  }
  return (
    <div onCopy={selectionCopied} className="mt-6 p-2 bg-background border border-border rounded-[14px] max-w-[720px]">
      {PLUGIN_LINES.map((line, i) => (
        <div key={line} className={`flex items-center gap-2.5 py-2 pr-2 pl-2.5 rounded-[9px] ${i ? 'border-t border-border/50' : ''}`}>
          <span className="font-mono text-[11.5px] text-text-muted w-3.5 flex-none">{i + 1}</span>
          <code id={`plugin-line-${i}`} className="flex-1 min-w-0 font-mono text-[14.5px] text-text [overflow-wrap:anywhere] select-all">{line}</code>
          <button
            type="button"
            onClick={() => copy(i, document.getElementById(`plugin-line-${i}`))}
            aria-label={`Copy line ${i + 1}`}
            className={`flex-none min-w-[76px] text-[13.5px] font-semibold px-[15px] py-2 rounded-[9px] ${done === i ? 'bg-surface-hover text-success' : 'text-white bg-gradient-to-r from-primary to-primary-dark'}`}
          >
            {done === i ? 'Copied' : 'Copy'}
          </button>
        </div>
      ))}
      {manual !== null && (
        <p role="status" className="px-2.5 pb-1.5 text-[12.5px] text-text-muted">
          This browser blocked the copy button. The line is selected: press and hold (or Cmd/Ctrl+C) to copy it.
        </p>
      )}
    </div>
  )
}

const ACTIONS: [string, string, string][] = [
  ['Safe to connect', 'text-success', 'Stays silent. A tool that cleared the full gate reads Safe to connect · Certified.'],
  ['Review before you connect', 'text-warning', 'One line with the reason. The install goes ahead.'],
  ['Do not connect', 'text-danger', 'Before an add or install, Claude Code asks you first. Calls to a server that is already connected are stopped, with the report link, unless you allowed that server.'],
  ['Tool definition changed', 'text-primary-light', 'Claude Code asks before the call.'],
]

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const section = `relative z-[2] py-[60px] ${DIVIDER_CLASS}`

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
        description="The AgentAvow plugin has Claude Code check MCP servers and packages before use: Safe to connect, Review before you connect, or Do not connect, with the reason."
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
          {/* Full page load on purpose, like the footer links: the ad pixel stays on this page. */}
          <p className="mt-2 text-[13px] text-text-muted">0 tokens per check · under 1,000 tokens a session. <a href={`${rp('/rebrand/faq')}#context-tokens`} className="text-primary-light hover:underline">How we measured →</a></p>
          <p className="mt-3 text-[14px] text-text-muted">Run each line in Claude Code, then start a new session. Or open <code className="font-mono text-[13px] text-primary-light">/plugin</code> and find AgentAvow Trust under Discover (the directory can lag behind the latest version).</p>
          <div className="flex flex-wrap gap-x-[18px] gap-y-1.5 mt-3.5 text-[13.5px] text-text-muted">
            {['Free, no account', 'The plugin is MIT licensed', 'Sends only the tool being checked and a random install ID (once a day, with the plugin version and app type)'].map((f) => (
              <span key={f}><span className="text-primary-light font-bold mr-1.5" aria-hidden="true">✓</span>{f}</span>
            ))}
          </div>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[860px] mx-auto px-6">
          <h2 className={h2}>Your first session opens with one line.</h2>
          <div className="mt-5 bg-background border border-border rounded-xl px-[18px] py-4 font-mono text-[13.5px] leading-relaxed overflow-x-auto">
            <span className="text-primary-light">AgentAvow pre-check:</span> MCP servers unchanged. <span className="text-text-muted">Dependencies:</span> checked 8 of 27 — <span className="text-success">8 Safe</span>, 0 Review. Ask for the AgentAvow pre-check for details. Since the last session AgentAvow checked 4 package installs — all <span className="text-success">Safe to connect</span>.
          </div>
          <p className="mt-4 text-[14.5px] text-text-muted max-w-[60ch]">Ask for the details and each server and dependency gets its own line:</p>
          <div className="mt-2.5 bg-background border border-border rounded-xl px-[18px] py-4 font-mono text-[13.5px] leading-relaxed overflow-x-auto grid gap-2">
            <p>✅ dependency &apos;uvicorn&apos; (pypi:uvicorn@&gt;=0.24.0,&lt;1.0): <span className="text-success">Safe to connect · Certified</span> — nothing found in 39 files · AgentAvow 90/100; sandbox: installed, no network beyond the registry.</p>
            <p>✅ MCP &apos;context7&apos;: <span className="text-success">Safe to connect</span> — no critical or high findings in 30 files · AgentAvow 83/100</p>
          </div>
          <p className="mt-2 text-[12.5px] text-text-muted">Real output from a Claude Code session, November 2026</p>

          <h2 className={`${h2} mt-11`}>It stays quiet until it matters.</h2>
          <div className="mt-[22px] glass rounded-[14px] border border-border/60 overflow-hidden">
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
          <div className="mt-5 glass rounded-2xl border border-border/60 font-mono text-[12.5px] leading-[1.7] px-4 py-3.5 overflow-x-auto whitespace-nowrap">
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
            <p><b className="text-text font-semibold">Claude Code machines connect to it every day.</b></p>
            <p>Each result is signed with Ed25519, and you can verify it offline against our public keys.</p>
            <p>Our tool definition digest is in the TRACE spec as <code className="font-mono text-[13px]">trace.mcp-tool-definition.v1</code>.</p>
            <p>An outside party reproduced our conformance vectors byte for byte in a Linux Foundation Decentralized Trust lab.</p>
            <p>Our founder co-authors the action-ref Internet-Draft, an individual submission to the IETF.</p>
          </div>
          <div className="grid sm:grid-cols-2 gap-3.5 mt-[22px]">
            <div className="glass rounded-2xl border border-border/60 p-5">
              <h3 className="text-[16px] font-bold">What it checks</h3>
              <ul className="mt-2 pl-[17px] list-disc text-text-muted text-[14.5px] grid gap-1">
                <li>MCP servers, at session start and on <code className="font-mono text-[13px]">claude mcp add</code></li>
                <li>Packages Claude installs by name with npm, pnpm, yarn, bun, pip, uv, pipx or poetry</li>
                <li>Your project&apos;s direct dependencies, up to 8 per session start</li>
              </ul>
            </div>
            <div className="glass rounded-2xl border border-border/60 p-5">
              <h3 className="text-[16px] font-bold">What it doesn&apos;t do</h3>
              <ul className="mt-2 pl-[17px] list-disc text-text-muted text-[14.5px] grid gap-1">
                <li>Lockfile installs, requirements files and URL installs are left alone</li>
                <li>If AgentAvow can&apos;t be reached, your work carries on with no check</li>
                <li>A check can miss things. It asks before installs and stops calls only on Do not connect</li>
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

      <div className={`relative z-[2] pt-[26px] pb-[30px] ${DIVIDER_CLASS}`}>
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
