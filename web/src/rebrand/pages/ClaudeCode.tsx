import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'

import SEOHead from '../../components/SEOHead'
import { trackCta, trackPluginCommandCopy } from '../../lib/analytics'
import { startMetaPixel, trackMetaInstallCopy } from '../../lib/metaPixel'
import { rp } from '../basePath'
import { ChatGptLink, EmailSetup, WalletAdExamples } from '../components/AdLanding'
import { PLUGIN_LINES } from '../lib/adLanding'
import { BTN_GHOST_CLASS, DIVIDER_CLASS, Eyebrow } from '../components/PageBits'

/**
 * /claude-code: the landing page for the Claude Code plugin (Google search ads, and
 * any link to the plugin). Concept v3, 2026-11-17: one H1, the real-results card the
 * X ad's homepage uses (compact), then the two commands with one copy button, then the
 * three answers in one row. Session output and detail sit lower, under "How it works".
 *
 * Phones (below the md breakpoint, by CSS only): the plugin installs on a computer, so
 * the first screen offers "Email me the setup" and a copy/share link under the card,
 * then "Check a server" and "Add to ChatGPT". The full site nav stays (Kenne, 11-11).
 * The Meta Pixel loads here and nowhere else (lib/metaPixel.ts).
 */

const H1 = 'Check every MCP server before Claude Code connects to it.'

const SIGNED_DIGEST = 'sha256:811d1414506d36dccc1a273a29714fe29d1d2f7f2220dc16b61fec0f972d70da'
const SERVED_DIGEST = 'sha256:b2163bf3f4aa19a65db1fc25b9bcf0609d8116603226490a708f2d7860be174f'

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

/** Select the commands so the person can copy them by hand (in-app browsers, like
 * Reddit's, often refuse clipboard writes). A manual copy is tracked by onCopy. */
function selectNode(el: HTMLElement | null): void {
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

/** Both commands in one block, with one "Copy both lines" button. */
function Install({ id }: { id: string }) {
  const [done, setDone] = useState(false)
  const [manual, setManual] = useState(false)
  const copy = async () => {
    if (!(await writeClipboard(PLUGIN_LINES.join('\n')))) {
      selectNode(document.getElementById(id))
      setManual(true)
      return
    }
    setManual(false)
    copied()
    setDone(true)
    window.setTimeout(() => setDone(false), 1800)
  }
  return (
    <div onCopy={selectionCopied} className="p-2 bg-background border border-border rounded-[14px]">
      <div id={id} className="px-2.5 py-2 grid gap-1.5">
        {PLUGIN_LINES.map((line) => (
          <code key={line} className="block font-mono text-[14.5px] text-text [overflow-wrap:anywhere]">{line}</code>
        ))}
      </div>
      <button
        type="button"
        onClick={copy}
        className={`mt-1 w-full text-[14.5px] font-semibold px-4 py-[10px] rounded-[10px] ${done ? 'bg-surface-hover text-success' : 'text-white bg-gradient-to-r from-primary to-primary-dark'}`}
      >
        {done ? 'Copied both lines' : 'Copy both lines'}
      </button>
      {manual && (
        <p role="status" className="px-2.5 pt-1.5 pb-1 text-[12.5px] text-text-muted">
          This browser blocked the copy button. The lines are selected: press and hold (or Cmd/Ctrl+C) to copy them.
        </p>
      )}
    </div>
  )
}

/** Real output from a Claude Code session, November 2026. */
function SessionOutput() {
  return (
    <div>
      <div className="bg-background border border-border rounded-xl px-4 py-3.5 font-mono text-[12.5px] leading-relaxed grid gap-2.5 [overflow-wrap:anywhere]">
        <p><span className="text-primary-light">AgentAvow pre-check:</span> MCP servers unchanged. <span className="text-text-muted">Dependencies:</span> checked 8 of 27 — <span className="text-success">8 Safe</span>, 0 Review. Since the last session AgentAvow checked 4 package installs — all <span className="text-success">Safe to connect</span>.</p>
        <p className="pt-2.5 border-t border-border/60">✅ MCP &apos;context7&apos;: <span className="text-success">Safe to connect</span> — no critical or high findings in 30 files · AgentAvow 83/100</p>
        <p>✅ dependency &apos;uvicorn&apos; (pypi:uvicorn@&gt;=0.24.0,&lt;1.0): <span className="text-success">Safe to connect · Certified</span> — nothing found in 39 files · AgentAvow 90/100</p>
      </div>
      <p className="mt-2 text-[12.5px] text-text-muted">Real output from a Claude Code session, November 2026</p>
    </div>
  )
}

const LEGEND: [string, string, string, string][] = [
  ['Safe to connect', 'text-success', 'border-success/40', 'Nothing to act on. Claude Code says nothing.'],
  ['Review before you connect', 'text-warning', 'border-warning/40', 'One line with the reason. The install goes ahead.'],
  ['Do not connect', 'text-danger', 'border-danger/40', 'Asks before you install it, and stops calls to a server that\'s already connected.'],
]

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const section = `relative z-[2] py-[60px] max-sm:py-11 ${DIVIDER_CLASS}`

export default function RebrandClaudeCode() {
  const { pathname, search } = useLocation()

  useEffect(() => {
    startMetaPixel(pathname)
  }, [pathname])

  return (
    <div className="relative">
      <SEOHead
        title="Claude Code plugin: check every MCP server before it connects"
        description="Free plugin: Claude Code checks every MCP server and package before use. Safe to connect, Review before you connect, or Do not connect, with the reason."
        path="/claude-code"
      />

      {/* HERO */}
      <div className="relative pt-4 md:pt-12 pb-9 md:pb-12">
        <div className="relative z-[2] max-w-[1080px] mx-auto px-6">
          <div className="max-w-[720px]">
            <Eyebrow className="hidden md:block">AgentAvow for Claude Code</Eyebrow>
            <h1 className="md:mt-3 text-[clamp(27px,4.4vw,44px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">{H1}</h1>

            {/* Real results, the same card as the X ad's homepage. */}
            <div className="mt-3.5 md:mt-6"><WalletAdExamples compact /></div>

            {/* Phone: the plugin needs a computer, so send the setup there. */}
            <div className="md:hidden mt-3">
              <p className="text-[14.5px] text-text-muted mb-2">It installs on a computer. Email yourself the setup:</p>
              <EmailSetup search={search} />
            </div>

            {/* Computer: paste the two lines. */}
            <div className="hidden md:block mt-5">
              <Install id="plugin-lines-hero" />
              <p className="mt-2.5 text-[14px] text-text-muted"><b className="font-semibold text-text">Free · No account</b> · Paste into Claude Code, then start a new session.</p>
              <p className="mt-2 text-[14px] text-text-muted">Using Codex? <a href={rp('/rebrand/codex')} className="text-primary-light hover:underline">Set it up here →</a></p>
            </div>
          </div>

          {/* Phone: things to do right now, then the commands for later. */}
          <div className="md:hidden mt-7 grid gap-2.5">
            <p className="text-[14.5px] text-text-muted">Or, from your phone:</p>
            {/* Full page load on purpose, like the footer links: the ad pixel stays on this page. */}
            <a href={rp('/rebrand/check')} className={BTN_GHOST_CLASS}>Check a server</a>
            <ChatGptLink />
            <p className="mt-4 text-[14.5px] text-text-muted">On a computer? Paste these into Claude Code. Free · No account.</p>
            <Install id="plugin-lines-phone" />
            <p className="mt-2 text-[14px] text-text-muted">Using Codex? <a href={rp('/rebrand/codex')} className="text-primary-light hover:underline">Set it up here →</a></p>
          </div>
        </div>
      </div>

      {/* THE THREE ANSWERS, one row */}
      <div className={`${section} !py-9`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <div className="grid sm:grid-cols-3 gap-3">
            {LEGEND.map(([label, color, border, text]) => (
              <div key={label} className={`glass rounded-[14px] border ${border} px-4 py-3.5`}>
                <b className={`block text-[15.5px] font-bold ${color}`}>{label}</b>
                <span className="mt-1 block text-[14px] text-text-muted">{text}</span>
              </div>
            ))}
          </div>
          <p className="mt-3 text-[13.5px] text-text-muted">Each answer has its reason, a signed 0-100 trust score and an adoption score, with a link to the full report.</p>
        </div>
      </div>

      {/* HOW IT WORKS */}
      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2} id="how-it-works">How it works</h2>
          <p className="mt-2.5 text-text-muted max-w-[60ch]">When a session starts, and when Claude Code adds a server or installs a package, the plugin checks it with AgentAvow. Your first session opens with one line, like this:</p>
          <div className="mt-4 max-w-[720px]"><SessionOutput /></div>
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
          <div className="flex flex-wrap gap-x-[18px] gap-y-1.5 mt-4 text-[13.5px] text-text-muted">
            {['Free, no account', 'The plugin is MIT licensed', 'Sends only the tool being checked and a random install ID (once a day, with the plugin version and app type)'].map((f) => (
              <span key={f}><span className="text-primary-light font-bold mr-1.5" aria-hidden="true">✓</span>{f}</span>
            ))}
          </div>
          {/* Full page load on purpose, like the footer links: the ad pixel stays on this page. */}
          <p className="mt-2 text-[13px] text-text-muted">0 tokens per check · under 1,000 tokens a session. <a href={`${rp('/rebrand/faq')}#context-tokens`} className="text-primary-light hover:underline">How we measured →</a></p>

          <h3 className="mt-10 text-[21px] font-bold tracking-tight">A server you approved can change later.</h3>
          <p className="mt-2 text-text-muted max-w-[60ch]">In a rug-pull, a tool passes review, then its definition changes to do something else. The plugin compares what a remote server serves now with the signed definition from the check. If they differ, Claude Code asks you before the call.</p>
          <div className="mt-4 glass rounded-2xl border border-border/60 font-mono text-[12.5px] leading-[1.7] px-4 py-3.5 overflow-x-auto whitespace-nowrap">
            <span className="text-primary-light">signed</span> {SIGNED_DIGEST}<br />
            <span className="text-danger">served</span> {SERVED_DIGEST}
          </div>
          <p className="mt-2 text-[12.5px] text-text-muted">From our <a href="https://github.com/AgentAvow/AgentAvow/tree/main/demos/rugpull" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:underline">rug-pull demo ↗</a>, run on localhost with test data.</p>

          <h3 className="mt-10 text-[21px] font-bold tracking-tight">Why developers can trust the answer</h3>
          <div className="grid gap-[7px] mt-3 text-[14.5px] text-text-muted max-w-[68ch]">
            <p><b className="text-text font-semibold">Claude Code machines connect to it every day.</b></p>
            <p>Each result is signed with Ed25519, and you can verify it offline against our public keys.</p>
            <p>Our tool definition digest is in the TRACE spec as <code className="font-mono text-[13px]">trace.mcp-tool-definition.v1</code>.</p>
            <p>An outside party reproduced our conformance vectors byte for byte in a Linux Foundation Decentralized Trust lab.</p>
            <p>Our founder co-authors the action-ref Internet-Draft, an individual submission to the IETF.</p>
          </div>
        </div>
      </div>

      {/* ADD IT */}
      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2}>Add it now.</h2>
          <div className="hidden md:block mt-5 max-w-[720px]">
            <Install id="plugin-lines-end" />
          </div>
          <div className="md:hidden mt-4 max-w-[480px]">
            <EmailSetup search={search} />
          </div>
          <p className="mt-3 text-[14px] text-text-muted">Needs Claude Code and <code className="font-mono text-[13px] text-primary-light">python3</code>. Remove it any time from <code className="font-mono text-[13px] text-primary-light">/plugin</code>.</p>
        </div>
      </div>

      <div className={`relative z-[2] pt-[26px] pb-[30px] ${DIVIDER_CLASS}`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <p className="text-[12.5px] text-text-muted max-w-[70ch] leading-normal">
            <b>What this page measures:</b> page views and clicks on the copy, email and share buttons, with the campaign tag from your link and a random ID stored in your browser. If you ask us to email you the setup, we send one email and don&apos;t keep your address. This page also loads the Meta Pixel, so we can see how many people our Meta ads bring here and how many copy the install command. It tells Meta about the page view and the first copy, and Meta may set a cookie. No other page on agentavow.com loads it, and it stays off if your browser sends Global Privacy Control or Do Not Track. Details and how to opt out are in our privacy policy.
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
