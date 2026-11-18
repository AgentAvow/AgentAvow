import { useState } from 'react'
import { useLocation } from 'react-router-dom'

import SEOHead from '../../components/SEOHead'
import { trackCta } from '../../lib/analytics'
import { rp } from '../basePath'
import { ShareSetupLink, type SetupTarget } from '../components/AdLanding'
import { BTN_GHOST_CLASS, DIVIDER_CLASS, Eyebrow } from '../components/PageBits'
import { AGENTAVOW_MCP } from '../lib/agentavowPaths'
import { CODEX_PLUGIN_COMMANDS, codexCmd } from '../lib/installLinks'

/**
 * /codex: the landing page for the AgentAvow plugin in the Codex CLI. Mirrors
 * /claude-code section for section (mockup: codex awareness kit 2026-11-18, section 4,
 * approved by Kenne), with the Codex wording: a Codex hook can't ask, so on Do not
 * connect the plugin stops a `codex mcp add` or package install and says why. It makes
 * no claim about calls to a server that's already connected. No rug-pull block, no
 * Meta Pixel, no machine count.
 *
 * Phones (below md, by CSS only): the plugin installs on a computer, so the first screen
 * offers to share or copy this page's link and "Check a server". "Email me the setup"
 * stays on /claude-code: that email carries the Claude Code commands.
 *
 * Links are full page loads, like /claude-code's.
 */

const H1 = 'Check every MCP server before Codex connects to it.'

const SHARE_TARGET: SetupTarget = {
  page: '/codex',
  title: 'AgentAvow for Codex',
  text: 'Set up AgentAvow in Codex on my computer',
  alone: true,
}

const DNC_REPORT = '/rebrand/check/pkg/npm/gadgethumans-mcp?version=1.0.15'
const SAFE_REPORT = '/rebrand/check/pkg/npm/gadgethumans-mcp?version=1.2.4'
const DNC_COMMAND = 'codex mcp add gadget -- npx -y gadgethumans-mcp@1.0.15'

async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** Select the commands so the person can copy them by hand (in-app browsers often refuse clipboard writes). */
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

/** Someone selected the Codex commands and copied them by hand. */
function selectionCopied(): void {
  try {
    if (/codex\s+plugin\s+(?:marketplace\s+add|add)\s/.test(String(window.getSelection()))) trackCta('copy_plugin_cmd')
  } catch {
    // Silently ignore
  }
}

/** Both commands in one block, with one "Copy both lines" button. */
function Install({ id }: { id: string }) {
  const [done, setDone] = useState(false)
  const [manual, setManual] = useState(false)
  const copy = async () => {
    if (!(await writeClipboard(CODEX_PLUGIN_COMMANDS.join('\n')))) {
      selectNode(document.getElementById(id))
      setManual(true)
      return
    }
    setManual(false)
    trackCta('copy_plugin_cmd')
    setDone(true)
    window.setTimeout(() => setDone(false), 1800)
  }
  return (
    <div onCopy={selectionCopied} className="p-2 bg-background border border-border rounded-[14px]">
      <div id={id} className="px-2.5 py-2 grid gap-1.5">
        {CODEX_PLUGIN_COMMANDS.map((line) => (
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

/**
 * Real results for one package, two versions, read from the live API
 * (GET /public/scan/package/npm/gadgethumans-mcp, with and without ?version=1.0.15)
 * on 2026-11-18 UTC. Each name links to its report, which always shows today's result.
 * Re-check before changing a row.
 */
function VersionExample() {
  const link = 'font-mono text-[13.5px] text-text [overflow-wrap:anywhere] underline decoration-border underline-offset-2 hover:text-primary-light'
  return (
    <div className="glass rounded-2xl border border-border/60 overflow-hidden text-left">
      <div className="px-4 py-2.5 border-b border-border/60 text-[12.5px] font-semibold text-text-muted">Real results and trust scores, November 2026</div>
      <ul className="divide-y divide-border/60">
        <li className="grid grid-cols-[22px_1fr] gap-x-2.5 px-4 py-2.5 bg-danger/[0.07]">
          <span className="mt-[1px] w-[22px] h-[22px] rounded-full inline-grid place-items-center text-[12px] font-extrabold text-danger bg-danger/15" aria-hidden="true">✕</span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
              <a href={rp(DNC_REPORT)} className={link}>gadgethumans-mcp 1.0.15</a>
              <span className="text-[14.5px] font-bold text-danger">Do not connect</span>
              <span className="text-[12.5px] text-text-muted">· 45</span>
            </div>
            <p className="mt-0.5 text-[13.5px] text-text-muted">Sends your wallet private key over the network (index.js:215).</p>
            <p className="mt-1.5 rounded-lg bg-danger/[0.10] px-2.5 py-1.5 text-[13px] text-text">In Codex, the plugin stops a <code className="font-mono text-[12.5px]">codex mcp add</code> of this version and tells you why.</p>
          </div>
        </li>
        <li className="grid grid-cols-[22px_1fr] gap-x-2.5 px-4 py-2.5">
          <span className="mt-[1px] w-[22px] h-[22px] rounded-full inline-grid place-items-center text-[12px] font-extrabold text-success bg-success/15" aria-hidden="true">✓</span>
          <div className="min-w-0 flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <a href={rp(SAFE_REPORT)} className={link}>gadgethumans-mcp 1.2.4</a>
            <span className="text-[14.5px] font-bold text-success">Safe to connect</span>
            <span className="text-[12.5px] text-text-muted">· 82 · a newer release</span>
          </div>
        </li>
      </ul>
    </div>
  )
}

/** Real output from Codex sessions on 2026-11-17 (session start, then a dependency line from another session). */
function SessionOutput() {
  return (
    <div>
      <div className="bg-background border border-border rounded-xl px-4 py-3.5 font-mono text-[12.5px] leading-relaxed grid gap-2.5 [overflow-wrap:anywhere]">
        <p><span className="text-primary-light">AgentAvow pre-check:</span> checked 1 MCP server — <span className="text-success">1 Safe</span>, 0 Review. Ask for the AgentAvow pre-check for details.</p>
        <p className="pt-2.5 border-t border-border/60">✅ MCP &apos;deepwiki&apos; (https://mcp.deepwiki.com/mcp): <span className="text-success">Safe to connect</span> — tool definitions clean; server code not inspected · AgentAvow 74/100.</p>
        <p>✅ dependency &apos;python-multipart&apos; (pypi:python-multipart@&gt;=0.0.7): <span className="text-success">Safe to connect · Certified</span> — nothing found in 8 files · AgentAvow 90/100</p>
      </div>
      <p className="mt-2 text-[12.5px] text-text-muted">Real output from Codex sessions, November 2026</p>
    </div>
  )
}

/** The plugin's real reply in Codex to DNC_COMMAND (plugin 0.1.45, live API, 2026-11-18). */
function StopOutput() {
  return (
    <div>
      <div className="bg-background border border-border rounded-xl px-4 py-3.5 font-mono text-[12.5px] leading-relaxed grid gap-2.5 [overflow-wrap:anywhere]">
        <p className="text-text-muted">$ {DNC_COMMAND}</p>
        <p className="pt-2.5 border-t border-border/60">AgentAvow checked this before it is added:</p>
        <p>⛔ MCP &apos;gadget&apos; (npm:gadgethumans-mcp@1.0.15): <span className="text-danger">Do not connect</span> — one critical finding in its code: wallet private key sent over the network · AgentAvow 45/100; sandbox: did not run (the sandbox has not observed this release), static analysis only. Report: https://agentavow.com/check/pkg/npm/gadgethumans-mcp?version=1.0.15</p>
        <p>AgentAvow says: Do not connect, so it stopped this step (Codex cannot ask you first). If you reviewed the report and still want to add this server, run the same command yourself in your own terminal outside Codex, or switch AgentAvow&apos;s hooks off in Codex (/hooks) for this session. Do not retry it another way from here.</p>
      </div>
      <p className="mt-2 text-[12.5px] text-text-muted">Real output of the plugin&apos;s Codex hook for this command, November 2026</p>
    </div>
  )
}

const LEGEND: [string, string, string, string][] = [
  ['Safe to connect', 'text-success', 'border-success/40', 'Nothing to act on. The step goes ahead.'],
  ['Review before you connect', 'text-warning', 'border-warning/40', 'One line with the reason. The step goes ahead.'],
  ['Do not connect', 'text-danger', 'border-danger/40', 'Stops the step and says why, with the report link. To go ahead anyway, run it yourself outside Codex.'],
]

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const section = `relative z-[2] py-[60px] max-sm:py-11 ${DIVIDER_CLASS}`
const code = 'font-mono text-[13px]'
const textLink = 'text-primary-light hover:underline'

export default function RebrandCodex() {
  const { search } = useLocation()

  return (
    <div className="relative">
      <SEOHead
        title="Codex plugin: check MCP servers and packages before Codex adds them"
        description="Free Codex CLI plugin: checks MCP servers and packages before Codex adds them. Safe to connect, Review before you connect, or Do not connect, with the reason."
        path="/codex"
      />

      {/* HERO */}
      <div className="relative pt-4 md:pt-12 pb-9 md:pb-12">
        <div className="relative z-[2] max-w-[1080px] mx-auto px-6">
          <div className="max-w-[720px]">
            <Eyebrow className="hidden md:block">AgentAvow for Codex</Eyebrow>
            <h1 className="md:mt-3 text-[clamp(27px,4.4vw,44px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">{H1}</h1>

            {/* Real results: one package, two versions. */}
            <div className="mt-3.5 md:mt-6"><VersionExample /></div>

            {/* Phone: the plugin needs a computer, so send this page there. */}
            <div className="md:hidden mt-3">
              <p className="text-[14.5px] text-text-muted mb-2">It installs on a computer. Send yourself this page:</p>
              <ShareSetupLink search={search} target={SHARE_TARGET} />
            </div>

            {/* Computer: paste the two lines. */}
            <div className="hidden md:block mt-5">
              <Install id="codex-lines-hero" />
              <p className="mt-2.5 text-[14px] text-text-muted"><b className="font-semibold text-text">Free · No account</b> · Paste into your terminal, start Codex, then choose Trust all and continue.</p>
            </div>
          </div>

          {/* Phone: something to do right now, then the commands for later. */}
          <div className="md:hidden mt-7 grid gap-2.5">
            <p className="text-[14.5px] text-text-muted">Or, from your phone:</p>
            <a href={rp('/rebrand/check')} className={BTN_GHOST_CLASS}>Check a server</a>
            <p className="mt-4 text-[14.5px] text-text-muted">On a computer? Paste these into your terminal, then start Codex. Free · No account.</p>
            <Install id="codex-lines-phone" />
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
          <p className="mt-2.5 text-text-muted max-w-[60ch]">When a session starts, and when Codex adds a server or installs a package, the plugin checks it with AgentAvow. Codex opens its first reply with one line, like this:</p>
          <div className="mt-4 max-w-[720px]"><SessionOutput /></div>
          <p className="mt-4 text-[14.5px] text-text-muted max-w-[64ch]">Codex asks you to trust the plugin&apos;s hooks the first time, and again after each plugin update. The checks run only while the hooks are trusted; choose Trust all and continue, or trust them later with <code className={code}>/hooks</code>.</p>
          <div className="grid sm:grid-cols-2 gap-3.5 mt-[22px]">
            <div className="glass rounded-2xl border border-border/60 p-5">
              <h3 className="text-[16px] font-bold">What it checks</h3>
              <ul className="mt-2 pl-[17px] list-disc text-text-muted text-[14.5px] grid gap-1">
                <li>MCP servers in <code className={code}>~/.codex/config.toml</code> and a trusted project&apos;s <code className={code}>.codex/config.toml</code>, at session start</li>
                <li><code className={code}>codex mcp add &lt;name&gt; --url …</code> and <code className={code}>codex mcp add &lt;name&gt; -- &lt;command&gt;</code></li>
                <li>Packages installed by name with npm, pnpm, yarn, bun, pip, uv, pipx or poetry, at the exact version you typed</li>
                <li>Your project&apos;s direct dependencies, a few at each session start. Those are already installed, so their answer is advice, never a stop</li>
              </ul>
            </div>
            <div className="glass rounded-2xl border border-border/60 p-5">
              <h3 className="text-[16px] font-bold">What it doesn&apos;t do</h3>
              <ul className="mt-2 pl-[17px] list-disc text-text-muted text-[14.5px] grid gap-1">
                <li>The IDE extension doesn&apos;t run plugins. Add the connector there instead: <code className={`${code} [overflow-wrap:anywhere]`}>{codexCmd(AGENTAVOW_MCP)}</code></li>
                <li>Hooks run only while you trust them, and Codex asks again after each update</li>
                <li><code className={code}>codex exec</code> skips hooks you haven&apos;t trusted, without a warning</li>
                <li>Lockfile installs, requirements files and URL installs are left alone</li>
                <li>If AgentAvow can&apos;t be reached, your work carries on with no check</li>
                <li>A check can miss things. It stops a step only on Do not connect</li>
              </ul>
            </div>
          </div>
          <div className="flex flex-wrap gap-x-[18px] gap-y-1.5 mt-4 text-[13.5px] text-text-muted">
            {['Free, no account', 'The plugin is MIT licensed', 'Sends only the tool being checked and a random install ID (once a day, with the plugin version and app type)'].map((f) => (
              <span key={f}><span className="text-primary-light font-bold mr-1.5" aria-hidden="true">✓</span>{f}</span>
            ))}
          </div>

          <h3 className="mt-10 text-[21px] font-bold tracking-tight">One package, two versions.</h3>
          <p className="mt-2 text-text-muted max-w-[62ch]">gadgethumans-mcp 1.2.4 reads Safe to connect, 82/100. Version 1.0.15 is still on npm and reads Do not connect, 45/100: line 215 of its <code className={code}>index.js</code> sends the <code className={code}>WALLET_PRIVATE_KEY</code> environment variable to the vendor&apos;s API. A README or a teammate&apos;s config that pins @1.0.15 runs that code, so the plugin checks the version you typed, not the latest one. When Codex tries to add 1.0.15, the step stops:</p>
          <div className="mt-4 max-w-[720px]"><StopOutput /></div>
          <p className="mt-3 text-[14px] text-text-muted max-w-[64ch]">The same command with @1.2.4 goes ahead. Reports: <a href={rp(DNC_REPORT)} className={textLink}>1.0.15</a> · <a href={rp(SAFE_REPORT)} className={textLink}>1.2.4</a>. Knostic wrote up this package&apos;s wallet-key behavior first, in September 2026.</p>

          <h3 className="mt-10 text-[21px] font-bold tracking-tight">No hooks? Use the connector.</h3>
          <p className="mt-2 text-text-muted max-w-[62ch]">The connector and the scan-before-connect skill check a tool when you ask, in the CLI, the IDE extension and the ChatGPT desktop app. Add the connector with one line:</p>
          <div className="mt-3 max-w-[720px] p-2 bg-background border border-border rounded-[14px]">
            <code className="block px-2.5 py-2 font-mono text-[14.5px] text-text [overflow-wrap:anywhere]">{codexCmd(AGENTAVOW_MCP)}</code>
          </div>
          <p className="mt-2.5 text-[14px] text-text-muted">The skill and the <code className={code}>config.toml</code> setup are in the <a href={rp('/rebrand/docs/codex')} className={textLink}>Codex setup guide →</a></p>

          <h3 className="mt-10 text-[21px] font-bold tracking-tight">Why developers can trust the answer</h3>
          <div className="grid gap-[7px] mt-3 text-[14.5px] text-text-muted max-w-[68ch]">
            <p>Each result is signed with Ed25519, and you can verify it offline against our public keys.</p>
            <p>Our tool definition digest is in the TRACE spec as <code className={code}>trace.mcp-tool-definition.v1</code>.</p>
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
            <Install id="codex-lines-end" />
          </div>
          <div className="md:hidden mt-4 max-w-[480px]">
            <ShareSetupLink search={search} target={SHARE_TARGET} />
          </div>
          <p className="mt-3 text-[14px] text-text-muted">Needs the Codex CLI and <code className={`${code} text-primary-light`}>python3</code>. Remove it any time with <code className={`${code} text-primary-light [overflow-wrap:anywhere]`}>codex plugin remove agentavow-trust@agentavow</code>. Full setup: <a href={rp('/rebrand/docs/codex')} className={textLink}>/docs/codex</a>.</p>
        </div>
      </div>

      <div className={`relative z-[2] pt-[26px] pb-[30px] ${DIVIDER_CLASS}`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <p className="text-[12.5px] text-text-muted max-w-[70ch] leading-normal">
            <b>What this page measures:</b> page views and clicks on the copy and share buttons, with the campaign tag from your link and a random ID stored in your browser. No ad pixel loads here. Details are in our privacy policy.
          </p>
          <div className="flex gap-4 mt-2.5 text-[13px]">
            <a href={rp('/rebrand/legal/privacy')} className="text-text-muted hover:text-text">Privacy</a>
            <a href={rp('/rebrand/legal/terms')} className="text-text-muted hover:text-text">Terms</a>
          </div>
        </div>
      </div>
    </div>
  )
}
