import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import { claudeCodeStdio, cursorStdio, stdioServersConfig, vscodeStdio } from '../lib/installLinks'
import { parseBadgeTarget, type BadgeStyle } from '../lib/badgeTarget'
import ListToolForm from '../components/ListToolForm'
import SEOHead from '../../components/SEOHead'
import api from '../../lib/api'
import { isCertified as certifiedMark } from '../../components/trust/gradeSystem'
import { trackBadgeCopied, trackCta, trackPageAction, trackPluginCommandCopy } from '../../lib/analytics'
import { DIVIDER_CLASS } from '../components/PageBits'

/**
 * /for-developers: the one entry point for a tool author (approved mock "Developers",
 * 2026-11-10). The top is three cards for the three jobs they come to do: claim the
 * tool, put its badge on the README, check a private repo first. The badge maker that
 * used to be /badge lives here now (#badge); /badge redirects to it. The "add a tool to
 * the catalog" form that used to be /submit follows it (#list). Under that: why a
 * score is worth having, gating in CI and at runtime, the registry snippet, and our own
 * MCP server.
 */

declare global {
  interface Window { AgentAvow?: { render: (root?: Element | Document) => void } }
}

// Our own MCP server as a stdio target — the "is this safe to install?" check.
const AA_MCP = { name: 'agentavow-trust', command: 'uvx', args: ['agentavow-trust'] }
const MCP_CONFIG = stdioServersConfig(AA_MCP)

// The signed-score block a maintainer pastes into their MCP server.json so the
// score travels into the registry record itself. The live, signed block for a
// specific repo comes from /api/v1/public/registry-snippet/{owner}/{repo}.
const REGISTRY_SNIPPET = `"_meta": {
  "io.modelcontextprotocol.registry/publisher-provided": {
    "com.agentavow/trust": {
      "trustScore": 92,
      "certified": false,
      "subject": "github:you/your-repo",
      "issuer": "did:web:agentgraph.co",
      "attestation": "<signed JWS — recompute & verify offline>",
      "jwks": "https://agentgraph.co/.well-known/jwks.json"
    }
  }
}`

const BADGE_STYLES: [BadgeStyle, string, string][] = [
  ['compact', 'Compact', 'One line, both meters: the answer, trust score and adoption.'],
  ['card', 'Card', 'The same card the website embed shows, as an image.'],
  ['classic', 'Classic', 'The previous shields-style badge.'],
]

const EXAMPLE = parseBadgeTarget('AgentAvow/AgentAvow')!

const DEV_RESOURCES: [string, string, string][] = [
  ['Declare your scope', 'Ship an .agentavow.yml with your declared egress and capabilities, shown on your score.', 'https://github.com/AgentAvow/AgentAvow/blob/main/.agentavow.yml'],
  ['API sandbox', 'Try the scan API live: no signup, an ephemeral token, read-only.', '/rebrand/sandbox'],
  ['Docs', 'Guides: reading a score, badges, verifying attestations.', '/rebrand/docs'],
  ['API reference', 'The REST API: every endpoint, offline-verifiable verdicts.', '/api/v1/redoc'],
  ['Verify keys (JWKS)', 'Public signing keys to verify any attestation offline.', 'https://agentgraph.co/.well-known/jwks.json'],
  ['GitHub', 'Source, specs, conformance fixtures, and issues.', 'https://github.com/AgentAvow/AgentAvow'],
]

const GATES: [string, string, string][] = [
  ['GitLab CI/CD Catalog', 'gate merge requests on the answer in your own runner', '/rebrand/docs/run-locally#gitlab-ci'],
  ['Bitbucket Pipelines', 'a pipe that posts a Code Insights report on the pull request', '/rebrand/docs/run-locally#bitbucket-pipelines'],
  ['Azure DevOps', 'a pipeline template with a run summary and SARIF', '/rebrand/docs/run-locally#azure-devops'],
  ['Vercel AI SDK', 'wrap your tools so a Do not connect answer never runs', '/rebrand/docs/gate-on-the-grade#vercel-ai-sdk'],
  ['Flue', 'gate the tools a Flue agent connects to', '/rebrand/docs/gate-on-the-grade#flue'],
  ['Claude Agent SDK', 'leave out a server that fails, and deny each mcp__ call that does', '/rebrand/docs/gate-on-the-grade#claude-agent-sdk'],
  ['OpenAI Agents SDK', 'wrap an MCP server so connect, listTools and callTool are checked', '/rebrand/docs/gate-on-the-grade#openai-agents-sdk'],
  ['Open Policy Agent', 'a Rego policy your gateway or Envoy asks before a server or tool call', '/rebrand/docs/gate-on-the-grade#open-policy-agent'],
  ['LiteLLM proxy', "a guardrail on every MCP tool call through LiteLLM's MCP gateway", '/rebrand/docs/gate-on-the-grade#litellm-proxy'],
  ['Behavioral sandbox', 'see what a package actually does when it runs', '/rebrand/docs/behavioral-sandbox'],
]

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const section = `relative z-[2] py-[60px] ${DIVIDER_CLASS}`
const wrap = 'max-w-[1080px] mx-auto px-6'
const codeCls = 'font-mono text-[12px] text-primary-light bg-surface px-1.5 py-0.5 rounded [overflow-wrap:anywhere]'
const btnPrimary = 'inline-flex items-center font-semibold text-[13.5px] px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25'
const btnGhost = 'inline-flex items-center font-semibold text-[13.5px] px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors'
const copyBtn = 'absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light'

function useCopy(): [string | null, (key: string, text: string) => void] {
  const [copied, setCopied] = useState<string | null>(null)
  const copy = (key: string, text: string) => {
    navigator.clipboard?.writeText(text)
    trackPageAction('dev', `copy_${key}`)
    setCopied(key)
    setTimeout(() => setCopied((k) => (k === key ? null : k)), 1400)
  }
  return [copied, copy]
}

/** "YES / NOT YET" lines: what works today, said plainly. */
function Today({ rows }: { rows: [boolean, ReactNode][] }) {
  return (
    <div className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2.5 gap-y-1 text-[13px] mt-1">
      {rows.map(([yes, text], i) => (
        <span key={i} className="contents">
          <i className={`not-italic font-mono text-[10px] font-extrabold px-1.5 py-0.5 rounded-[5px] h-max mt-0.5 ${yes ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'}`}>{yes ? 'YES' : 'NOT YET'}</i>
          <span className="text-text-muted">{text}</span>
        </span>
      ))}
    </div>
  )
}

function Card({ id, step, title, children }: { id: string; step: string; title: string; children: ReactNode }) {
  return (
    <div id={id} className="glass rounded-2xl border border-border/60 p-5 flex flex-col gap-2 min-w-0 scroll-mt-24">
      <div className="font-mono text-[11px] tracking-[.12em] uppercase text-primary-light font-semibold">{step}</div>
      <h3 className="text-[18px] font-bold">{title}</h3>
      {children}
    </div>
  )
}

/** Live preview that dogfoods the hosted widget.js; re-renders when the tool changes. */
function WidgetPreview({ slug }: { slug: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const existing = document.querySelector<HTMLScriptElement>('script[data-agentavow-widget]')
    if (!existing) {
      const s = document.createElement('script')
      s.src = `${window.location.origin}/widget.js`
      s.async = true
      s.setAttribute('data-agentavow-widget', '1')
      s.onload = () => window.AgentAvow?.render(ref.current || undefined)
      document.body.appendChild(s)
    } else if (window.AgentAvow) {
      window.AgentAvow.render(ref.current || undefined)
    }
  }, [slug])
  return <div ref={ref}><div key={slug} data-agentavow-tool={slug} /></div>
}

export default function RebrandForDevelopers() {
  const location = useLocation()
  const [input, setInput] = useState('')
  const [style, setStyle] = useState<BadgeStyle>('compact')
  const [copied, copy] = useCopy()

  // Old /badge links land on #badge; scroll there once the page has rendered.
  useEffect(() => {
    if (!location.hash) return
    const t = setTimeout(() => document.getElementById(location.hash.slice(1))?.scrollIntoView({ block: 'start' }), 80)
    return () => clearTimeout(t)
  }, [location.hash])

  const parsed = parseBadgeTarget(input)
  const target = parsed ?? EXAMPLE
  const hasTarget = !!parsed
  const effStyle: BadgeStyle = target.styles.includes(style) ? style : 'compact'
  // The page's own origin, so a badge copied on staging or agentgraph.co resolves there.
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const badgeSrc = `${origin}${target.badgePath(effStyle)}`
  const markdown = hasTarget
    ? `[![AgentAvow](${badgeSrc})](${origin}${target.reportPath})`
    : `[![AgentAvow](${origin}/api/v1/public/scan/you/your-repo/badge)](${origin}/check/you/your-repo)`

  // A repo badge that has earned the Certified mark gets a note (the badge itself
  // already renders the earned treatment server-side).
  const repo = hasTarget && target.kind === 'repo' ? target.label : null
  const { data: certData } = useQuery({
    queryKey: ['badge-cert', repo],
    enabled: !!repo,
    retry: false,
    staleTime: 60_000,
    queryFn: async () => {
      try { return (await api.get<Record<string, unknown>>(`/public/scan/${repo}`)).data } catch { return null }
    },
  })
  const isCertified = !!certData && certifiedMark(certData)

  const widgetSnippet = target.widgetSlug
    ? `<script src="${origin}/widget.js"\n        data-tool="${hasTarget ? target.widgetSlug : 'you/your-repo'}"></script>`
    : null

  const copyBadge = () => { copy('badge', markdown); trackBadgeCopied('badge') }
  const badgeInput = (label: string) => (
    <input value={input} onChange={(e) => setInput(e.target.value)} aria-label={label}
      placeholder="owner/repo, npm:name or an MCP URL"
      className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[13px] text-text placeholder:text-text-muted" />
  )

  return (
    <div>
      <SEOHead
        title="For developers: claim your tool, badge your README, check a private repo"
        description="Claim the tool you publish, put its signed trust score and adoption badge on your README, or check a private repo first. Free, no account for public tools."
        path="/for-developers"
      />

      {/* hero */}
      <div className="relative pt-14 pb-[30px]">
        <div className={`relative z-[2] ${wrap}`}>
          <div className="font-mono text-[12px] tracking-[.16em] uppercase text-primary-light font-semibold">For developers</div>
          <h1 className="mt-3 max-w-[20em] text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">
            Ship a tool your users can trust — and <span className="gradient-text-bio">prove it</span>.
          </h1>
          <p className="mt-[18px] max-w-[58ch] text-[18px] font-light text-text-muted">
            A <b className="font-medium text-text">signed, offline-recomputable</b> safety score for the MCP server, package, or agent tool you publish. Free, no account. Claim it, put its badge on your README, or check a private repo first.
          </p>
        </div>
      </div>

      {/* the three jobs */}
      <div className="relative z-[2] pb-[60px]">
        <div className={`${wrap} grid lg:grid-cols-3 gap-3.5`}>
          <Card id="claim" step="1 · Claim your tool" title="Prove it's yours">
            <p className="text-[14px] text-text-muted">A claimed tool shows a “✓ Maintainer-claimed” chip on its result, and we watch it for you: you get an alert when its answer or score changes.</p>
            <ol className="mt-1 pl-5 list-decimal text-[14px] flex flex-col gap-1.5 marker:text-primary-light">
              <li>Sign in and paste <code className={codeCls}>owner/repo</code>.</li>
              <li>Add the GitHub topic we give you, <code className={codeCls}>agentavow-verify-…</code>, or run <code className={codeCls}>gh repo edit owner/repo --add-topic agentavow-verify-…</code></li>
              <li>Press <b>Verify topic</b>. We start watching it for you.</li>
            </ol>
            <Today rows={[
              [true, 'Public GitHub repos and skills: the GitHub topic'],
              [true, "npm, PyPI, crates: automatic when the package links to a repo you've claimed, or a keyword you publish"],
              [true, <>MCP servers: return the code in an <code className={codeCls}>X-AgentAvow-Verify</code> header or <code className={codeCls}>serverInfo</code></>],
            ]} />
            <div className="mt-auto pt-2 flex flex-wrap gap-2">
              <Link to={rp('/rebrand/tools')} onClick={() => trackPageAction('dev', 'claim_start')} className={btnPrimary}>Claim your tool</Link>
            </div>
          </Card>

          <Card id="get-badge" step="2 · Get your badge" title="Put the answer on your README">
            <p className="text-[14px] text-text-muted">One line of Markdown. It shows the current signed answer, trust score and adoption, and links to the full report. No account needed for a public tool.</p>
            <form onSubmit={(e) => { e.preventDefault(); trackPageAction('dev', 'badge_preview'); document.getElementById('badge')?.scrollIntoView({ behavior: 'smooth', block: 'start' }) }}
              className="flex gap-2 rounded-xl border border-border bg-surface p-1.5 pl-3 mt-1">
              {badgeInput('Repo, package or MCP URL')}
              <button type="submit" className="shrink-0 font-semibold text-[13px] px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark">Make badge</button>
            </form>
            {input.trim() && !parsed && <p className="text-[12.5px] text-warning">Try <span className="font-mono">owner/repo</span>, <span className="font-mono">npm:name</span>, <span className="font-mono">pypi:name</span> or an <span className="font-mono">https://</span> MCP URL.</p>}
            <div className="rounded-xl border border-border bg-surface/60 p-3 text-[13px] min-w-0">
              <span className="inline-flex max-w-full overflow-x-auto"><img src={`${origin}${target.badgePath('compact')}`} alt={hasTarget ? `${target.label} AgentAvow badge` : 'Example AgentAvow badge'} className="h-[20px] w-auto max-w-none" /></span>
              <code className="block mt-2 font-mono text-[11.5px] text-text-muted break-all">{markdown}</code>
              <button type="button" onClick={copyBadge} className="mt-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copied === 'badge' ? 'copied ✓' : 'copy'}</button>
            </div>
            <Today rows={[
              [true, 'GitHub repos, npm, PyPI and crates packages, and MCP servers'],
            ]} />
            <div className="mt-auto pt-2 flex flex-wrap gap-2">
              <a href="#badge" className={btnGhost}>Styles and the website widget ↓</a>
            </div>
          </Card>

          <Card id="private" step="3 · Check a private repo" title="Check it before it's public">
            <p className="text-[14px] text-text-muted">Two ways. Both need you signed in.</p>
            <ol className="mt-1 pl-5 list-decimal text-[14px] flex flex-col gap-1.5 marker:text-primary-light">
              <li><b>GitHub App.</b> Install it on the repos you choose. We check them now and re-check daily.</li>
              <li><b>One-time token.</b> A fine-grained, read-only token for a single check. It's used for that check and never stored.</li>
            </ol>
            <p className="text-[13.5px] border-l-[3px] border-warning bg-warning/[.07] rounded-r-[10px] px-3 py-2">
              <b>What you get:</b> a private report only you can open. It isn't listed in Browse or search, and it has no public badge. To get a badge, publish the result: publishing lists it in Browse and turns the badge on.
            </p>
            <Today rows={[
              [true, 'A private report (GitHub App: kept and re-checked daily; token: one check, nothing kept)'],
              [true, '"Publish to search" for GitHub App repos, which also turns on the badge'],
            ]} />
            <div className="mt-auto pt-2 flex flex-wrap gap-2">
              <Link to={rp('/rebrand/tools') + '?private=1'} onClick={() => trackPageAction('dev', 'private_scan')} className={btnPrimary}>Check a private repo</Link>
            </div>
          </Card>
        </div>
      </div>

      {/* the badge maker (was /badge) */}
      <div id="badge" className={`${section} scroll-mt-16`}>
        <div className={wrap}>
          <h2 className={h2}>Your badge, your way.</h2>
          <p className="mt-3 max-w-[64ch] text-[15px] text-text-muted">The badge regenerates on every view, so it never goes stale in your README, and clicking it opens the full signed report. Pick a style, copy one line.</p>
          <div className="grid lg:grid-cols-2 gap-3.5 mt-[26px]">
            <div className="glass rounded-2xl border border-border/60 p-5 min-w-0">
              <div className="flex gap-2 rounded-xl border border-border bg-surface p-1.5 pl-3">
                {badgeInput('Repo, package or MCP URL for the badge')}
                {hasTarget && <Link to={rp(`/rebrand${target.reportPath}`)} className="shrink-0 font-semibold text-[13px] px-3 py-1.5 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light">Report →</Link>}
              </div>
              <div className="mt-4 flex items-center gap-x-4 gap-y-2 flex-wrap">
                <span className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Style</span>
                <div className="inline-flex rounded-lg border border-border overflow-hidden" role="radiogroup" aria-label="Badge style">
                  {BADGE_STYLES.filter(([v]) => target.styles.includes(v)).map(([v, lbl]) => (
                    <button key={v} type="button" role="radio" aria-checked={effStyle === v} onClick={() => setStyle(v)}
                      className={`px-3 py-1 font-mono text-[12px] transition-colors ${effStyle === v ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>{lbl}</button>
                  ))}
                </div>
                <span className="text-[12px] text-text-muted">{BADGE_STYLES.find(([v]) => v === effStyle)?.[2]}</span>
              </div>
              {isCertified && (
                <div className="mt-4 rounded-xl p-3.5 border border-primary/30 bg-gradient-to-r from-primary/10 to-accent/10 text-[13px]">
                  <b>{target.label} is Certified.</b> <span className="text-text-muted">Your badge renders the Certified mark, and drops it if the tool ever slips. <Link to={rp('/rebrand/certified')} className="text-primary-light hover:text-primary font-semibold">What that means →</Link></span>
                </div>
              )}
              <div className="mt-4 flex items-center gap-3 flex-wrap">
                <span className="font-mono text-[11.5px] text-text-muted">{hasTarget ? 'Live badge:' : 'Example:'}</span>
                <span className="inline-flex p-3 rounded-lg bg-surface-hover max-w-full overflow-x-auto">
                  <img src={badgeSrc} alt={hasTarget ? `${target.label} AgentAvow badge` : 'Example AgentAvow badge'}
                    className={effStyle === 'card' ? 'w-[360px] max-w-full h-auto' : 'h-[20px] w-auto max-w-none'} />
                </span>
              </div>
              <div className="relative mt-4">
                <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto whitespace-pre-wrap break-all">{markdown}</pre>
                <button type="button" onClick={copyBadge} className={copyBtn}>{copied === 'badge' ? 'copied ✓' : 'copy'}</button>
              </div>
              <p className="mt-2 text-[12.5px] text-text-muted">More styles and themes: <Link to={rp('/rebrand/docs/trust-badges')} className="text-primary-light hover:text-primary">Badge docs →</Link></p>
            </div>

            <div className="glass rounded-2xl border border-border/60 p-5 min-w-0">
              <h3 className="text-[16px] font-semibold">Or embed the live widget</h3>
              <p className="mt-1.5 text-text-muted text-[13.5px]">
                The trust card (the answer, the trust bar and the adoption dial), linked to the report, plus a <b className="text-text">Verify offline</b> button that checks the Ed25519 signature in your reader's own browser. One script tag, no tracking.
              </p>
              {widgetSnippet ? (
                <>
                  <div className="relative mt-3">
                    <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto whitespace-pre-wrap break-all">{widgetSnippet}</pre>
                    <button type="button" onClick={() => { copy('widget', widgetSnippet); trackBadgeCopied('widget') }} className={copyBtn}>{copied === 'widget' ? 'copied ✓' : 'copy'}</button>
                  </div>
                  <div className="mt-4 font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">Live preview</div>
                  {hasTarget && target.widgetSlug
                    ? <WidgetPreview slug={target.widgetSlug} />
                    : <p className="text-text-muted text-[13px] italic">Enter a repo or package to preview the live widget.</p>}
                </>
              ) : (
                <p className="mt-3 text-[13px] text-text-muted">The widget shows repos and packages. For an MCP server, use the badge in its Card style.</p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* add a tool to the catalog (was /submit) */}
      <div id="list" className={`${section} scroll-mt-16`}>
        <div className={`${wrap} grid lg:grid-cols-2 gap-x-10 gap-y-5 items-start`}>
          <div className="min-w-0">
            <h2 className={h2}>Not listed yet? Add it.</h2>
            <p className="mt-3 max-w-[60ch] text-[15px] text-text-muted">
              Pasting a link into <Link to={rp('/rebrand/check')} className="text-primary-light hover:underline">Check</Link> is the fastest way to see an answer, and a GitHub repo or an npm, PyPI, crates, Docker or Hugging Face package you check there joins the public catalog on its own. A live MCP server checked by URL doesn&apos;t. Add it here: we scan it, sign the result and list it in Browse. Free, no account.
            </p>
          </div>
          <div className="glass rounded-2xl border border-border/60 p-5 min-w-0">
            <ListToolForm />
          </div>
        </div>
      </div>

      {/* why */}
      <div className={section}>
        <div className={wrap}>
          <h2 className={h2}>Why put a score on your tool.</h2>
          <p className="mt-3 max-w-[64ch] text-[15px] text-text-muted">It works because it's the one score a skeptic can check for themselves.</p>
          <div className="grid sm:grid-cols-2 gap-3.5 mt-[26px]">
            {[
              ['Signed, not "trust us"', 'Every score is signed (Ed25519), so anyone can prove who issued it, when, and that nobody changed the number in your README. They verify it offline against our public keys.'],
              ['Stand out in a crowded space', 'MCP servers and agent tools are multiplying. A signed high score is a trust signal to your users for a new project nobody has vetted yet.'],
              ['One score, everywhere your code lives', 'MCP server, npm, PyPI, GitHub repo, or skill: one recomputable score across all of them, that travels with the artifact.'],
              ['Actionable, not a black box', 'Score poorly and the report points at the exact file and line, with the fix. Score well and you get the badge.'],
            ].map(([h, p]) => (
              <div key={h} className="glass rounded-2xl border border-border/60 p-5 min-w-0">
                <div className="text-[15px] font-semibold">{h}</div>
                <p className="mt-1.5 text-text-muted text-[14px] leading-relaxed">{p}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* gate */}
      <div className={section}>
        <div className={wrap}>
          <h2 className={h2}>Gate pull requests and agents on the answer.</h2>
          <p className="mt-3 max-w-[64ch] text-[15px] text-text-muted">
            For a public repo, the hosted GitHub Action comments the answer and the trust score on every PR, and fails the build when the answer is Do not connect. When the repo publishes a package, AgentAvow also runs it in the behavioral sandbox and the Action prints a <code className={codeCls}>Sandbox:</code> line; <code className={codeCls}>fail_on_behavioral: true</code> fails the build on a high or critical sandbox finding. Prefer to keep it all local? <code className={codeCls}>agentavow scan .</code> runs offline, and nothing leaves your machine.
          </p>
          <div className="grid lg:grid-cols-2 gap-3.5 mt-[26px]">
            <div className="glass rounded-2xl border border-border/60 p-5 min-w-0">
              <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3 text-text overflow-x-auto">{`- uses: AgentAvow/AgentAvow/github-action@main
  with:
    fail_on: do_not_connect   # the default; "review" is stricter
    fail_on_behavioral: true`}</pre>
              <div className="mt-3 flex gap-x-4 gap-y-1.5 flex-wrap text-[13px]">
                <a href="https://github.com/AgentAvow/AgentAvow/tree/main/github-action" target="_blank" rel="noopener noreferrer" className="font-semibold text-primary-light hover:text-primary">Action inputs ↗</a>
                <Link to={rp('/rebrand/docs/run-locally')} className="font-semibold text-primary-light hover:text-primary">Run locally and in CI →</Link>
                <Link to={rp('/rebrand/preflight')} className="font-semibold text-primary-light hover:text-primary">Preflight for the app stores →</Link>
              </div>
            </div>
            <div className="glass rounded-2xl border border-border/60 p-5 min-w-0">
              <div className="text-[15px] font-semibold">Other places to gate</div>
              <ul className="mt-2 space-y-1.5 text-[13.5px] text-text-muted">
                {GATES.map(([h, p, to]) => (
                  <li key={h}><Link to={rp(to)} onClick={() => trackPageAction('dev', 'open_gate_doc')} className="font-semibold text-primary-light hover:text-primary">{h} →</Link> <span>{p}</span></li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* registry */}
      <div className={section}>
        <div className={wrap}>
          <h2 className={h2}>Carry the score into the MCP Registry.</h2>
          <p className="mt-3 max-w-[64ch] text-[15px] text-text-muted">
            The signed block rides the publisher-provided <code className={codeCls}>_meta</code> slot into your registry record. It is offline-recomputable, so a reviewer checks it without trusting us. Live block: <code className={codeCls}>/api/v1/public/registry-snippet/you/your-repo</code>
          </p>
          <div className="relative mt-[22px] max-w-[760px]">
            <pre className="font-mono text-[11.5px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto">{REGISTRY_SNIPPET}</pre>
            <button type="button" onClick={() => copy('snip', REGISTRY_SNIPPET)} className={copyBtn}>{copied === 'snip' ? 'copied ✓' : 'copy'}</button>
          </div>
        </div>
      </div>

      {/* our own MCP server */}
      <div className={section}>
        <div className={wrap}>
          <div className="font-mono text-[12px] tracking-[.16em] uppercase text-primary-light font-semibold">For anyone running an agent</div>
          <h2 className={`${h2} mt-2`}>Give your agent a safety check before it connects anything.</h2>
          <p className="mt-3 max-w-[64ch] text-[15px] text-text-muted">
            Add AgentAvow's own MCP server to Claude, ChatGPT, Cursor, or any MCP client. Your agent can ask <b className="text-text">"is this tool safe to install?"</b> and get a signed 0-100 score and findings back, before it connects an unknown server or runs a package. Free, no account, read-only.
          </p>
          <div className="mt-5 flex gap-2.5 flex-wrap">
            <a href="https://claude.ai/directory/connectors/agentavow" target="_blank" rel="noopener noreferrer" onClick={() => trackCta('add_claude')} className={btnPrimary}>Add to Claude ↗</a>
            <a href="https://chatgpt.com/plugins/plugin_asdk_app_6ac830ccc2d48191ac27974dec7d8344" target="_blank" rel="noopener noreferrer" onClick={() => trackCta('add_chatgpt')} className={btnGhost}>Add to ChatGPT ↗</a>
            <a href={cursorStdio(AA_MCP)} onClick={() => trackPageAction('dev', 'add_cursor')} className={btnGhost}>Add to Cursor →</a>
            <a href={vscodeStdio(AA_MCP)} onClick={() => trackPageAction('dev', 'add_vscode')} className={btnGhost}>Add to VS Code →</a>
            <Link to={rp('/rebrand/get')} className={btnGhost}>Every way to get it →</Link>
          </div>
          <p className="mt-4 text-[13.5px] text-text-muted">Claude Code: <code className={codeCls}>{claudeCodeStdio(AA_MCP)}</code></p>
          <p onCopy={trackPluginCommandCopy} className="mt-2 text-[13.5px] text-text-muted max-w-[72ch]">Or install the Claude Code plugin, which also checks each new MCP server at session start and warns you before your agent uses one: <code className={codeCls}>/plugin marketplace add AgentAvow/AgentAvow</code> then <code className={codeCls}>/plugin install agentavow-trust@agentavow</code>. <Link to={rp('/rebrand/docs/auto-scan-claude-code')} className="text-primary-light hover:underline">How it works</Link>.</p>
          <p className="mt-2 text-[13.5px] text-text-muted max-w-[72ch]">The plugin&apos;s checks run on your machine, so they cost Claude nothing: zero tokens per check, about 650 a session. <Link to={`${rp('/rebrand/faq')}#context-tokens`} className="text-primary-light hover:underline">The numbers</Link>.</p>
          <div className="relative mt-4 max-w-[760px]">
            <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto">{MCP_CONFIG}</pre>
            <button type="button" onClick={() => copy('mcp', MCP_CONFIG)} className={copyBtn}>{copied === 'mcp' ? 'copied ✓' : 'copy'}</button>
          </div>
          <p className="mt-2.5 text-[13.5px] text-text-muted">Prefer the terminal? <code className={codeCls}>npx agentavow-trust scan owner/repo</code> gives a signed score from the command line, no install.</p>
        </div>
      </div>

      {/* resources */}
      <div className={section}>
        <div className={wrap}>
          <h2 className={h2}>Developer resources.</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2.5 mt-[22px]">
            {DEV_RESOURCES.map(([h, p, href]) => {
              const external = href.startsWith('http') || href.startsWith('/api')
              const inner = (
                <>
                  <div className="flex items-center justify-between gap-2"><div className="text-[14.5px] font-semibold">{h}</div><span className="text-primary-light text-[13px] shrink-0">{external ? '↗' : '→'}</span></div>
                  <div className="text-[13px] text-text-muted mt-0.5">{p}</div>
                </>
              )
              return external
                ? <a key={h} href={href} target="_blank" rel="noopener noreferrer" onClick={() => trackPageAction('dev', 'open_resource')} className="glass card-hover rounded-xl px-4 py-3 block">{inner}</a>
                : <Link key={h} to={rp(href)} onClick={() => trackPageAction('dev', 'open_resource')} className="glass card-hover rounded-xl px-4 py-3 block">{inner}</Link>
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
