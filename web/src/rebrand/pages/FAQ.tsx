import { useEffect, type ReactNode } from 'react'
import { Helmet } from 'react-helmet-async'
import { Link, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

/**
 * AgentAvow FAQ — tool-safety relevant, with FAQPage structured data for SEO
 * (Google rich results). Replaces the old social-era FAQ.
 */

/** `id` gives an answer a stable anchor (/faq#id opens it); `extra` renders under the
 * answer text and stays out of the structured data. */
interface QA { q: string; a: string; id?: string; extra?: ReactNode }

/** Measured with Claude Code's /context on 12 Nov 2026, plugin 0.1.38. */
const CONTEXT_ROWS: [string, string][] = [
  ['Each check (install hook, per-call gate)', '0'],
  ['8 connector tool names', 'about 90'],
  ['Connector instructions', 'about 620'],
  ['/agentavow-trust:scan command and scan-before-connect skill', 'about 140'],
  ['Session-start line', 'about 50 to 100'],
  ['Total a session', 'under 1,000'],
]
const CONTEXT_ON_USE: [string, string][] = [
  ['One tool\'s full definition', '111 to 571 (all eight: 2,180)'],
  ['One scan result', 'about 270 to 620'],
]

function ContextTokens() {
  const row = (label: string, n: string, bold = false) => (
    <tr key={label} className="border-t border-border/60">
      <td className={`py-1.5 pr-4 ${bold ? 'font-semibold text-text' : ''}`}>{label}</td>
      <td className={`py-1.5 text-right font-mono text-[13px] whitespace-nowrap ${bold ? 'font-semibold text-text' : ''}`}>{n}</td>
    </tr>
  )
  return (
    <div className="mt-3 text-text-muted text-[14px] leading-relaxed">
      <table className="w-full max-w-[520px] text-[13.5px]">
        <thead>
          <tr><th className="text-left font-semibold text-text pb-1.5">Every session</th><th className="text-right font-semibold text-text pb-1.5">Tokens</th></tr>
        </thead>
        <tbody>
          {CONTEXT_ROWS.map(([l, n], i) => row(l, n, i === CONTEXT_ROWS.length - 1))}
          <tr><th colSpan={2} className="text-left font-semibold text-text pt-3 pb-1.5">Only when Claude uses it</th></tr>
          {CONTEXT_ON_USE.map(([l, n]) => row(l, n))}
        </tbody>
      </table>
      <p className="mt-3">Check it yourself in Claude Code:</p>
      <ol className="mt-1 pl-5 list-decimal grid gap-0.5">
        <li>With the plugin on, start a session and run <code className="font-mono text-[13px] text-primary-light">/context</code>.</li>
        <li>Turn the plugin off in <code className="font-mono text-[13px] text-primary-light">/plugin</code>, start a new session and run <code className="font-mono text-[13px] text-primary-light">/context</code> again.</li>
        <li>Compare the two totals.</li>
      </ol>
    </div>
  )
}
interface Section { title: string; items: QA[] }

const SECTIONS: Section[] = [
  {
    title: 'About AgentAvow',
    items: [
      { q: 'What is AgentAvow?', a: 'AgentAvow tells you whether a tool, MCP server, or package is safe for your AI agent to connect to. Paste a URL and get one of three answers with its reason (Safe to connect, Review before you connect, or Do not connect), a signed 0–100 trust score backed by scan evidence anyone can recompute, and an adoption score from real usage.' },
      { q: 'Is AgentAvow free?', a: 'Yes. Checking any tool is free and requires no account. An account is only needed to watch tools for change-alerts, manage API keys, or claim repositories you own.' },
      { q: 'Do I need an account to use it?', a: 'No. Checking a tool and browsing the catalog are free and need no signup. The site keeps its own analytics; the privacy policy says what they record.' },
    ],
  },
  {
    title: 'The scan & the score',
    items: [
      { q: 'How does the scan work?', a: 'We read the actual source code across 14 detection categories — secrets, code execution, obfuscation, prompt injection, remote code load (rug-pull), data exfiltration, toxic flows (the lethal trifecta), network endpoints, filesystem access, dependencies, install hooks, tool definitions, artifact integrity, and runtime robustness (from the behavioral sandbox) — and produce one of three answers, a 0–100 trust score and a signed attestation.' },
      { q: 'What does the result mean?', a: 'Every result leads with one of three answers and the reason behind it. Do not connect: a critical finding in the tool\'s own code, a leaked canary credential in the sandbox, or a known-malicious package. Review before you connect: a hardcoded credential (it exposes the vendor\'s key, not yours), a high finding, a known advisory on the version you would install, a deprecated package, or a trust score below 51. Safe to connect: none of those. Under the answer sit two scores: the signed 0–100 trust score (higher is safer) and the adoption score. The trust score also maps to a tier (Verified, Trusted, Standard, Minimal, Restricted, Blocked) that sets a recommended rate limit and confirmation posture; the answer, not the tier, says whether to connect. A result reflects a scan at a point in time, so watch anything you depend on.' },
      { q: 'Why does a result say "waiting for a sandbox slot"?', a: 'The behavioral sandbox runs a limited number of tools at once. When every slot is busy, a new run waits its turn and the result shows its place in the queue; the answer from the code scan is shown meanwhile and updates when the run finishes. If no slot frees up for two hours, the result says the sandbox is unavailable and the answer stands on static analysis alone.' },
      { q: 'What are the two scores — Trust and Adoption?', a: 'The trust score (0–100) is the signed safety score from our scanner, and anyone can verify it. Adoption reflects how much the ecosystem actually uses a tool — real usage like downloads, dependents, stars or pulls, depending on the surface, not opinions.' },
      { q: 'Do you run the tool, or only read its code?', a: 'Both. The scan reads the code. For npm and PyPI packages, GitHub repos, skills, Docker images and MCP servers published as packages, a behavioral sandbox also installs and runs the tool in a fresh gVisor container: it starts an MCP server, calls each tool (up to 25) with synthetic arguments, and fills the environment variables the tool reads with fake canary credentials. It reports undeclared network hosts, read-only tools that write files, and any canary that leaves the machine (graded critical). Each run is signed as a separate BehavioralObservation and shown beside the score. Remote MCP servers reached by URL are not run, because calling someone else\'s live server could have real side effects.' },
      { q: 'What happens if a package is deprecated, yanked or removed?', a: 'If the registry says the maintainer has retired it (npm marks the resolved version deprecated, or PyPI marks the project Development Status :: 7 - Inactive), the scan adds a medium maintenance finding that quotes the maintainer\'s message, and the answer reads Review before you connect. A deprecated package gets no more security fixes, so treat it as "don\'t adopt for new work" even if the code looks clean. A yanked PyPI release is usually a broken build: we still check its code, and the yank is a low note, or medium when the maintainer\'s reason says it was a security problem. A version the registry no longer serves reads Do not connect when a malware record names that exact version, and otherwise Review before you connect, since its code can\'t be checked.' },
      { q: 'Can my agent check tools automatically, before it connects?', a: 'Yes. Add AgentAvow\'s MCP server to your agent (Claude Code, Cursor, or your own runtime) and it pulls a tool\'s signed answer before your agent connects, so your agent (or a gate) can refuse an unsafe tool rather than find it after the fact. It uses the same free, signed scan as the website and needs no account.' },
    ],
  },
  {
    title: 'Verification & trust',
    items: [
      { q: 'What makes the score verifiable?', a: 'Every result is signed with Ed25519 (JWS). You can verify any attestation offline against our public keys — no call back to us required. If a single byte of the score is altered, verification fails. It\'s a signature, not just a badge.' },
      { q: 'How do I verify a score myself?', a: 'Use the live verification tool on the How-it-works page, or check any attestation against our public JWKS. The evidence format and conformance vectors are published and versioned in the open.' },
      { q: 'Isn\'t this just a directory\'s score or a self-assigned badge?', a: 'No. A directory\'s in-house number and a self-assigned badge are figures you take on faith — they live on one platform and disappear off it. An AgentAvow score is cryptographically signed and recomputable by anyone: it travels with your tool (README, npm, CI) and doesn\'t depend on us being online. A directory optimizes for discoverability; we grade for safety, and we let you check our work.' },
    ],
  },
  {
    title: 'For developers',
    items: [
      { q: 'How do I add a trust badge to my README?', a: 'Check your repo and copy one line of Markdown. The badge is kept up to date from the current scan and links back to the full, signed, verifiable report — no account needed to mint one.' },
      { q: 'Is there an API, SDK, or CI gate?', a: 'Yes — a REST API, an npm SDK (agentavow-trust) with gates for the Vercel AI SDK, Flue, the Claude Agent SDK and the OpenAI Agents SDK (Python gates are in the repository), a Python client (agentavow-sdk), a local CLI, a GitHub Action, a GitLab CI component, a Bitbucket Pipe, an Azure Pipelines template, an Open Policy Agent policy, and a LiteLLM proxy guardrail for its MCP gateway. The CI gates fail the build when the answer is Do not connect (fail_on: do_not_connect, the default; set review to be stricter). The Action also prints the sandbox result, and with fail_on_behavioral: true it fails the build on a high or critical sandbox finding. See the developer page and docs.' },
      { q: 'What does the Claude Code plugin show?', a: 'When you add an MCP server that runs from an npm or PyPI package, the plugin\'s session-start check prints one line per server: the answer and its reason, the trust score, then the sandbox result (for example "sandbox: called 9 tools, no network beyond the registry", the number of behavioral findings, or why the server could not be exercised). If the maintainer has deprecated the package, the line says so. The session-start check only warns. Installing something that reads Do not connect asks you first, the per-call gate stops a tool on a server that reads Do not connect, and it asks you before using a tool whose definition changed since it was checked.' },
      {
        id: 'context-tokens',
        q: 'How much of Claude\'s context does AgentAvow use?',
        a: 'Zero tokens per check. Under 1,000 a session. The install-time hook and the per-call gate run as Python scripts on your machine, so they cost Claude nothing. Safe to connect stays silent; only a Review before you connect or Do not connect note reaches Claude. That is the plugin\'s setup: tool names, connector instructions, the /agentavow-trust:scan command and skill, and the session-start line. Claude Code loads a tool\'s full definition only when it uses that tool. We measured these with Claude Code\'s /context on plugin 0.1.38. They are approximate: the exact number depends on your Claude Code version and your other tools.',
        extra: <ContextTokens />,
      },
      { q: 'Can I scan a private repo?', a: 'Yes. Sign in and scan it through the GitHub App, or with a GitHub token you supply that\'s used once and never stored. Claiming with a GitHub topic proves ownership of a public repo only.' },
    ],
  },
  {
    title: 'Account & watching',
    items: [
      { q: 'What does "watching" a tool do?', a: 'We re-scan the tools you watch and alert you — by email, in-app, or webhook — when its score drops by more than 5 points, its answer gets worse (Safe to connect → Review before you connect → Do not connect), its Certified mark comes off, or its signed definition changes. That\'s the rug-pull you\'d otherwise miss. Definition-change alerts cover GitHub repos, OpenClaw skills and live MCP servers; npm and PyPI packages alert on score. Once the sandbox has run a watched tool, a later run that turns up new behavioral findings (for example a leaked canary or a new undeclared host) sends an in-app and webhook alert too.' },
      { q: 'How do I claim a tool I own?', a: 'Add a GitHub topic we give you to the repo to prove ownership. A verified claim (public repos) gives you continuous re-scans with change alerts, and control over how the tool appears in the catalog and search.' },
    ],
  },
]

const FAQ_JSONLD = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: SECTIONS.flatMap((s) => s.items).map((i) => ({
    '@type': 'Question',
    name: i.q,
    acceptedAnswer: { '@type': 'Answer', text: i.a },
  })),
}

export default function RebrandFAQ() {
  const { hash } = useLocation()
  // Open and scroll to the answer a link points at (/faq#context-tokens).
  useEffect(() => {
    const id = hash.slice(1)
    if (!id) return
    const el = document.getElementById(id)
    if (el instanceof HTMLDetailsElement) {
      el.open = true
      el.scrollIntoView({ block: 'start' })
    }
  }, [hash])

  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <Helmet>
        <title>FAQ · AgentAvow</title>
        <link rel="canonical" href="https://agentavow.com/faq" />
        <meta name="description" content="Frequently asked questions about AgentAvow — signed, verifiable trust scores for the tools your AI agents connect to." />
        <script type="application/ld+json">{JSON.stringify(FAQ_JSONLD)}</script>
      </Helmet>

      <Reveal>
        <div className="max-w-[60ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">FAQ</span>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">Questions, answered.</h1>
          <p className="mt-3 text-text-muted">Everything about checking tools, verifying scores, and staying safe over time.</p>
        </div>
      </Reveal>

      {SECTIONS.map((s) => (
        <Reveal key={s.title}>
          <section className="mt-10">
            <h2 className="text-[13px] font-mono uppercase tracking-wide text-primary-light mb-3">{s.title}</h2>
            <div className="flex flex-col gap-2.5">
              {s.items.map((i) => (
                <details key={i.q} id={i.id} className="glass rounded-xl px-5 py-4 group scroll-mt-24">
                  <summary className="cursor-pointer list-none flex items-center justify-between gap-3 font-semibold text-[15px]">
                    {i.q}
                    <span className="text-text-muted group-open:rotate-45 transition-transform text-lg leading-none">+</span>
                  </summary>
                  <p className="mt-3 text-text-muted text-[14px] leading-relaxed">{i.a}</p>
                  {i.extra}
                </details>
              ))}
            </div>
          </section>
        </Reveal>
      ))}

      <Reveal>
        <div className="mt-12 text-center">
          <Link to={rp('/rebrand/check')} className="inline-block font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Check a tool →</Link>
        </div>
      </Reveal>
    </div>
  )
}
