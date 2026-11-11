import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'

import SEOHead from '../../components/SEOHead'
import { rp } from '../basePath'

/**
 * State of Agent Security 2026 (published May 12, 2026, v2.0), in the rebrand layout.
 * Ported from the pre-rebrand page (web/src/pages/StateOfAgentSecurity2026.tsx) with its
 * content and data unchanged. This is a dated report: every figure is as of publication.
 * Lines that went stale after publication say so with a date rather than being rewritten.
 *
 * Source content: docs/internal/agentgraph-litepaper-v1.md (§0 + §3.8).
 */

interface ScanRow {
  surface: string
  description: string
  targets: string
  critical: string
  trust: string
}

interface InteropRow {
  implementation: string
  maintainer: string
  language: 'Python' | 'TypeScript'
  byteMatch: string
  claimTypeLive: string
}

const SCAN_ROWS: ScanRow[] = [
  { surface: 'x402 Bazaar', description: 'Coinbase agent-payment endpoints on Base L2', targets: '26,302 endpoints', critical: 'only 0.41% (107) serve the spec-required header', trust: '78% of catalog from 2 hosts' },
  { surface: 'OpenClaw', description: 'Skill repositories — 190K+ stars, legacy baseline', targets: '231 of 2,007', critical: '98 across 20 repos', trust: '57 / 100' },
  { surface: 'MCP Registry', description: 'Model Context Protocol servers (Claude Code, Cursor)', targets: '7,029 discovered, 1,058 fully scanned', critical: '55.3% have crit/high (6.5% critical)', trust: 'after Apr 29 retry pass' },
  { surface: 'npm', description: 'Agent-framework JS/TS packages', targets: '472 discovered, 46 fully scanned', critical: '82.6% have crit/high (15.2% critical)', trust: 'top-installed sample' },
  { surface: 'PyPI', description: 'Agent-framework Python packages', targets: '23 discovered', critical: '31% have crit/high', trust: '16 fully scanned' },
  { surface: 'Dreamspace', description: 'AI-generated Solidity (Microsoft M12-backed, deploys to Base)', targets: '10 apps generated', critical: 'pending review', trust: 'pending review' },
]

const INTEROP_ROWS: InteropRow[] = [
  { implementation: 'AgentAvow', maintainer: 'Kenne Ives', language: 'Python', byteMatch: '✓ vs APS bilateral-delegation (10 vectors) + APS rotation-attestation (5 vectors, live-fetch)', claimTypeLive: '✓ deployed to agentavow.com' },
  { implementation: 'Agent Passport System (APS)', maintainer: 'aeoess', language: 'Python', byteMatch: '✓ — publishes the bilateral-delegation + rotation-attestation fixture sets', claimTypeLive: '✓ Agent Cards integration cites claim_type' },
  { implementation: 'AgentID', maintainer: 'Harold Frimpong', language: 'Python', byteMatch: '✓ vs APS bilateral-delegation (all 10 byte-exact)', claimTypeLive: '✓ live on /api/v1/agents/verify, 32/32 tests passing' },
  { implementation: '@nobulex/crypto', maintainer: 'Arian Gogani', language: 'TypeScript', byteMatch: '✓ vs AgentAvow + APS fixtures', claimTypeLive: 'Verifier testing in flight' },
  { implementation: 'HiveTrust', maintainer: 'Steve Rotzin', language: 'Python', byteMatch: '✓ 4/4 byte-exact + SHA-256-exact on inline vectors (A2A #1786, 2026-04-28); HAHS + epoch primitive for v0.3.2', claimTypeLive: '✓ verifier live at hive-gamification.onrender.com' },
]

const COSIGNERS = [
  'aeoess (Agent Passport System)',
  'Harold Frimpong (AgentID)',
  'Steve Rotzin (HiveTrust)',
  'Arian Gogani (Nobulex)',
  'Erik Newton (Concordia / Verascore)',
  'Justin Headley (MoltBridge / SageMindAI)',
  'lawcontinue',
  'Kwame Nyantakyi (Vorim AI)',
]

const LAYERS = [
  { badge: 'Layer 1', ref: '§1', color: 'text-primary-light', title: 'What we found', question: 'Is the agent infrastructure shipping today actually safe?', body: 'Scan data across x402 Bazaar, OpenClaw, MCP Registry, npm/PyPI agent packages, and a sample of AI-generated Solidity from Microsoft-backed Dreamspace. The pattern is consistent across surfaces.' },
  { badge: 'Layer 2', ref: '§3', color: 'text-accent', title: 'What good looks like', question: 'How do we make this verifiable across implementations?', body: 'CTEF v0.3.1 frozen, 5-way byte-match validated across two languages. A2A WG Proposal #1786 in Proposal Phase. Eight independent collaborators with shipped artifacts.' },
  { badge: 'Layer 3', ref: '§0', color: 'text-warning', title: 'Why this matters now', question: 'Why should this hit my desk this week?', body: 'Alchemy + Coinbase x402 + Microsoft/Dreamspace + Frequency/DSNP collide on the same April 2026 news cycle. The trust gate between agent infra and the standards substrate does not yet exist.' },
]

const TEST_VECTORS = 'https://agentgraph.co/.well-known/cte-test-vectors.json'

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const eyebrow = 'font-mono text-[12px] tracking-[.16em] uppercase font-semibold'
const section = 'relative z-[2] py-[60px] border-t border-border/60'
const th = 'text-left text-[12px] text-text-muted font-semibold px-2.5 py-2 border-b border-border'
const td = 'block sm:table-cell sm:p-2.5 align-top sm:border-b sm:border-surface-hover'
const link = 'text-primary-light hover:underline'

function LangPill({ language }: { language: InteropRow['language'] }) {
  return (
    <span className={`inline-block text-[10.5px] font-mono font-bold px-2 py-0.5 rounded-full ${language === 'TypeScript' ? 'bg-accent/15 text-accent' : 'bg-primary/15 text-primary-light'}`}>
      {language}
    </span>
  )
}

function Signup() {
  const [email, setEmail] = useState('')
  const [state, setState] = useState<'idle' | 'submitting' | 'ok' | 'error'>('idle')
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!email.trim()) return
    setState('submitting')
    setError(null)
    try {
      const res = await fetch('/api/v1/analytics/newsletter-signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), source: 'state-of-agent-security-2026' }),
      })
      if (res.ok) {
        setState('ok')
        setEmail('')
      } else {
        setError((await res.text().catch(() => '')) || `HTTP ${res.status}`)
        setState('error')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error')
      setState('error')
    }
  }

  const busy = state === 'submitting' || state === 'ok'
  return (
    <form onSubmit={submit} className="glass rounded-2xl border border-border/60 grid gap-3 p-[22px] max-w-[560px]">
      <label htmlFor="soas-email" className="grid gap-[5px] text-[13.5px] text-text-muted">Email address
        <input
          id="soas-email"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          autoComplete="email"
          disabled={busy}
          className="w-full bg-background border border-border rounded-[10px] px-3 py-2.5 text-[15px] text-text focus:outline-none focus:border-primary disabled:opacity-50"
        />
      </label>
      <button type="submit" disabled={busy} className="justify-self-start font-semibold text-[15px] px-5 py-[11px] rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow disabled:opacity-60 disabled:cursor-not-allowed">
        {state === 'submitting' ? 'Submitting…' : state === 'ok' ? 'Subscribed ✓' : 'Subscribe'}
      </button>
      <p className="text-[12.5px]" role="status">
        {state === 'ok' && <span className="text-success">Thanks — you&apos;ll hear from us when the next report ships.</span>}
        {state === 'error' && error && <span className="text-danger">Couldn&apos;t submit: {error}</span>}
      </p>
    </form>
  )
}

export default function RebrandStateOfAgentSecurity2026() {
  return (
    <div>
      <SEOHead
        title="State of Agent Security 2026"
        description="The May 2026 State of Agent Security report: scans of x402 Bazaar, OpenClaw, the MCP Registry and npm/PyPI agent packages, and CTEF interop receipts from AgentAvow and 8 spec collaborators."
        path="/state-of-agent-security-2026"
        type="article"
      />

      {/* hero */}
      <div className="relative pt-14 pb-10">
        <div className="relative z-[2] max-w-[1080px] mx-auto px-6">
          <div className={`${eyebrow} text-primary-light`}>Quarterly report · v2.0 · May 12, 2026</div>
          <h1 className="mt-3 max-w-[21em] text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">
            State of Agent Security 2026
          </h1>
          <p className="mt-[18px] max-w-[58ch] text-[18px] font-light text-text-muted">
            AI agents are about to operate finance — but the agent infrastructure shipping today has no trust gate.
          </p>
          <p className="mt-3 max-w-[58ch] text-[14.5px] text-text-muted">
            From AgentAvow and 8 independent spec collaborators. Every number reproducible against the public test vectors.
          </p>
          <div className="flex flex-wrap gap-3 mt-7">
            <Link to={rp('/rebrand/check')} className="inline-flex items-center font-semibold text-[15px] px-5 py-[11px] rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Check any agent</Link>
            <a href="/state-of-agent-security-2026-v1.pdf" target="_blank" rel="noopener noreferrer" aria-label="Read the full report — PDF download" className="inline-flex items-center font-semibold text-[15px] px-5 py-[11px] rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Read the full report (PDF)</a>
            <a href={TEST_VECTORS} target="_blank" rel="noopener noreferrer" aria-label="View the public CTEF test vectors (raw JSON, Ed25519 signed)" className="inline-flex items-center text-[15px] px-3 py-[11px] text-text-muted hover:text-primary-light transition-colors">View test vectors (JSON) →</a>
          </div>
          <p className="mt-5 max-w-[68ch] text-[13px] text-text-muted border-l-2 border-border pl-3">
            A dated report: the figures and project status below are as of May 12, 2026. For current figures see
            the <Link to={rp('/rebrand/state-of-agent-security-q3-2026')} className={link}>Q3 2026 report</Link> and
            the live <Link to={rp('/rebrand/index')} className={link}>Trust Index</Link>.
          </p>
        </div>
      </div>

      {/* epigraph */}
      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <figure className="max-w-[68ch]">
            <blockquote className="border-l-2 border-primary-light pl-4 text-[17px] font-light italic text-text leading-relaxed">
              &ldquo;Crypto is the global infrastructure for money that agents need.&rdquo; What makes crypto difficult for
              humans — seed phrases, private keys, code-first interaction — is exactly what makes it powerful for
              machines. &ldquo;Just like computers operate the internet and humans use it, agents will operate finance.&rdquo;
            </blockquote>
            <figcaption className="mt-2 pl-4 text-[13px] text-text-muted">
              — Nikil Viswanathan, Alchemy CEO ·{' '}
              <a href="https://www.coindesk.com/tech/2026/04/25/crypto-is-built-for-ai-agents-not-humans-says-alchemy-s-ceo" target="_blank" rel="noopener noreferrer" className={link}>CoinDesk, April 25 2026</a>
            </figcaption>
          </figure>
        </div>
      </div>

      {/* three layers */}
      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <div className={`${eyebrow} text-primary-light`}>The report has three layers</div>
          <h2 className={`mt-2 ${h2}`}>Each answers a different question.</h2>
          <div className="grid md:grid-cols-3 gap-3.5 mt-[26px]">
            {LAYERS.map((card) => (
              <div key={card.badge} className="glass rounded-2xl border border-border/60 p-[22px] flex flex-col gap-[9px]">
                <div className={`font-mono text-[11px] font-bold tracking-[.16em] ${card.color}`}>{card.badge.toUpperCase()} · {card.ref}</div>
                <h3 className="text-[19px] font-bold">{card.title}</h3>
                <p className="text-[14.5px] text-text italic">&ldquo;{card.question}&rdquo;</p>
                <p className="text-text-muted text-[14.5px]">{card.body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* layer 1: scan data */}
      <div id="layer-1" className={`${section} scroll-mt-[70px]`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <div className={`${eyebrow} text-primary-light`}>Layer 1 · §1 — What we found</div>
          <h2 className={`mt-2 ${h2}`}>Five distribution surfaces, scanned April 21–28.</h2>
          <p className="mt-2.5 text-text-muted text-[15px] max-w-[68ch]">
            Every scan output is signed (JWS, RFC 7515) and verifiable against the public JWKS
            at <code className="font-mono text-[13px] text-primary-light">/.well-known/jwks.json</code>. Figures are as of
            publication (May 12, 2026); the Dreamspace review was still pending then.
          </p>
          <table className="w-full mt-[18px] text-[14.5px] border-collapse block sm:table">
            <thead className="hidden sm:table-header-group">
              <tr><th className={th}>Surface</th><th className={th}>Targets</th><th className={th}>Critical findings</th><th className={th}>Avg trust</th></tr>
            </thead>
            <tbody className="block sm:table-row-group">
              {SCAN_ROWS.map((row) => (
                <tr key={row.surface} className="block sm:table-row py-2.5 sm:py-0 border-b border-surface-hover">
                  <td className={`${td} sm:w-[30%]`}>
                    <div className="font-semibold">{row.surface}</div>
                    <div className="text-[12.5px] text-text-muted mt-0.5">{row.description}</div>
                  </td>
                  <td className={`${td} text-text`}><span className="sm:hidden text-text-muted text-[12px]">Targets: </span>{row.targets}</td>
                  <td className={`${td} text-text`}><span className="sm:hidden text-text-muted text-[12px]">Critical findings: </span>{row.critical}</td>
                  <td className={`${td} text-text`}><span className="sm:hidden text-text-muted text-[12px]">Avg trust: </span>{row.trust}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* layer 2: interop */}
      <div id="layer-2" className={`${section} scroll-mt-[70px]`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <div className={`${eyebrow} text-accent`}>Layer 2 · §3.8 — Cross-implementation interop receipts</div>
          <h2 className={`mt-2 ${h2}`}>CTEF v0.3.1: byte-match-validated across 5 implementations, 2 languages.</h2>
          <p className="mt-2.5 text-text-muted text-[15px] max-w-[68ch]">
            Three independent Python canonicalizers + one independent TypeScript canonicalizer producing byte-identical
            output against the published fixtures. RFC 8785 JCS proves language-agnostic in practice, not just by design.
            Any one-sided drift fires against three witnesses.
          </p>
          <table className="w-full mt-[18px] text-[14.5px] border-collapse block sm:table">
            <thead className="hidden sm:table-header-group">
              <tr><th className={th}>Implementation</th><th className={th}>Maintainer</th><th className={th}>Language</th><th className={th}>JCS byte-match</th><th className={th}>claim_type live</th></tr>
            </thead>
            <tbody className="block sm:table-row-group">
              {INTEROP_ROWS.map((row) => (
                <tr key={row.implementation} className="block sm:table-row py-2.5 sm:py-0 border-b border-surface-hover">
                  <td className={`${td} font-semibold`}>{row.implementation}</td>
                  <td className={`${td} text-text-muted`}>{row.maintainer}</td>
                  <td className={td}><LangPill language={row.language} /></td>
                  <td className={`${td} text-text-muted text-[13px]`}><span className="sm:hidden text-[12px]">JCS byte-match: </span>{row.byteMatch}</td>
                  <td className={`${td} text-text-muted text-[13px]`}><span className="sm:hidden text-[12px]">claim_type live: </span>{row.claimTypeLive}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-4 text-[13px] text-text-muted max-w-[68ch]">
            Plus <span className="text-text">lawcontinue</span> (245-step distributed-inference fixture for v0.3.2
            long-session worked example), <span className="text-text">Vorim AI</span> (IETF{' '}
            <code className="font-mono text-primary-light">draft-vorim-vaip-00</code>) onboarding as a sixth implementation,
            and <span className="text-text">Concordia v1.0.0</span> (Erik Newton, Verascore) fixtures landing via PR #10
            with 131/131 checks.
          </p>
        </div>
      </div>

      {/* co-signers */}
      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <div className={`${eyebrow} text-primary-light`}>Co-signers · documented public spec collaboration</div>
          <p className="mt-3 text-text-muted text-[15px] max-w-[68ch]">{COSIGNERS.join(' · ')}</p>
        </div>
      </div>

      {/* lead capture */}
      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6 grid md:grid-cols-2 gap-5 md:gap-[34px] items-start">
          <div>
            <h2 className={h2}>Get the next quarterly update.</h2>
            <p className="mt-2.5 text-text-muted max-w-[60ch]">
              New scan corpus and spec progress. One email per quarter, no list spam. As of November 10, 2026,{' '}
              <Link to={rp('/rebrand/state-of-agent-security-q3-2026')} className={link}><em>State of Agent Security Q3 2026</em></Link> is out.
            </p>
          </div>
          <Signup />
        </div>
      </div>

      {/* methodology */}
      <div id="methodology" className={`${section} scroll-mt-[70px]`}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2}>Methodology.</h2>
          <p className="mt-2.5 text-text-muted text-[15px] max-w-[68ch]">
            Every number reproducible. Pull the live test vectors. Run a JCS canonicalizer (RFC 8785). Verify the SHA-256s
            match. Fail-closed on the negative-path vectors. There is no AgentAvow-private side channel.
          </p>
          <p className="mt-3 text-text-muted text-[15px] max-w-[68ch]">
            Scans run between April 21–28, 2026. Every scan attestation is signed with Ed25519 (JWS, RFC 7515) and
            verifiable against the public JWKS endpoint. Dreamspace generation used non-adversarial prompts only;
            generated Solidity was archived but never deployed to Base mainnet.
          </p>
          <p className="mt-3 text-text-muted text-[15px] max-w-[68ch]">
            35,689 scans in the catalog as of May 12, 2026. A living record: every row reproducible, not a frozen PDF.{' '}
            <Link to={rp('/rebrand/browse')} className={`${link} font-semibold`}>Browse the current catalog →</Link>
          </p>
          <nav aria-label="Report links" className="mt-8 flex flex-wrap gap-x-6 gap-y-3 text-[14px]">
            <a href="https://github.com/AgentAvow/AgentAvow" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-primary-light">GitHub</a>
            <a href="https://github.com/a2aproject/A2A/issues/1786" target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-primary-light">A2A WG #1786</a>
            <a href={TEST_VECTORS} target="_blank" rel="noopener noreferrer" className="text-text-muted hover:text-primary-light">CTEF test vectors</a>
            <Link to={rp('/rebrand/check')} className="text-text-muted hover:text-primary-light">Check a tool</Link>
            <Link to={rp('/rebrand/browse')} className="text-text-muted hover:text-primary-light">Browse the catalog</Link>
            <Link to={rp('/rebrand/research')} className="text-text-muted hover:text-primary-light">All research</Link>
          </nav>
        </div>
      </div>
    </div>
  )
}
