/**
 * State of Agent Security 2026 — Launch landing page (May 12, 2026).
 *
 * Companion landing for the State of Agent Security report.
 * Layout-first staging build: real scan data wires in later as scans complete.
 * Placeholders carry data-testid="scan-cell-{surface}" so we can target them
 * for live data injection without restructuring the DOM.
 *
 * Source content: docs/internal/agentgraph-litepaper-v1.md (§0 + §3.8).
 */

import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import SEOHead from '../components/SEOHead'
import {
  FadeIn,
  Stagger,
  StaggerItem,
  PageTransition,
  motion,
} from '../components/Motion'

// ─── Types ───

interface ScanRow {
  surface: string
  testId: string
  description: string
  targetsLabel: string
  criticalLabel: string
  trustLabel: string
}

interface InteropRow {
  implementation: string
  maintainer: string
  language: 'Python' | 'TypeScript'
  byteMatch: string
  claimTypeLive: string
}

// ─── Static Data (from litepaper §1 + §3.8) ───

const SCAN_ROWS: ScanRow[] = [
  {
    surface: 'x402 Bazaar',
    testId: 'scan-cell-x402',
    description: 'Coinbase agent-payment endpoints on Base L2',
    targetsLabel: '26,302 endpoints',
    criticalLabel: 'only 0.41% (107) serve the spec-required header',
    trustLabel: '78% of catalog from 2 hosts',
  },
  {
    surface: 'OpenClaw',
    testId: 'scan-cell-openclaw',
    description: 'Skill repositories — 190K+ stars, legacy baseline',
    targetsLabel: '231 of 2,007',
    criticalLabel: '98 across 20 repos',
    trustLabel: '57 / 100',
  },
  {
    surface: 'MCP Registry',
    testId: 'scan-cell-mcp',
    description: 'Model Context Protocol servers (Claude Code, Cursor)',
    targetsLabel: '7,029 discovered, 1,058 fully scanned',
    criticalLabel: '55.3% have crit/high (6.5% critical)',
    trustLabel: 'after Apr 29 retry pass',
  },
  {
    surface: 'npm',
    testId: 'scan-cell-npm',
    description: 'Agent-framework JS/TS packages',
    targetsLabel: '472 discovered, 46 fully scanned',
    criticalLabel: '82.6% have crit/high (15.2% critical)',
    trustLabel: 'top-installed sample',
  },
  {
    surface: 'PyPI',
    testId: 'scan-cell-pypi',
    description: 'Agent-framework Python packages',
    targetsLabel: '23 discovered',
    criticalLabel: '31% have crit/high',
    trustLabel: '16 fully scanned',
  },
  {
    surface: 'Dreamspace',
    testId: 'scan-cell-dreamspace',
    description: 'AI-generated Solidity (Microsoft M12-backed, deploys to Base)',
    targetsLabel: '10 apps generated',
    criticalLabel: 'pending review',
    trustLabel: 'pending review',
  },
]

const INTEROP_ROWS: InteropRow[] = [
  {
    implementation: 'AgentAvow',
    maintainer: 'Kenne Ives',
    language: 'Python',
    byteMatch:
      '✓ vs APS bilateral-delegation (10 vectors) + APS rotation-attestation (5 vectors, live-fetch)',
    claimTypeLive: '✓ deployed to agentavow.com',
  },
  {
    implementation: 'Agent Passport System (APS)',
    maintainer: 'aeoess',
    language: 'Python',
    byteMatch: '✓ — publishes the bilateral-delegation + rotation-attestation fixture sets',
    claimTypeLive: '✓ Agent Cards integration cites claim_type',
  },
  {
    implementation: 'AgentID',
    maintainer: 'Harold Frimpong',
    language: 'Python',
    byteMatch: '✓ vs APS bilateral-delegation (all 10 byte-exact)',
    claimTypeLive: '✓ live on /api/v1/agents/verify, 32/32 tests passing',
  },
  {
    implementation: '@nobulex/crypto',
    maintainer: 'Arian Gogani',
    language: 'TypeScript',
    byteMatch: '✓ vs AgentAvow + APS fixtures',
    claimTypeLive: 'Verifier testing in flight',
  },
  {
    implementation: 'HiveTrust',
    maintainer: 'Steve Rotzin',
    language: 'Python',
    byteMatch:
      '✓ 4/4 byte-exact + SHA-256-exact on inline vectors (A2A #1786, 2026-04-28); HAHS + epoch primitive for v0.3.2',
    claimTypeLive: '✓ verifier live at hive-gamification.onrender.com',
  },
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

// ─── Sub-components ───

function ScanCell({ testId, label }: { testId: string; label: string }) {
  const inProgress = label === 'scanning...' || label === 'pending review'
  return (
    <span
      data-testid={testId}
      className={`text-xs ${inProgress ? 'text-text-muted italic' : 'text-text font-medium'}`}
    >
      {label}
    </span>
  )
}

function SectionAnchor({ id }: { id: string }) {
  return <span id={id} className="block -mt-20 pt-20" aria-hidden="true" />
}

// ─── Main Component ───

export default function StateOfAgentSecurity2026() {
  const [email, setEmail] = useState('')
  const [signupState, setSignupState] = useState<'idle' | 'submitting' | 'ok' | 'error'>('idle')
  const [signupError, setSignupError] = useState<string | null>(null)

  const handleSignup = async (e: FormEvent) => {
    e.preventDefault()
    if (!email.trim()) return
    setSignupState('submitting')
    setSignupError(null)
    try {
      const res = await fetch('/api/v1/analytics/newsletter-signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), source: 'state-of-agent-security-2026' }),
      })
      if (res.ok) {
        setSignupState('ok')
        setEmail('')
      } else {
        const txt = await res.text().catch(() => '')
        setSignupError(txt || `HTTP ${res.status}`)
        setSignupState('error')
      }
    } catch (err) {
      setSignupError(err instanceof Error ? err.message : 'Network error')
      setSignupState('error')
    }
  }

  return (
    <PageTransition className="overflow-hidden">
      <SEOHead
        title="State of Agent Security 2026"
        description="AI agents are about to operate finance — but the agent infrastructure shipping today has no trust gate. Quarterly report from AgentAvow and 8 spec collaborators."
        path="/state-of-agent-security-2026"
      />

      <div className="max-w-5xl mx-auto px-4 pt-16 pb-24">
        {/* ═══════════════════════════
            HERO
            ═══════════════════════════ */}
        <section className="text-center mb-20">
          <FadeIn delay={0.05}>
            <motion.div
              className="inline-flex items-center gap-2 bg-primary/10 border border-primary/20 rounded-full px-4 py-1.5 mb-8"
              whileHover={{ scale: 1.03 }}
            >
              <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
              <span className="text-xs text-text-muted font-medium">
                Quarterly report &middot; v2.0 &middot; May 12, 2026
              </span>
            </motion.div>
          </FadeIn>

          <FadeIn delay={0.15}>
            <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold leading-[1.1] tracking-tight mb-6">
              <span className="gradient-text">State of Agent Security</span>
              <br />
              <span className="text-text">2026</span>
            </h1>
          </FadeIn>

          <FadeIn delay={0.3}>
            <p className="text-lg md:text-xl text-text-muted max-w-3xl mx-auto leading-relaxed font-light">
              AI agents are about to operate finance — but the agent infrastructure shipping today
              has no trust gate.
            </p>
          </FadeIn>

          <FadeIn delay={0.4}>
            <p className="text-sm text-text-muted/80 max-w-2xl mx-auto mt-4">
              From AgentAvow and 8 independent spec collaborators. Every number reproducible
              against the public test vectors.
            </p>
          </FadeIn>

          {/* Primary CTA group */}
          <FadeIn delay={0.5}>
            <div className="flex flex-col sm:flex-row gap-3 justify-center items-center mt-10">
              <Link
                to="/check"
                className="bg-gradient-to-r from-primary to-primary-dark text-white px-8 py-3.5 rounded-xl text-base font-semibold transition-all duration-300 shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30"
              >
                Check any agent
              </Link>
              <a
                href="/state-of-agent-security-2026-v1.pdf"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-surface border border-border text-text px-6 py-3.5 rounded-xl text-base font-semibold hover:border-primary/50 transition-colors"
                aria-label="Read the full report — PDF download"
              >
                Read the full report (PDF)
              </a>
              <a
                href="https://agentgraph.co/.well-known/cte-test-vectors.json"
                target="_blank"
                rel="noopener noreferrer"
                className="text-text-muted hover:text-primary-light px-4 py-3.5 rounded-xl text-base transition-colors"
                aria-label="View the public CTEF test vectors (raw JSON, Ed25519 signed)"
              >
                View test vectors (JSON) &rarr;
              </a>
            </div>
          </FadeIn>
        </section>

        {/* ═══════════════════════════
            ALCHEMY EPIGRAPH
            ═══════════════════════════ */}
        <section className="mb-20">
          <FadeIn>
            <blockquote className="relative bg-surface border border-border rounded-2xl p-8 md:p-10 overflow-hidden">
              <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-primary via-accent to-warning rounded-l-2xl" />
              <p className="text-lg md:text-xl text-text leading-relaxed font-light italic mb-4 pl-3">
                &ldquo;Crypto is the global infrastructure for money that agents need.&rdquo; What
                makes crypto difficult for humans — seed phrases, private keys, code-first
                interaction — is exactly what makes it powerful for machines. &ldquo;Just like
                computers operate the internet and humans use it, agents will operate
                finance.&rdquo;
              </p>
              <footer className="text-sm text-text-muted pl-3">
                — Nikil Viswanathan, Alchemy CEO &middot;{' '}
                <a
                  href="https://www.coindesk.com/tech/2026/04/25/crypto-is-built-for-ai-agents-not-humans-says-alchemy-s-ceo"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-primary-light hover:text-primary transition-colors underline-offset-2 hover:underline"
                >
                  CoinDesk, April 25 2026
                </a>
              </footer>
            </blockquote>
          </FadeIn>
        </section>

        {/* ═══════════════════════════
            THREE-LAYER THESIS — from §0 of litepaper
            ═══════════════════════════ */}
        <section className="mb-20">
          <FadeIn className="text-center mb-10">
            <p className="text-xs font-mono uppercase tracking-widest text-primary-light mb-3">
              The report has three layers
            </p>
            <h2 className="text-2xl md:text-3xl font-bold">Each answers a different question</h2>
          </FadeIn>

          <Stagger className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                badge: 'Layer 1',
                color: 'text-primary-light',
                glow: 'hover:shadow-[0_0_30px_rgba(13,148,136,0.15)]',
                borderAccent: 'hover:border-primary/40',
                title: 'What we found',
                question: 'Is the agent infrastructure shipping today actually safe?',
                body: 'Scan data across x402 Bazaar, OpenClaw, MCP Registry, npm/PyPI agent packages, and a sample of AI-generated Solidity from Microsoft-backed Dreamspace. The pattern is consistent across surfaces.',
                ref: '§1',
              },
              {
                badge: 'Layer 2',
                color: 'text-accent',
                glow: 'hover:shadow-[0_0_30px_rgba(232,121,249,0.12)]',
                borderAccent: 'hover:border-accent/40',
                title: 'What good looks like',
                question: 'How do we make this verifiable across implementations?',
                body: 'CTEF v0.3.1 frozen, 5-way byte-match validated across two languages. A2A WG Proposal #1786 in Proposal Phase. Eight independent collaborators with shipped artifacts.',
                ref: '§3',
              },
              {
                badge: 'Layer 3',
                color: 'text-warning',
                glow: 'hover:shadow-[0_0_30px_rgba(245,158,11,0.12)]',
                borderAccent: 'hover:border-warning/40',
                title: 'Why this matters now',
                question: 'Why should this hit my desk this week?',
                body: 'Alchemy + Coinbase x402 + Microsoft/Dreamspace + Frequency/DSNP collide on the same April 2026 news cycle. The trust gate between agent infra and the standards substrate does not yet exist.',
                ref: '§0',
              },
            ].map((card) => (
              <StaggerItem key={card.badge}>
                <div
                  className={`relative h-full bg-surface border border-border rounded-2xl p-6 transition-shadow duration-500 ${card.glow} ${card.borderAccent}`}
                >
                  <div
                    className={`text-[10px] font-mono font-bold tracking-widest mb-3 ${card.color}`}
                  >
                    {card.badge.toUpperCase()} &middot; {card.ref}
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{card.title}</h3>
                  <p className="text-sm text-text italic mb-3">&ldquo;{card.question}&rdquo;</p>
                  <p className="text-sm text-text-muted leading-relaxed">{card.body}</p>
                </div>
              </StaggerItem>
            ))}
          </Stagger>
        </section>

        {/* ═══════════════════════════
            SCAN DATA TABLE — Layer 1
            ═══════════════════════════ */}
        <section className="mb-20">
          <SectionAnchor id="layer-1" />
          <FadeIn className="mb-6">
            <p className="text-xs font-mono uppercase tracking-widest text-primary-light mb-2">
              Layer 1 &middot; §1 — What we found
            </p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">
              Five distribution surfaces, scanned April 21–28
            </h2>
            <p className="text-sm text-text-muted leading-relaxed max-w-3xl">
              Every scan output is signed (JWS, RFC 7515) and verifiable against the public JWKS
              at <code className="text-primary-light text-xs">/.well-known/jwks.json</code>. Live
              data injection happens as scans complete; placeholder cells below get replaced when
              their surface finishes scanning.
            </p>
          </FadeIn>

          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl overflow-hidden">
              {/* Desktop table */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-surface-hover/40 border-b border-border">
                    <tr>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Surface
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Targets
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Critical findings
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Avg trust
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {SCAN_ROWS.map((row) => (
                      <tr key={row.surface} className="border-b border-border last:border-b-0">
                        <td className="px-5 py-4 align-top">
                          <div className="font-semibold text-text">{row.surface}</div>
                          <div className="text-xs text-text-muted mt-0.5">{row.description}</div>
                        </td>
                        <td className="px-5 py-4 align-top">
                          <ScanCell testId={`${row.testId}-targets`} label={row.targetsLabel} />
                        </td>
                        <td className="px-5 py-4 align-top">
                          <ScanCell testId={`${row.testId}-critical`} label={row.criticalLabel} />
                        </td>
                        <td className="px-5 py-4 align-top">
                          <ScanCell testId={`${row.testId}-trust`} label={row.trustLabel} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile stack */}
              <div className="md:hidden divide-y divide-border">
                {SCAN_ROWS.map((row) => (
                  <div key={row.surface} className="p-4">
                    <div className="font-semibold text-text">{row.surface}</div>
                    <div className="text-xs text-text-muted mt-0.5 mb-3">{row.description}</div>
                    <dl className="grid grid-cols-3 gap-2 text-xs">
                      <div>
                        <dt className="text-text-muted uppercase tracking-wider text-[10px] mb-0.5">
                          Targets
                        </dt>
                        <dd>
                          <ScanCell
                            testId={`${row.testId}-targets-mobile`}
                            label={row.targetsLabel}
                          />
                        </dd>
                      </div>
                      <div>
                        <dt className="text-text-muted uppercase tracking-wider text-[10px] mb-0.5">
                          Critical
                        </dt>
                        <dd>
                          <ScanCell
                            testId={`${row.testId}-critical-mobile`}
                            label={row.criticalLabel}
                          />
                        </dd>
                      </div>
                      <div>
                        <dt className="text-text-muted uppercase tracking-wider text-[10px] mb-0.5">
                          Avg trust
                        </dt>
                        <dd>
                          <ScanCell
                            testId={`${row.testId}-trust-mobile`}
                            label={row.trustLabel}
                          />
                        </dd>
                      </div>
                    </dl>
                  </div>
                ))}
              </div>
            </div>
          </FadeIn>
        </section>

        {/* ═══════════════════════════
            5-WAY BYTE-MATCH — §3.8
            ═══════════════════════════ */}
        <section className="mb-20">
          <SectionAnchor id="layer-2" />
          <FadeIn className="mb-6">
            <p className="text-xs font-mono uppercase tracking-widest text-accent mb-2">
              Layer 2 &middot; §3.8 — Cross-implementation interop receipts
            </p>
            <h2 className="text-2xl md:text-3xl font-bold mb-3">
              CTEF v0.3.1: byte-match-validated across 5 implementations, 2 languages
            </h2>
            <p className="text-sm text-text-muted leading-relaxed max-w-3xl">
              Three independent Python canonicalizers + one independent TypeScript canonicalizer
              producing byte-identical output against the published fixtures. RFC 8785 JCS proves
              language-agnostic in practice, not just by design. Any one-sided drift fires against
              three witnesses.
            </p>
          </FadeIn>

          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl overflow-hidden">
              {/* Desktop */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-surface-hover/40 border-b border-border">
                    <tr>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Implementation
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Maintainer
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        Language
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        JCS byte-match
                      </th>
                      <th className="text-left px-5 py-3 font-semibold text-text-muted text-xs uppercase tracking-wider">
                        claim_type live
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {INTEROP_ROWS.map((row) => (
                      <tr
                        key={row.implementation}
                        className="border-b border-border last:border-b-0"
                      >
                        <td className="px-5 py-4 font-semibold text-text align-top">
                          {row.implementation}
                        </td>
                        <td className="px-5 py-4 text-text-muted align-top">{row.maintainer}</td>
                        <td className="px-5 py-4 align-top">
                          <span
                            className={`inline-block text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                              row.language === 'TypeScript'
                                ? 'bg-accent/15 text-accent'
                                : 'bg-primary/15 text-primary-light'
                            }`}
                          >
                            {row.language}
                          </span>
                        </td>
                        <td className="px-5 py-4 text-text-muted text-xs leading-relaxed align-top">
                          {row.byteMatch}
                        </td>
                        <td className="px-5 py-4 text-text-muted text-xs leading-relaxed align-top">
                          {row.claimTypeLive}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Mobile stack */}
              <div className="md:hidden divide-y divide-border">
                {INTEROP_ROWS.map((row) => (
                  <div key={row.implementation} className="p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-semibold text-text">{row.implementation}</span>
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full ${
                          row.language === 'TypeScript'
                            ? 'bg-accent/15 text-accent'
                            : 'bg-primary/15 text-primary-light'
                        }`}
                      >
                        {row.language}
                      </span>
                    </div>
                    <div className="text-xs text-text-muted mb-3">{row.maintainer}</div>
                    <dl className="space-y-2 text-xs">
                      <div>
                        <dt className="text-text-muted uppercase tracking-wider text-[10px] mb-0.5">
                          JCS byte-match
                        </dt>
                        <dd className="text-text-muted leading-relaxed">{row.byteMatch}</dd>
                      </div>
                      <div>
                        <dt className="text-text-muted uppercase tracking-wider text-[10px] mb-0.5">
                          claim_type live
                        </dt>
                        <dd className="text-text-muted leading-relaxed">{row.claimTypeLive}</dd>
                      </div>
                    </dl>
                  </div>
                ))}
              </div>
            </div>
          </FadeIn>

          <FadeIn className="mt-4">
            <p className="text-xs text-text-muted leading-relaxed">
              Plus <span className="text-text">lawcontinue</span> (245-step distributed-inference
              fixture for v0.3.2 long-session worked example),{' '}
              <span className="text-text">Vorim AI</span> (IETF{' '}
              <code className="text-primary-light">draft-vorim-vaip-00</code>) onboarding as a
              sixth implementation, and <span className="text-text">Concordia v1.0.0</span> (Erik
              Newton, Verascore) fixtures landing via PR #10 with 131/131 checks.
            </p>
          </FadeIn>
        </section>

        {/* ═══════════════════════════
            CO-SIGNERS (text-list per scope)
            ═══════════════════════════ */}
        <section className="mb-20">
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6 md:p-7">
              <p className="text-xs font-mono uppercase tracking-widest text-primary-light mb-3">
                Co-signers &middot; documented public spec collaboration
              </p>
              <p className="text-sm text-text-muted leading-relaxed">
                {COSIGNERS.join(' · ')}
              </p>
            </div>
          </FadeIn>
        </section>

        {/* ═══════════════════════════
            LEAD CAPTURE
            ═══════════════════════════ */}
        <section className="mb-20">
          <FadeIn>
            <div className="relative bg-surface border border-primary/20 rounded-2xl p-8 md:p-10 overflow-hidden">
              <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-primary via-accent to-warning rounded-l-2xl" />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center pl-3">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Get the next quarterly update</h2>
                  <p className="text-sm text-text-muted leading-relaxed">
                    <em>State of Agent Security Q3 2026</em> drops August 12. New scan corpus,
                    spec progress, and CTEF v0.3.3 / v0.4 deltas. One email per quarter, no list spam.
                  </p>
                </div>

                <form onSubmit={handleSignup} className="flex flex-col sm:flex-row gap-2">
                  <label htmlFor="launch-email" className="sr-only">
                    Email address
                  </label>
                  <input
                    id="launch-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    disabled={signupState === 'submitting' || signupState === 'ok'}
                    className="flex-1 bg-background border border-border rounded-xl px-4 py-3 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-primary/60 transition-colors disabled:opacity-50"
                  />
                  <button
                    type="submit"
                    disabled={signupState === 'submitting' || signupState === 'ok'}
                    className="bg-gradient-to-r from-primary to-primary-dark text-white px-6 py-3 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 disabled:opacity-60 disabled:cursor-not-allowed whitespace-nowrap"
                  >
                    {signupState === 'submitting'
                      ? 'Submitting...'
                      : signupState === 'ok'
                        ? 'Subscribed ✓'
                        : 'Subscribe'}
                  </button>
                </form>
              </div>

              {signupState === 'ok' && (
                <p className="text-xs text-success mt-3 pl-3">
                  Thanks — you&apos;ll hear from us when Q3 2026 ships.
                </p>
              )}
              {signupState === 'error' && signupError && (
                <p className="text-xs text-danger mt-3 pl-3">Couldn&apos;t submit: {signupError}</p>
              )}
            </div>
          </FadeIn>
        </section>

        {/* ═══════════════════════════
            METHODOLOGY ANCHOR + FOOTER LINKS
            ═══════════════════════════ */}
        <section className="mb-12">
          <SectionAnchor id="methodology" />
          <FadeIn>
            <div className="bg-surface border border-border rounded-2xl p-6 md:p-7">
              <p className="text-xs font-mono uppercase tracking-widest text-primary-light mb-3">
                Methodology
              </p>
              <p className="text-sm text-text-muted leading-relaxed mb-3">
                Every number reproducible. Pull the live test vectors. Run a JCS canonicalizer
                (RFC 8785). Verify the SHA-256s match. Fail-closed on the negative-path vectors.
                There is no AgentAvow-private side channel.
              </p>
              <p className="text-sm text-text-muted leading-relaxed mb-4">
                Scans run between April 21–28, 2026. Every scan attestation is signed with Ed25519
                (JWS, RFC 7515) and verifiable against the public JWKS endpoint. Dreamspace
                generation used non-adversarial prompts only; generated Solidity was archived but
                never deployed to Base mainnet.
              </p>
              <Link
                to="/scans"
                className="inline-flex items-center gap-2 text-sm text-primary-light hover:text-primary transition-colors font-mono"
              >
                Browse all 35,689 scans →
              </Link>
              <p className="text-xs text-text-muted mt-2">
                Living record. Every row reproducible. Not a frozen PDF.
              </p>
            </div>
          </FadeIn>
        </section>

        <footer className="border-t border-border pt-8 mt-8">
          <FadeIn>
            <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-3 text-sm">
              <a
                href="https://github.com/AgentAvow/AgentAvow"
                target="_blank"
                rel="noopener noreferrer"
                className="text-text-muted hover:text-primary-light transition-colors"
              >
                GitHub
              </a>
              <a
                href="https://github.com/a2aproject/A2A/issues/1786"
                target="_blank"
                rel="noopener noreferrer"
                className="text-text-muted hover:text-primary-light transition-colors"
              >
                A2A WG #1786
              </a>
              <a
                href="https://agentgraph.co/.well-known/cte-test-vectors.json"
                target="_blank"
                rel="noopener noreferrer"
                className="text-text-muted hover:text-primary-light transition-colors"
              >
                CTEF test vectors
              </a>
              <a
                href="#methodology"
                className="text-text-muted hover:text-primary-light transition-colors"
              >
                Methodology
              </a>
              <Link to="/check" className="text-text-muted hover:text-primary-light transition-colors">
                /check
              </Link>
              <Link to="/scans" className="text-text-muted hover:text-primary-light transition-colors">
                /scans (catalog)
              </Link>
            </div>
          </FadeIn>
        </footer>
      </div>
    </PageTransition>
  )
}
