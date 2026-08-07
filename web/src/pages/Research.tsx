/**
 * Research hub — chronological index of AgentGraph research outputs.
 *
 * First entry: State of Agent Security 2026 (May 12, 2026).
 * Future entries (Q3 2026 / Q4 2026 / etc.) slot in as published.
 */

import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import SEOHead from '../components/SEOHead'
import { FadeIn, Stagger, StaggerItem, PageTransition } from '../components/Motion'

interface ReportEntry {
  title: string
  subtitle: string
  date: string
  status: 'live' | 'upcoming' | 'archived'
  path?: string
  pdf?: string
  body: string
  signals?: string[]
}

const REPORTS: ReportEntry[] = [
  {
    title: 'State of Agent Security 2026',
    subtitle: 'Q2 2026 — agent distribution surfaces + CTEF v0.3.1 substrate',
    date: 'May 12, 2026',
    status: 'live',
    path: '/state-of-agent-security-2026',
    pdf: '/state-of-agent-security-2026-v1.pdf',
    body:
      'Scan data across x402 Bazaar, OpenClaw, MCP Registry, npm/PyPI agent packages, and a sample of AI-generated Solidity from Microsoft-backed Dreamspace. Critical/high findings rates ranged from 31% (PyPI sample) to 82.6% (npm sample); 55.3% on the official MCP Registry; 1-in-3 OpenClaw skill repositories scoring an F. Includes the 8-implementation byte-match conformance set for the CTEF v0.3.1 wire format.',
    signals: [
      '8 byte-match validated implementations',
      '7 independent canonicalizers',
      '2 reader-runnable verifier scripts',
      'A2A WG Proposal #1786 (Proposal Phase)',
    ],
  },
  {
    title: 'State of Agent Security Q3 2026',
    subtitle: 'Coming August 12, 2026',
    date: 'Q3 2026',
    status: 'upcoming',
    body:
      'Next quarterly update. New scan corpus (HuggingFace Spaces, LangChain Hub, CrewAI marketplace, AutoGen), CTEF v0.3.2 + v0.3.3 deltas, multi-provider aggregation pipeline results, ERC-8004 binding profile field data.',
  },
]

export default function Research() {
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
        body: JSON.stringify({ email: email.trim(), source: 'research-hub' }),
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
        title="Research"
        description="AgentGraph research on agent identity, trust, and security. Quarterly reports with reproducible methodology and verifiable scan attestations."
        path="/research"
      />

      <div className="max-w-4xl mx-auto px-4 pt-16 pb-24">
        <section className="text-center mb-14">
          <FadeIn delay={0.1}>
            <p className="text-xs font-mono uppercase tracking-widest text-primary-light mb-3">
              Research
            </p>
          </FadeIn>
          <FadeIn delay={0.2}>
            <h1 className="text-4xl md:text-5xl font-extrabold leading-[1.1] tracking-tight mb-6">
              <span className="gradient-text">Quarterly research</span>
              <br />
              <span className="text-text">on agent identity, trust, and security</span>
            </h1>
          </FadeIn>
          <FadeIn delay={0.35}>
            <p className="text-lg text-text-muted max-w-2xl mx-auto leading-relaxed font-light">
              Reproducible methodology. Verifiable scan attestations. Cross-implementation
              substrate validation. Every number reproducible against the public test vectors.
            </p>
          </FadeIn>
        </section>

        <Stagger className="space-y-6 mb-16">
          {REPORTS.map((report) => (
            <StaggerItem key={report.title}>
              <article
                className={`relative bg-surface border rounded-2xl p-6 md:p-8 transition-all ${
                  report.status === 'live'
                    ? 'border-primary/30 hover:border-primary/50 hover:shadow-[0_0_30px_rgba(13,148,136,0.15)]'
                    : 'border-border/60 opacity-90'
                }`}
              >
                <div className="flex items-start justify-between gap-4 mb-3 flex-wrap">
                  <div>
                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                      <span
                        className={`text-[10px] font-mono uppercase tracking-widest px-2 py-1 rounded-full ${
                          report.status === 'live'
                            ? 'bg-primary/15 text-primary-light border border-primary/30'
                            : 'bg-surface border border-border text-text-muted'
                        }`}
                      >
                        {report.status === 'live' ? 'Published' : 'Upcoming'}
                      </span>
                      <span className="text-xs text-text-muted font-mono">{report.date}</span>
                    </div>
                    <h2 className="text-2xl md:text-3xl font-bold mb-1">{report.title}</h2>
                    <p className="text-sm text-text-muted">{report.subtitle}</p>
                  </div>
                </div>

                <p className="text-sm md:text-base text-text leading-relaxed mt-4 mb-5">
                  {report.body}
                </p>

                {report.signals && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mb-6">
                    {report.signals.map((signal) => (
                      <div
                        key={signal}
                        className="flex items-center gap-2 text-xs text-text-muted bg-background/50 border border-border/40 rounded-lg px-3 py-2"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-primary-light flex-shrink-0" />
                        <span>{signal}</span>
                      </div>
                    ))}
                  </div>
                )}

                {report.status === 'live' && report.path && (
                  <div className="flex flex-col sm:flex-row gap-3 pt-2">
                    <Link
                      to={report.path}
                      className="bg-gradient-to-r from-primary to-primary-dark text-white px-5 py-2.5 rounded-xl text-sm font-semibold shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 transition-all"
                    >
                      Read the report
                    </Link>
                    {report.pdf && (
                      <a
                        href={report.pdf}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="bg-surface border border-border text-text px-5 py-2.5 rounded-xl text-sm font-semibold hover:border-primary/50 transition-colors text-center"
                      >
                        Download PDF
                      </a>
                    )}
                  </div>
                )}
              </article>
            </StaggerItem>
          ))}
        </Stagger>

        <section id="subscribe" className="mb-12">
          <FadeIn>
            <div className="relative bg-surface border border-primary/20 rounded-2xl p-8 md:p-10 overflow-hidden">
              <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-primary via-accent to-warning rounded-l-2xl" />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center pl-3">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Subscribe to quarterly updates</h2>
                  <p className="text-sm text-text-muted leading-relaxed">
                    One email per quarter when a new report ships. No list spam — research only.
                  </p>
                </div>
                <form onSubmit={handleSignup} className="flex flex-col sm:flex-row gap-2">
                  <label htmlFor="research-email" className="sr-only">
                    Email address
                  </label>
                  <input
                    id="research-email"
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
                    className="bg-gradient-to-r from-primary to-primary-dark text-white px-6 py-3 rounded-xl text-sm font-semibold shadow-lg shadow-primary/20 hover:shadow-xl hover:shadow-primary/30 disabled:opacity-60 disabled:cursor-not-allowed whitespace-nowrap"
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
                  Thanks — you&apos;ll hear from us when the next report ships.
                </p>
              )}
              {signupState === 'error' && signupError && (
                <p className="text-xs text-danger mt-3 pl-3">Couldn&apos;t submit: {signupError}</p>
              )}
            </div>
          </FadeIn>
        </section>

        <section className="text-center">
          <FadeIn>
            <p className="text-sm text-text-muted">
              Want to contribute methodology, a fixture set, or a cross-implementation
              comparison?{' '}
              <a
                href="https://github.com/AgentAvow/AgentAvow"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary-light hover:text-primary transition-colors"
              >
                Open an issue on GitHub
              </a>
              .
            </p>
          </FadeIn>
        </section>
      </div>
    </PageTransition>
  )
}
