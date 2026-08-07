import { Helmet } from 'react-helmet-async'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

/**
 * AgentAvow FAQ — tool-safety relevant, with FAQPage structured data for SEO
 * (Google rich results). Replaces the old social-era FAQ.
 */

interface QA { q: string; a: string }
interface Section { title: string; items: QA[] }

const SECTIONS: Section[] = [
  {
    title: 'About AgentAvow',
    items: [
      { q: 'What is AgentAvow?', a: 'AgentAvow gives any tool, MCP server, or package a signed, verifiable safety grade — so you know whether it\'s safe for your AI agent to connect to. Paste a URL, get a letter grade backed by scan evidence anyone can recompute.' },
      { q: 'Is AgentAvow free?', a: 'Yes. Checking any tool is free and requires no account. An account is only needed to watch tools for change-alerts, manage API keys, or claim repositories you own.' },
      { q: 'Do I need an account to use it?', a: 'No. Checking a tool and browsing the catalog are free and anonymous — no signup, no tracking required to get a result.' },
    ],
  },
  {
    title: 'The scan & the score',
    items: [
      { q: 'How does the scan work?', a: 'We read the actual source code across 12 safety categories — exposed secrets, unsafe code execution, data handling, filesystem and network access, prompt-injection surfaces, obfuscation, and dependency health — and produce a letter grade plus a signed attestation.' },
      { q: 'What does the grade mean?', a: 'An A–F letter grade mapped from a 0–100 score; higher is safer. It reflects a scan at a point in time — tools can change after they\'re scanned, so watch anything you depend on.' },
      { q: 'What are the two scores — Attestation Trust and Adoption?', a: 'Attestation Trust is the signed safety grade from our scanner (verifiable now). Adoption reflects how much the ecosystem actually uses a tool — real usage like stars, checks, and watchers, not opinions.' },
    ],
  },
  {
    title: 'Verification & trust',
    items: [
      { q: 'What makes the grade "verifiable"?', a: 'Every result is signed with Ed25519 (JWS). You can verify any attestation offline against our public keys — no call back to us required. If a single byte of the grade is altered, verification fails. It\'s a signature, not just a badge.' },
      { q: 'How do I verify a grade myself?', a: 'Use the live verification tool on the How-it-works page, or check any attestation against our public JWKS. The evidence format and conformance vectors are published and versioned in the open.' },
    ],
  },
  {
    title: 'For developers',
    items: [
      { q: 'How do I add a trust badge to my README?', a: 'Check your repo and copy one line of Markdown. The badge regenerates on every view (never stale), is signed, and links back to a full, verifiable report — no account needed to mint one.' },
      { q: 'Is there an API, SDK, or GitHub Action?', a: 'Yes — a REST API, a Python SDK/CLI, and a GitHub Action that can gate pull requests on a minimum grade. See the developer page and docs.' },
      { q: 'Can I scan a private repo?', a: 'Yes. Claim the repository to unlock private scans (verify ownership with a GitHub topic — no token stored), or scan with a token you supply that\'s used transiently and never persisted.' },
    ],
  },
  {
    title: 'Account & watching',
    items: [
      { q: 'What does "watching" a tool do?', a: 'We re-scan the tools you watch and alert you — by email, in-app, or webhook — the moment a grade drops or a signed definition changes. That\'s the rug-pull you\'d otherwise miss.' },
      { q: 'How do I claim a tool I own?', a: 'Add a GitHub topic we give you to the repo to prove ownership. A verified claim unlocks a fix-it report, the ability to respond to findings, private scans, and control over how the tool appears.' },
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
  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <Helmet>
        <title>FAQ — AgentAvow</title>
        <meta name="description" content="Frequently asked questions about AgentAvow — signed, verifiable safety grades for the tools your AI agents connect to." />
        <script type="application/ld+json">{JSON.stringify(FAQ_JSONLD)}</script>
      </Helmet>

      <Reveal>
        <div className="max-w-[60ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">FAQ</span>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">Questions, answered.</h1>
          <p className="mt-3 text-text-muted">Everything about checking tools, verifying grades, and staying safe over time.</p>
        </div>
      </Reveal>

      {SECTIONS.map((s) => (
        <Reveal key={s.title}>
          <section className="mt-10">
            <h2 className="text-[13px] font-mono uppercase tracking-wide text-primary-light mb-3">{s.title}</h2>
            <div className="flex flex-col gap-2.5">
              {s.items.map((i) => (
                <details key={i.q} className="glass rounded-xl px-5 py-4 group">
                  <summary className="cursor-pointer list-none flex items-center justify-between gap-3 font-semibold text-[15px]">
                    {i.q}
                    <span className="text-text-muted group-open:rotate-45 transition-transform text-lg leading-none">+</span>
                  </summary>
                  <p className="mt-3 text-text-muted text-[14px] leading-relaxed">{i.a}</p>
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
