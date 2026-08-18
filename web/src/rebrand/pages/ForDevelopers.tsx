import { useState } from 'react'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal, RevealStagger } from '../components/motion'

/**
 * The developer one-pager — the single conversion destination the whole
 * developer-adoption motion funnels to (badge PRs, registry claims, hackathons,
 * the LinkedIn post). Answers a tool author's three questions in one scroll:
 * why me · what do I do · how do I show it. Keeps /badge as the interactive
 * minting tool this page links to.
 */

const BADGE_MD = '[![AgentAvow Trust](https://agentavow.com/api/v1/public/scan/you/your-repo/badge)](https://agentavow.com/check/you/your-repo)'

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

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">{children}</span>
}

export default function RebrandForDevelopers() {
  const [copied, setCopied] = useState(false)
  const [copiedSnip, setCopiedSnip] = useState(false)
  const copy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(BADGE_MD)
    setCopied(true); setTimeout(() => setCopied(false), 1400)
  }
  const copySnip = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(REGISTRY_SNIPPET)
    setCopiedSnip(true); setTimeout(() => setCopiedSnip(false), 1400)
  }

  return (
    <div className="max-w-[960px] mx-auto px-6 py-16">
      {/* hero — the thesis, aimed at the tool author */}
      <Reveal>
        <div className="max-w-[64ch]">
          <Eyebrow>For developers</Eyebrow>
          <h1 className="mt-3 text-3xl md:text-5xl font-extrabold tracking-tight leading-[1.05]">
            Ship a tool your users can trust — and <span className="gradient-text-bio">prove it</span>.
          </h1>
          <p className="mt-4 text-text-muted text-[16px] leading-relaxed">
            A <strong className="text-text">signed, offline-recomputable</strong> safety score for the MCP server,
            package, or agent tool you publish. Free, no account. Scan it, fix what it finds, and put a badge on
            your README that anyone — a developer reviewing a PR, or another agent about to connect — can
            <em>recompute and verify</em> in seconds against our public keys.
          </p>
          <div className="mt-6 flex gap-3 flex-wrap">
            <Link to={rp('/rebrand/check')} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Scan your tool →</Link>
            <Link to={rp('/rebrand/preflight')} className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Preflight for the app stores</Link>
            <Link to={rp('/rebrand/badge')} className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Mint a badge</Link>
          </div>
        </div>
      </Reveal>

      {/* 1 — why it's worth it (value to the developer) */}
      <Reveal>
        <h2 className="mt-16 text-xl font-bold">Why put a score on your tool</h2>
        <p className="mt-1.5 text-text-muted text-[14px] max-w-[62ch]">The badge is free credibility — and it works because it's the one score a skeptic can check for themselves.</p>
      </Reveal>
      <RevealStagger className="grid sm:grid-cols-2 gap-3 mt-5" stagger={0.05}>
        {[
          ['Verifiable, not "trust us"', 'Every score is signed (Ed25519) and recomputable offline against our public keys. A directory’s in-house number you take on faith; ours you can prove. That’s the difference that earns trust.'],
          ['Stand out in a crowded space', 'MCP servers and agent tools are multiplying. A signed high score is a real differentiator for a new project with no reputation yet — a trust signal to YOUR users.'],
          ['One score, everywhere your code lives', 'MCP server, npm, PyPI, GitHub repo, or skill — one recomputable score across all of them, that travels with the artifact instead of dying inside one directory.'],
          ['Actionable, not a black box', 'Score poorly and the report points at the exact file and line, with the fix. Score well and you get the badge. Either way you learn something.'],
        ].map(([h, p]) => (
          <div key={h} className="glass rounded-xl p-5 min-w-0">
            <div className="text-[15px] font-semibold">{h}</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">{p}</p>
          </div>
        ))}
      </RevealStagger>

      {/* 2 — get verified (3 steps) */}
      <Reveal>
        <h2 className="mt-16 text-xl font-bold">Get verified in three steps</h2>
      </Reveal>
      <RevealStagger className="grid md:grid-cols-3 gap-3.5 mt-5" stagger={0.06}>
        {[
          ['01', 'Scan', 'Free, no signup. Paste your repo/package at the check page, or run it locally:', 'agentavow scan .', rp('/rebrand/check')],
          ['02', 'Fix', 'The report lists each finding with the exact file, line, and a fix — plus a signed attestation of the result.', 'critical · high · medium', rp('/rebrand/docs/how-grading-works')],
          ['03', 'Earn & claim', 'Hit the bar and you earn the score — the top tier is Certified (a public, conjunctive gate, no cheating). Then claim your badge.', 'Score → Certified', rp('/rebrand/badge')],
        ].map(([n, h, p, code, href]) => (
          <Link key={n} to={href} className="glass card-hover rounded-xl p-5 block min-w-0">
            <div className="font-mono text-[12px] text-primary-light">{n}</div>
            <h3 className="mt-2 text-[16px] font-semibold">{h}</h3>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">{p}</p>
            <code className="inline-block mt-3 font-mono text-[11.5px] text-primary-light bg-surface px-2 py-1 rounded break-all">{code}</code>
          </Link>
        ))}
      </RevealStagger>
      <Reveal>
        <p className="mt-4 text-text-muted text-[13.5px] max-w-[64ch]">
          Prefer to keep it private? The same engine runs <strong className="text-text">in your own CI</strong> — a
          GitHub Action gates the build and uploads findings, and <code className="font-mono text-[12px] text-primary-light bg-surface px-1.5 py-0.5 rounded">agentavow scan .</code> runs
          fully offline. Nothing leaves your machine. <Link to={rp('/rebrand/docs/run-locally')} className="text-primary-light hover:text-primary">Run locally &amp; in CI →</Link>
        </p>
      </Reveal>

      {/* 3 — show it off (assets) */}
      <Reveal>
        <h2 className="mt-16 text-xl font-bold">Show it off</h2>
        <p className="mt-1.5 text-text-muted text-[14px] max-w-[62ch]">Assets that render your live score and link to the full signed report. All free, all update automatically.</p>
      </Reveal>
      <div className="mt-5 glass rounded-2xl p-6">
        <div className="font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">README badge — one line</div>
        <div className="relative">
          <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto whitespace-pre-wrap break-all">{BADGE_MD}</pre>
          <button onClick={copy} className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copied ? 'copied ✓' : 'copy'}</button>
        </div>
        <p className="mt-2 font-mono text-[11px] text-text-muted/70">swap in your own owner/repo — regenerates on every view, never goes stale</p>

        <div className="mt-6 font-mono text-[10.5px] uppercase tracking-wide text-text-muted mb-1.5">MCP registry — signed score in your server.json</div>
        <div className="relative">
          <pre className="font-mono text-[11.5px] bg-surface border border-border rounded-xl px-4 py-3.5 pr-16 text-text overflow-x-auto">{REGISTRY_SNIPPET}</pre>
          <button onClick={copySnip} className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copiedSnip ? 'copied ✓' : 'copy'}</button>
        </div>
        <p className="mt-2 font-mono text-[11px] text-text-muted/70">rides the <span className="text-text-muted">publisher-provided</span> <span className="text-text-muted">_meta</span> slot into the registry record — offline-recomputable, so a reviewer verifies it without trusting us. Live block: <span className="text-primary-light">/api/v1/public/registry-snippet/you/your-repo</span></p>

        <div className="mt-5 grid sm:grid-cols-2 gap-4">
          {[
            ['Embeddable widget', 'The full dual-mark card + an in-browser "Verify offline" button, for docs sites and landing pages — one script tag.', rp('/rebrand/badge')],
            ['Share / social card', 'A downloadable card of your score for a launch post, changelog, or slide.', rp('/rebrand/badge')],
            ['Signed report link', 'The full report + JWS attestation at agentavow.com/check/you/your-repo — verifiable offline against our JWKS.', rp('/rebrand/check')],
            ['The "Certified" mark', 'Earn the top tier through the public conjunctive gate and display the Certified treatment — the earned top tier.', rp('/rebrand/how-it-works')],
          ].map(([h, p, href]) => (
            <Link key={h} to={href} className="block rounded-xl border border-border/60 p-4 hover:border-primary-light/60 transition-colors">
              <div className="text-[14px] font-semibold">{h}</div>
              <div className="text-[13px] text-text-muted mt-0.5 leading-relaxed">{p}</div>
            </Link>
          ))}
        </div>
      </div>

      {/* CTA */}
      <Reveal>
        <div className="mt-16 text-center">
          <h2 className="text-2xl font-extrabold">Two minutes to a score your users can verify.</h2>
          <p className="mt-2 text-text-muted text-[14.5px] max-w-[52ch] mx-auto">Free, no account. Scan the tool you're about to publish — or one you already shipped.</p>
          <div className="mt-5 flex gap-3 justify-center flex-wrap">
            <Link to={rp('/rebrand/check')} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Scan your tool →</Link>
            <a href="https://github.com/AgentAvow/AgentAvow/tree/main/local-scan-action" target="_blank" rel="noopener noreferrer" className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Add the CI action ↗</a>
          </div>
        </div>
      </Reveal>
    </div>
  )
}
