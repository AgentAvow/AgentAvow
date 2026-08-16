import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal, RevealStagger } from '../components/motion'
import { TrustBar, AdoptionNeedle } from '../components/TrustMark'
import { VerifyDemo } from '../components/VerifyDemo'

/**
 * How it works — the transparency page. Explains the aggregate-over-signed-evidence
 * score ("Rotten Tomatoes for agent trust"), offline verification (the home for
 * Verify), the 12 categories, and the open standards / partner interop work. On a
 * trust product, publishing the methodology is the point — not something to hide.
 */

const CATEGORIES = [
  ['Secret hygiene', 'Exposed API keys, tokens, and credentials in the code.'],
  ['Code safety', 'Unsafe execution — shell-outs, eval, dynamic code paths.'],
  ['Data handling', 'Where your data goes and how it\'s treated.'],
  ['Filesystem access', 'What files it can read and write, and whether that\'s scoped.'],
  ['Network & exfiltration', 'Calls out to external hosts that could leak data.'],
  ['Prompt injection', 'Surfaces where a malicious input could hijack the agent.'],
  ['Obfuscation', 'Hidden or deliberately unreadable payloads.'],
  ['Dependency health', 'Outdated or known-vulnerable dependencies.'],
]

const STANDARDS = [
  ['Safety Model spec (v1)', 'Exactly how a scan composes into the 0–100 score, the tiers, and the Certified gate — the model published separately from the code, so anyone can recompute a score from the same findings.', 'https://github.com/AgentAvow/AgentAvow/blob/main/docs/standards/agentavow-safety-model-v1.md'],
  ['Tool manifest — .agentavow.yml', 'Declare the hosts your tool contacts and the capabilities it uses; the sandbox holds it to its own declaration. Undeclared egress is a finding.', 'https://github.com/AgentAvow/AgentAvow/blob/main/docs/standards/agentavow-manifest-v0.md'],
  ['CTEF — Cryptographic Trust Evidence Format', 'The signed, reproducible evidence envelope any implementer can recompute byte-for-byte. Versioned in the open.', 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards'],
  ['Published test vectors', 'Conformance vectors served at /.well-known so anyone can validate their own implementation against ours.', 'https://agentgraph.co/.well-known/cte-test-vectors.json'],
  ['ERC-8004 bridge', 'Interop with the on-chain agent-trust registry standard.', 'https://github.com/AgentAvow/AgentAvow/tree/main/src/agentgraph_bridge_erc8004'],
  ['AIPOU cross-fixture', 'A shared conformance fixture proving two independent implementations agree.', 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/conformance'],
  ['MCP & AIP bridges', 'Adapters so the trust layer plugs into the frameworks agents already use.', 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/protocol'],
]

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">{children}</span>
}

export default function RebrandHowItWorks() {
  return (
    <div className="max-w-[880px] mx-auto px-6 py-16">
      <Reveal>
        <div className="max-w-[62ch]">
          <Eyebrow>How it works</Eyebrow>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">A trust score you don't have to trust.</h1>
          <p className="mt-3 text-text-muted text-[15.5px] leading-relaxed">
            Most "trust scores" are a black box — you take the number on faith. Ours is different: it's an
            <strong className="text-text"> aggregate over signed evidence</strong>. The score is one recognizable, portable
            number, but underneath sits a cryptographic receipt anyone can recompute and verify.
          </p>
        </div>
      </Reveal>

      {/* the two-axis score */}
      <Reveal>
        <div className="mt-10 glass rounded-2xl p-7">
          <h2 className="text-xl font-bold">Two axes, one signed record.</h2>
          <p className="mt-2 text-text-muted text-[14px] max-w-[62ch]"><strong className="text-text">Attestation Trust</strong> is the signed safety score from our scanner — live and verifiable now. <strong className="text-text">Adoption</strong> reflects how much the ecosystem actually uses a tool. Together they tell you both "is it safe?" and "is it real?"</p>
          <div className="mt-5 rounded-xl border border-border/60 bg-surface/30 overflow-hidden relative">
            {/* specimen framing — an illustrative example, distinct from the live readout on a score page */}
            <div className="flex items-center justify-between px-4 py-2 border-b border-border/50 bg-surface/40">
              <span className="font-mono text-[10px] uppercase tracking-[0.16em] text-text-muted">Example — a widely-used, safe tool</span>
              <span className="font-mono text-[10px] text-text-muted/70">illustrative</span>
            </div>
            <div className="grid grid-cols-2 relative">
              <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(340px 130px at 25% 0%, rgba(34,197,94,0.10), transparent 70%), radial-gradient(340px 130px at 78% 0%, rgba(45,212,191,0.10), transparent 70%)' }} />
              <div className="relative p-6 text-center flex flex-col items-center border-r border-border/50">
                <div className="min-h-[132px] flex items-center justify-center"><TrustBar score={94} /></div>
                <div className="mt-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-success">Attestation Trust</div>
              </div>
              <div className="relative p-6 text-center flex flex-col items-center">
                <div className="min-h-[132px] flex items-center justify-center"><AdoptionNeedle count={12400} unit="stars" /></div>
                <div className="mt-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] gradient-text">Adoption</div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* pipeline */}
      <Reveal>
        <h2 className="mt-12 text-xl font-bold">Paste → scan → sign.</h2>
      </Reveal>
      <RevealStagger className="grid md:grid-cols-3 gap-3 mt-4" stagger={0.06}>
        {[
          ['01', 'You paste a URL', 'A repo, MCP server, npm/PyPI package, or skill. No signup, no install.'],
          ['02', 'We read the actual code', 'Not metadata or self-claims — the real source, across the categories below.'],
          ['03', 'You get a signed score', 'A 0–100 trust score plus a cryptographic attestation you can verify offline.'],
        ].map(([n, h, p]) => (
          <div key={n} className="glass rounded-xl p-5">
            <div className="font-mono text-[12px] text-primary-light">{n}</div>
            <h3 className="mt-2 text-[16px] font-semibold">{h}</h3>
            <p className="mt-1.5 text-text-muted text-[13.5px]">{p}</p>
          </div>
        ))}
      </RevealStagger>

      {/* run it yourself — local / CI */}
      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
          <div className="flex items-baseline justify-between gap-3 flex-wrap">
            <h3 className="text-[16px] font-bold">Or run it in CI — on private code.</h3>
            <span className="font-mono text-[11px] text-text-muted">same engine · same score · offline</span>
          </div>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch] leading-relaxed">
            The exact scanner runs in your own runner or terminal, so a <strong className="text-text">private repo</strong> never
            leaves your machine. Gate a PR on a minimum score and get findings as inline annotations — the signed attestation
            is the one part that stays with us.
          </p>
          <pre className="mt-3 font-mono text-[12.5px] bg-surface border border-border rounded-xl px-4 py-3 text-text overflow-x-auto">{`# CI (private repos, runs in the runner)
- uses: AgentAvow/AgentAvow/local-scan-action@main
  with: { min-score: "60" }

# or locally
agentavow scan . --min-score 60`}</pre>
          <Link to={rp('/rebrand/docs/run-locally')} className="inline-block mt-3 text-[13.5px] font-semibold text-primary-light hover:text-primary">Run locally &amp; in CI →</Link>
        </div>
      </Reveal>

      {/* categories */}
      <Reveal>
        <h2 className="mt-12 text-xl font-bold">What we check</h2>
        <p className="mt-1.5 text-text-muted text-[14px] max-w-[62ch]">The engine runs <strong className="text-text">12 detection categories</strong> — a score page shows the ones that applied to that surface. The main ones:</p>
      </Reveal>
      <RevealStagger className="grid sm:grid-cols-2 gap-2.5 mt-4" stagger={0.03}>
        {CATEGORIES.map(([h, p]) => (
          <div key={h} className="glass rounded-xl px-4 py-3">
            <div className="text-[14.5px] font-semibold">{h}</div>
            <div className="text-[13px] text-text-muted mt-0.5">{p}</div>
          </div>
        ))}
      </RevealStagger>

      {/* verify — the home for Verify */}
      <Reveal>
        <div id="verify" className="mt-12 glass rounded-2xl p-7 border-l-4 border-primary/60">
          <Eyebrow>Verify</Eyebrow>
          <h2 className="mt-2 text-xl font-bold">Every score is signed. Verify it offline.</h2>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch] leading-relaxed">
            Each result is signed with Ed25519 (JWS). You can verify any attestation against our public keys — no call
            back to us required. If a single byte of the score is altered, verification fails. That's what makes this a
            <strong className="text-text"> signature, not just a badge</strong>: you don't have to trust AgentAvow, you can check the math.
          </p>
          <div className="mt-4 flex gap-4 flex-wrap">
            <a href="https://agentgraph.co/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Public keys (JWKS) ↗</a>
            <a href="https://agentgraph.co/.well-known/cte-test-vectors.json" target="_blank" rel="noopener noreferrer" className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Test vectors ↗</a>
          </div>
        </div>
      </Reveal>

      {/* live, real verification */}
      <Reveal><div className="mt-4"><VerifyDemo /></div></Reveal>

      {/* standards & partners */}
      <Reveal>
        <div className="mt-12">
          <Eyebrow>Built in the open</Eyebrow>
          <h2 className="mt-2 text-xl font-bold">Open standards & interoperability</h2>
          <p className="mt-2 text-text-muted text-[14px] max-w-[62ch]">The evidence format and conformance vectors are public and versioned, developed alongside the wider agent-trust standards community. Reproducibility across independent implementations is the whole point.</p>
        </div>
      </Reveal>
      <RevealStagger className="flex flex-col gap-2.5 mt-4" stagger={0.04}>
        {STANDARDS.map(([h, p, href]) => (
          <a key={h} href={href} target="_blank" rel="noopener noreferrer" className="glass card-hover rounded-xl px-5 py-4 block">
            <div className="flex items-center justify-between gap-3">
              <div className="text-[15px] font-semibold">{h}</div>
              <span className="text-primary-light text-[13px] shrink-0">↗</span>
            </div>
            <div className="text-[13.5px] text-text-muted mt-1">{p}</div>
          </a>
        ))}
      </RevealStagger>

      <Reveal>
        <div className="mt-12 text-center">
          <Link to={rp("/rebrand/check")} className="inline-block font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Check a tool now →</Link>
        </div>
      </Reveal>
    </div>
  )
}
