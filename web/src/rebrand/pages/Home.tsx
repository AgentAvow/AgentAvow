import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'

/**
 * AgentAvow rebrand homepage (prototype).
 * The /check input IS the hero. Two-audience fork, honest proof, a live signed
 * result (Attestation Trust + Adoption), the Yelp browse teaser, the badge loop,
 * and the one earned account ask. Static content for now — see
 * docs/internal/rebrand-build-spec-and-loose-ends.md for the live-data wiring pass.
 */

const CHIPS = [
  'github.com/acme/mcp-server',
  'mcp://github-tools',
  'npm: agent-toolkit',
  'pypi: langchain-tools',
]

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">{children}</span>
}

export default function RebrandHome() {
  const [value, setValue] = useState('')
  const navigate = useNavigate()
  const go = () => navigate('/rebrand/check')

  return (
    <div>
      {/* ① HERO = the check itself */}
      <section className="text-center pt-16 pb-8 px-6">
        <div className="max-w-[1080px] mx-auto">
          <Eyebrow>Tool-counterparty safety</Eyebrow>
          <h1 className="mt-4 text-4xl sm:text-5xl md:text-6xl font-extrabold leading-[1.06] tracking-tight">
            Is this AI tool <span className="gradient-text-bio">safe</span> to connect?
          </h1>
          <p className="mt-5 mx-auto max-w-[50ch] text-lg text-text-muted font-light">
            Scan any tool, MCP server, or skill your agent connects to. Get a signed, verifiable safety grade
            in seconds — free, no signup.
          </p>

          <form
            onSubmit={(e) => { e.preventDefault(); go() }}
            className="glass mt-8 mx-auto max-w-[600px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10"
          >
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 self-center text-text-muted shrink-0">
              <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              aria-label="Check a tool"
              placeholder="github.com/owner/repo"
              className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15.5px] text-text placeholder:text-text-muted"
            />
            <button
              type="submit"
              className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow whitespace-nowrap"
            >
              Check
            </button>
          </form>

          <div className="mt-4 flex flex-wrap gap-2 justify-center">
            {CHIPS.map((c) => (
              <button
                key={c}
                onClick={() => setValue(c)}
                className="font-mono text-[12.5px] text-text-muted bg-surface border border-border rounded-full px-3 py-1.5 hover:border-primary-light hover:text-primary-light transition-colors"
              >
                {c}
              </button>
            ))}
          </div>
          <div className="mt-4">
            <Link to="/rebrand/browse" className="text-[14px] text-text-muted border-b border-border hover:text-primary-light hover:border-primary-light">
              or browse 35,000+ already-scanned tools →
            </Link>
          </div>
          <div className="mt-3.5 font-mono text-[12px] text-text-muted/70">
            no account · no install · signed result you can verify offline
          </div>
        </div>
      </section>

      {/* ② TWO-AUDIENCE FORK */}
      <section className="max-w-[1080px] mx-auto px-6 py-14">
        <div className="grid md:grid-cols-2 gap-4">
          <div className="glass card-hover rounded-2xl p-6 flex flex-col gap-2">
            <h3 className="text-lg font-semibold">Checking a tool</h3>
            <p className="text-text-muted text-[14.5px] flex-1">
              Browse tools by grade before you connect one. See the exact reason for every grade — the
              dangerous permission, the injection surface, the signed evidence — not a star rating.
            </p>
            <Link to="/rebrand/browse" className="mt-2 self-start text-[14.5px] font-semibold text-primary-light hover:text-primary">
              Browse the catalog →
            </Link>
          </div>
          <div className="glass card-hover rounded-2xl p-6 flex flex-col gap-2">
            <h3 className="text-lg font-semibold">Building a tool</h3>
            <p className="text-text-muted text-[14.5px] flex-1">
              Scan your repo and drop a signed trust badge in your README in one line. Every viewer can verify
              the grade themselves. Wire it into CI when you're ready.
            </p>
            <Link to="/rebrand/badge" className="mt-2 self-start text-[14.5px] font-semibold text-primary-light hover:text-primary">
              Get your badge →
            </Link>
          </div>
        </div>
      </section>

      {/* ③ PROOF-OF-SCALE STRIP (TODO: pull counts live from public scan API — do not ship hardcoded) */}
      <section className="max-w-[1080px] mx-auto px-6 pb-14">
        <div className="glass rounded-2xl p-8 flex flex-wrap gap-x-12 gap-y-4 justify-center text-center">
          {[
            ['35,689', 'tools scanned'],
            ['7,029', 'MCP servers'],
            ['12', 'detection categories'],
            ['100%', 'signed & verifiable'],
          ].map(([n, l]) => (
            <div key={l}>
              <b className="block text-3xl tracking-tight tabular-nums gradient-text">{n}</b>
              <span className="text-[13px] text-text-muted">{l}</span>
            </div>
          ))}
          <div className="basis-full font-mono text-[11.5px] text-text-muted/70 mt-1">
            a one-time launch corpus — counts pulled live from the scan catalog, never hardcoded
          </div>
        </div>
      </section>

      {/* ④ LIVE PROOF — a real signed result (Attestation Trust + Adoption) */}
      <section id="proof" className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <div className="text-center max-w-[56ch] mx-auto">
          <Eyebrow>Not a score, a signature</Eyebrow>
          <h2 className="mt-3 text-2xl md:text-3xl font-bold">Two scores, one signed record.</h2>
          <p className="mt-3 text-text-muted">
            Attestation Trust is your signed safety grade. Adoption shows how much the ecosystem actually uses
            a tool — real usage, not opinions.
          </p>
        </div>

        <div className="glass rounded-2xl overflow-hidden max-w-[620px] mx-auto mt-8">
          <div className="flex items-center gap-4 p-5 border-b border-border/60">
            <div className="w-14 h-14 rounded-2xl grid place-items-center text-2xl font-extrabold text-[#08110f] bg-gradient-to-br from-accent to-primary shadow-lg shadow-accent/30">A</div>
            <div>
              <div className="font-mono text-[13px] text-text-muted">github.com/acme/filesystem-mcp</div>
              <div className="mt-1 text-[13px] font-semibold gradient-text">Verified / Trusted · tier 4</div>
            </div>
          </div>
          <div className="flex flex-wrap gap-2.5 p-4 border-b border-border/60">
            <div className="flex-1 min-w-[180px] bg-surface border border-border rounded-xl px-4 py-3">
              <div className="font-mono text-[11.5px] uppercase tracking-wide text-text-muted">Attestation Trust</div>
              <div className="text-lg font-bold text-primary-light mt-0.5">A · 94</div>
              <div className="text-[11.5px] text-text-muted mt-0.5">signed scanner grade · verifiable now</div>
            </div>
            <div className="flex-1 min-w-[180px] bg-surface border border-border rounded-xl px-4 py-3">
              <div className="font-mono text-[11.5px] uppercase tracking-wide text-text-muted">Adoption</div>
              <div className="text-lg font-bold text-warning mt-0.5">12.4k installs · 340 checks</div>
              <div className="text-[11.5px] text-text-muted mt-0.5">downloads · stars · checks · public data</div>
            </div>
          </div>
          <div className="p-5 flex flex-col gap-2.5">
            <div className="flex gap-2.5 items-start text-[14px]">
              <span className="font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-success/15 text-success shrink-0 mt-0.5">pass</span>
              <span>Scoped file access, no shell <code className="font-mono text-[12.5px] text-text-muted">exec()</code></span>
            </div>
            <div className="flex gap-2.5 items-start text-[14px]">
              <span className="font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-success/15 text-success shrink-0 mt-0.5">pass</span>
              <span>No secrets · no exfiltration sinks · no injection surface · deps clean</span>
            </div>
          </div>
          <div className="flex items-center gap-2.5 p-4 border-t border-dashed border-border flex-wrap">
            <span className="flex items-center gap-2 font-mono text-[12px] text-success">
              <svg viewBox="0 0 24 24" fill="none" className="w-[18px] h-[18px]">
                <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" />
                <path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              Signed · Ed25519 / JWS
            </span>
            <a href="/.well-known/jwks.json" className="ml-auto text-[13px] font-semibold text-primary-light hover:text-primary">Verify this attestation →</a>
          </div>
        </div>
      </section>

      {/* ⑤ BROWSE STRIP (Yelp teaser) */}
      <section className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <div className="max-w-[56ch]">
          <Eyebrow>Browse</Eyebrow>
          <h2 className="mt-3 text-2xl md:text-3xl font-bold">See how the tools you're about to trust actually score.</h2>
          <p className="mt-3 text-text-muted">Sorted safest-first. Open any tool to see why it earned its grade.</p>
        </div>
        <div className="grid md:grid-cols-3 gap-3.5 mt-8">
          {[
            ['acme/filesystem-mcp', 'A', 'text-success bg-success/15'],
            ['acme/mcp-server', 'B', 'text-warning bg-warning/15'],
            ['unknown/agent-bridge', 'D', 'text-danger bg-danger/15'],
          ].map(([name, grade, cls]) => (
            <Link key={name} to="/rebrand/browse" className="glass card-hover rounded-xl p-[18px] block">
              <div className="flex items-center justify-between gap-2.5">
                <span className="font-mono text-[13.5px] break-all">{name}</span>
                <span className={`font-extrabold text-[13px] px-2.5 py-0.5 rounded-lg ${cls}`}>{grade}</span>
              </div>
              <div className="mt-3 text-[12.5px] text-primary-light">Why this grade →</div>
            </Link>
          ))}
        </div>
        <div className="mt-6">
          <Link to="/rebrand/browse" className="text-[14px] font-semibold text-primary-light hover:text-primary">Browse the full catalog →</Link>
        </div>
      </section>

      {/* ⑥ DEVELOPER STRIP — the badge loop */}
      <section id="developers" className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <div className="max-w-[56ch]">
          <Eyebrow>For developers</Eyebrow>
          <h2 className="mt-3 text-2xl md:text-3xl font-bold">One line. A signed trust badge in your README.</h2>
          <p className="mt-3 text-text-muted">Check your repo, copy the badge. Every reader can verify the grade — and clicking it re-checks your tool.</p>
        </div>
        <div className="grid md:grid-cols-2 gap-6 items-center mt-6">
          <div>
            <span className="inline-flex font-mono text-[12px] rounded overflow-hidden shadow-md">
              <span className="bg-surface-hover text-text px-2.5 py-1.5">🛡 AgentAvow</span>
              <span className="px-2.5 py-1.5 font-bold text-white bg-gradient-to-r from-primary to-primary-dark">Trust: A 94</span>
            </span>
            <div className="mt-4 font-mono text-[12.5px] bg-surface border border-border rounded-xl px-4 py-3.5 text-text overflow-x-auto">
              [![AgentAvow Trust](https://agentavow.com/api/v1/public/scan/you/your-repo/badge)](https://agentavow.com/check/you/your-repo)
            </div>
          </div>
          <div>
            <p className="text-text-muted text-[14.5px]">
              The badge regenerates on every view, so it never goes stale. It's signed and links back to a
              full, verifiable report — no account required to mint one.
            </p>
            <Link to="/rebrand/badge" className="inline-block mt-4 font-mono text-[13px] text-primary-light hover:text-primary">
              Wire it into CI with the GitHub Action · SDK · CLI →
            </Link>
          </div>
        </div>
      </section>

      {/* ⑦ HOW IT WORKS */}
      <section id="how" className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <div className="max-w-[56ch]">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="mt-3 text-2xl md:text-3xl font-bold">Paste, scan, verify.</h2>
        </div>
        <div className="grid md:grid-cols-3 rounded-2xl overflow-hidden border border-border/60 mt-8 glass">
          {[
            ['01', 'Paste a URL', 'A repo, MCP server, npm/PyPI package, or skill. No signup.'],
            ['02', 'We scan it', 'Across 12 categories — secrets, exec sinks, exfiltration, prompt injection, obfuscation, deps.'],
            ['03', 'Get a signed grade', 'A letter grade plus a signed attestation anyone can verify offline against our public key.'],
          ].map(([n, h, p], i) => (
            <div key={n} className={`p-6 ${i < 2 ? 'md:border-r border-border/60' : ''}`}>
              <div className="font-mono text-[12px] text-primary-light tracking-wide">{n}</div>
              <h3 className="mt-2.5 text-[17px] font-semibold">{h}</h3>
              <p className="mt-2 text-text-muted text-[14px]">{p}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ⑧ ACCOUNT CAPTURE — the one earned account ask */}
      <section className="max-w-[1080px] mx-auto px-6 py-14">
        <div className="glass rounded-3xl p-10 text-center relative overflow-hidden">
          <div className="relative">
            <Eyebrow>Stay safe over time</Eyebrow>
            <h2 className="mt-2.5 text-2xl md:text-3xl font-bold">
              Depend on a tool? We'll <span className="gradient-text">watch it</span> for you.
            </h2>
            <p className="mt-3 mx-auto max-w-[52ch] text-text-muted">
              Tools change after you vet them. We re-scan the ones you watch and alert you the moment a grade
              drops or a signed definition changes — the rug-pull you'd otherwise miss.
            </p>
            <a
              href="/register"
              className="inline-block mt-6 font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow"
            >
              Watch a tool
            </a>
            <div className="mt-3.5 font-mono text-[11.5px] text-text-muted/70">
              the one thing worth an account · everything else stays free and anonymous
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
