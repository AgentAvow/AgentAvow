import { useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal, RevealStagger } from '../components/motion'
import { TrustBar, AdoptionNeedle } from '../components/TrustMark'
import { VerifyDemo } from '../components/VerifyDemo'
import { SandboxTotalsStrip } from '../components/SandboxStats'
import { cursorStdio, vscodeStdio } from '../lib/installLinks'
import SEOHead from '../../components/SEOHead'

const AA_MCP = { name: 'agentavow-trust', command: 'uvx', args: ['agentavow-trust'] }

/**
 * How it works — the transparency page. Explains the aggregate-over-signed-evidence
 * score ("Rotten Tomatoes for agent trust"), offline verification (the home for
 * Verify), the 14 detection categories, and the open standards / partner interop work. On a
 * trust product, publishing the methodology is the point — not something to hide.
 */

// The 14 detection categories, canonical names and one-liners from
// src/scanner/categories.py (keep in step with it).
const CATEGORIES = [
  ['Secrets', 'API keys, tokens, passwords or private keys written into the code or config.'],
  ['Code execution', 'Shell or eval execution of input, unsafe deserialization, and git configs that run commands on ordinary git operations.'],
  ['Obfuscation', 'Encoded, packed or bytecode-only code, and invisible or bidi Unicode that hides text from a human reviewer.'],
  ['Prompt injection', 'Instruction-override or hidden-directive text in tool descriptions, metadata, skill prose or tool results, aimed at the model that reads it.'],
  ['Remote code load (rug-pull)', 'Code, config or tool definitions fetched from a mutable remote source that can change after you approved the tool.'],
  ['Data exfiltration', 'Credentials or local data sent to an outbound endpoint.'],
  ['Toxic flow (lethal trifecta)', 'Private-data access, untrusted input and an outbound send combined in one tool (or a server’s tools together): the prompt-injection-to-exfiltration chain. We flag it as a blocking critical.'],
  ['Network endpoints', 'Caller-supplied URLs fetched unchecked (SSRF), plain-HTTP or private-address endpoints, cross-site endpoints, and weak or missing auth schemes.'],
  ['Filesystem access', 'Unsandboxed reads and writes, path traversal, and recursive deletes.'],
  ['Dependencies', 'Dependencies with known vulnerabilities, published advisories against the package itself, and deprecated or yanked releases.'],
  ['Install hooks', 'Scripts that run on install or around a skill’s invocation without being called (npm pre/postinstall, skill hook manifests).'],
  ['Tool definition', 'Risky input schemas, annotations that misstate what a tool does, and skill permission grants that differ from what the shipped code does.'],
  ['Artifact integrity', 'A published package that differs from its source repo, and agent cards whose signature does not verify.'],
  ['Runtime robustness (sandbox only)', 'A tool call that crashes the server or a read-only tool that fails on a read, seen only when the behavioral sandbox runs the tool.'],
]

const STANDARDS = [
  ['Safety Model spec (v1)', 'Exactly how a scan composes into the 0–100 score, the tiers, and the Certified gate — the model published separately from the code, so anyone can recompute a score from the same findings.', 'https://github.com/AgentAvow/AgentAvow/blob/main/docs/standards/agentavow-safety-model-v1.md'],
  ['Tool manifest — .agentavow.yml', 'Declare the hosts your tool contacts and the capabilities it uses; the sandbox holds it to its own declaration. Undeclared egress is a finding.', 'https://github.com/AgentAvow/AgentAvow/blob/main/docs/standards/agentavow-manifest-v0.md'],
  ['CTEF — Composable Trust Evidence Format', 'The signed, reproducible evidence envelope any implementer can recompute byte-for-byte. Versioned in the open.', 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards'],
  ['Published test vectors', 'Conformance vectors served at /.well-known so anyone can validate their own implementation against ours.', 'https://agentgraph.co/.well-known/cte-test-vectors.json'],
  ['ERC-8004 reader', 'Reader for ERC-8004 identity and feedback records; not yet used in any answer or score.', 'https://github.com/AgentAvow/AgentAvow/tree/main/src/agentgraph_bridge_erc8004'],
  ['AIPOU cross-fixture', 'A shared conformance fixture proving two independent implementations agree.', 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/conformance'],
  ['Independently cross-run in the LF DT lab', 'Our CTEF conformance vectors, positive and adversarial/fail-closed, were reproduced byte-for-byte in the Linux Foundation Decentralized Trust Agent Authority Conformance lab, by a party other than us.', 'https://github.com/Agent-Authority-Conformance/aps-conformance-suite/pull/79'],
  ['MCP & AIP bridges', 'Adapters so the trust layer plugs into the frameworks agents already use.', 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/protocol'],
]

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">{children}</span>
}

export default function RebrandHowItWorks() {
  const location = useLocation()
  useEffect(() => {
    if (!location.hash) return
    const id = location.hash.slice(1)
    // ScrollToTop fires on route change; wait a tick so our scroll wins
    const t = setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 120)
    return () => clearTimeout(t)
  }, [location.hash])
  return (
    <div className="max-w-[880px] mx-auto px-6 py-16">
      <SEOHead
        title="How it works — a trust score you don't have to trust"
        description="Scan, score, attest, verify: how AgentAvow turns scan evidence into a signed trust score and adoption score anyone can recompute offline with public keys."
        path="/how-it-works"
      />
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
            <div className="px-5 pt-4 text-[14px] font-semibold text-success" data-decision="safe">
              Safe to connect <span className="font-normal text-text-muted">— nothing found in its shipped code</span>
            </div>
            <div className="grid grid-cols-2 relative">
              <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(340px 130px at 25% 0%, rgba(34,197,94,0.10), transparent 70%), radial-gradient(340px 130px at 78% 0%, rgba(45,212,191,0.10), transparent 70%)' }} />
              <div className="relative p-6 text-center flex flex-col items-center border-r border-border/50">
                <div className="min-h-[100px] sm:min-h-[132px] flex items-center justify-center"><TrustBar score={94} /></div>
                <div className="mt-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] text-success">Attestation Trust</div>
              </div>
              <div className="relative p-6 text-center flex flex-col items-center">
                <div className="min-h-[100px] sm:min-h-[132px] flex items-center justify-center"><AdoptionNeedle count={12400} unit="stars" /></div>
                <div className="mt-2 font-mono text-[10px] font-bold uppercase tracking-[0.16em] gradient-text">Adoption</div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* pipeline */}
      <Reveal>
        <h2 className="mt-12 text-xl font-bold">Paste → scan → run → sign.</h2>
      </Reveal>
      <RevealStagger className="grid sm:grid-cols-2 md:grid-cols-4 gap-3 mt-4" stagger={0.06}>
        {[
          ['01', 'You paste a URL', 'A repo, MCP server, npm/PyPI package, or skill. No signup, no install.'],
          ['02', 'We read the actual code', 'Not metadata or self-claims — the real source, across the categories below.'],
          ['03', 'We run it in a sandbox', 'Packages (including MCP servers published as packages) are installed and run in isolation, each tool (up to 25) called, with fake credentials planted.'],
          ['04', 'You get a signed score', 'A 0–100 trust score plus a cryptographic attestation you can verify offline. The sandbox run is signed separately.'],
        ].map(([n, h, p]) => (
          <div key={n} className="glass rounded-xl p-5">
            <div className="font-mono text-[12px] text-primary-light">{n}</div>
            <h3 className="mt-2 text-[16px] font-semibold">{h}</h3>
            <p className="mt-1.5 text-text-muted text-[13.5px]">{p}</p>
          </div>
        ))}
      </RevealStagger>

      {/* behavioral sandbox — the run step, with live totals */}
      <Reveal>
        <div id="sandbox" className="mt-4 glass rounded-2xl p-6 border-l-4 border-accent/50 scroll-mt-24">
          <div className="flex items-baseline justify-between gap-3 flex-wrap">
            <h3 className="text-[16px] font-bold">Behavioral sandbox: what the tool actually does.</h3>
            <span className="font-mono text-[11px] text-text-muted">gVisor · canary credentials · signed</span>
          </div>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch] leading-relaxed">
            Reading code misses what only shows up at runtime. So we install npm, PyPI and Docker packages, GitHub repos and skills in a fresh
            gVisor container, start MCP servers and <strong className="text-text">call each tool (up to 25)</strong> with synthetic
            arguments, and fill the environment variables a tool reads with <strong className="text-text">canary
            credentials</strong>. If a canary leaves the machine, that is credential exfiltration, rated critical. We also flag
            undeclared network hosts and read-only tools that write files. Each run is signed as a
            <strong className="text-text"> BehavioralObservation</strong> and shown beside the score. Watches alert you when a later run turns up new sandbox findings, and the GitHub Action can fail a build on a
            high or critical sandbox finding.
          </p>
          <SandboxTotalsStrip className="mt-4" align="start" linkLabel={null} />
          <Link to={rp('/rebrand/docs/behavioral-sandbox')} className="inline-block mt-3 text-[13.5px] font-semibold text-primary-light hover:text-primary">How the behavioral sandbox works →</Link>
        </div>
      </Reveal>

      {/* run it yourself — local / CI */}
      <Reveal>
        <div className="mt-4 glass rounded-2xl p-6 border-l-4 border-primary/50">
          <div className="flex items-baseline justify-between gap-3 flex-wrap">
            <h3 className="text-[16px] font-bold">Or run it in CI — on private code.</h3>
            <span className="font-mono text-[11px] text-text-muted">same engine · same score · offline</span>
          </div>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch] leading-relaxed">
            The exact scanner runs in your own runner or terminal, so a <strong className="text-text">private repo</strong> never
            leaves your machine. Fail a PR when the answer is Do not connect and get findings as inline annotations — the signed attestation
            is the one part that stays with us.
          </p>
          <pre className="mt-3 font-mono text-[12.5px] bg-surface border border-border rounded-xl px-4 py-3 text-text overflow-x-auto">{`# CI (private repos, runs in the runner)
- uses: AgentAvow/AgentAvow/local-scan-action@main
  with: { fail-on: "do_not_connect" }

# or locally
agentavow scan . --fail-on do_not_connect`}</pre>
          <Link to={rp('/rebrand/docs/run-locally')} className="inline-block mt-3 text-[13.5px] font-semibold text-primary-light hover:text-primary">Run locally &amp; in CI →</Link>
        </div>
      </Reveal>

      {/* categories */}
      <Reveal>
        <h2 className="mt-12 text-xl font-bold">What we check</h2>
        <p className="mt-1.5 text-text-muted text-[14px] max-w-[62ch]">The engine runs <strong className="text-text">14 detection categories</strong> — a score page shows the ones that applied to that surface. The first 13 read the code; the last needs the behavioral sandbox to run the tool.</p>
      </Reveal>
      <RevealStagger className="grid sm:grid-cols-2 gap-2.5 mt-4" stagger={0.03}>
        {CATEGORIES.map(([h, p]) => (
          <div key={h} className="glass rounded-xl px-4 py-3">
            <div className="text-[14.5px] font-semibold">{h}</div>
            <div className="text-[13px] text-text-muted mt-0.5">{p}</div>
          </div>
        ))}
      </RevealStagger>

      {/* MCP plug — give your own agent this same check, built in */}
      <Reveal>
        <div id="mcp-check" className="mt-12 glass rounded-2xl p-7 border-l-4 border-primary/60 scroll-mt-24">
          <Eyebrow>For your agent</Eyebrow>
          <h2 className="mt-2 text-xl font-bold">Give your own agent this check, built in.</h2>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch] leading-relaxed">
            The same scan runs as an <strong className="text-text">MCP server</strong>. Add it to your agent and it can ask
            <em> "is this safe to install?"</em> — getting a signed safety score <strong className="text-text">before</strong> it
            connects any tool, package, or server. Free, no account. One line: <code className="font-mono text-[12.5px] text-primary-light bg-surface px-1.5 py-0.5 rounded">uvx agentavow-trust</code>
          </p>
          <div className="mt-4 flex gap-3 flex-wrap items-center">
            <a href={cursorStdio(AA_MCP)} className="inline-flex items-center gap-2 font-semibold text-[13.5px] px-4 py-2 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Add to Cursor →</a>
            <a href={vscodeStdio(AA_MCP)} className="inline-flex items-center font-semibold text-[13.5px] px-4 py-2 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Add to VS Code →</a>
            <Link to={rp('/rebrand/for-developers')} className="inline-flex items-center font-semibold text-[13.5px] px-4 py-2 rounded-lg border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Claude Code & full setup →</Link>
          </div>
        </div>
      </Reveal>

      {/* verify — the home for Verify */}
      <Reveal>
        <div id="verify" className="mt-12 glass rounded-2xl p-7 border-l-4 border-primary/60">
          <Eyebrow>Verify</Eyebrow>
          <h2 className="mt-2 text-xl font-bold">Signed, so a tool can't show one score and be another.</h2>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch] leading-relaxed">
            Each result is signed with Ed25519 (JWS): the score <strong className="text-text">and</strong> the tool's definition,
            captured the moment we scanned it. Nobody can hand you a doctored number, and if a tool swaps its definition after
            you trusted it, the signed digest no longer matches and we flag it. Verify any attestation offline against our
            public keys — a <strong className="text-text">signature, not just a badge</strong>: you don't have to trust
            AgentAvow, you can check the math.
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

      {/* how we're different — the one row only we can fill */}
      <Reveal>
        <div className="mt-12">
          <Eyebrow>How we're different</Eyebrow>
          <h2 className="mt-2 text-xl font-bold">Everyone can give you a number. One row is ours alone.</h2>
          <p className="mt-2 text-text-muted text-[14px] max-w-[64ch]">There are good MCP scanners and trust registries now — the ecosystem needs them. Here's the honest landscape and the one property none of them have.</p>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-[13.5px] border-collapse min-w-[520px]">
              <thead>
                <tr className="text-text-muted">
                  <th className="text-left font-semibold py-2 pr-4">Property</th>
                  <th className="text-left font-semibold py-2 px-3">Directory scores<br /><span className="font-normal text-[11px]">(Smithery, mcp registries)</span></th>
                  <th className="text-left font-semibold py-2 px-3">Trust checkers<br /><span className="font-normal text-[11px]">(mcpskills, others)</span></th>
                  <th className="text-left font-semibold py-2 px-3 text-primary-light">AgentAvow</th>
                </tr>
              </thead>
              <tbody className="[&_td]:py-2.5 [&_td]:border-t [&_td]:border-border/50">
                {[
                  ['Free public safety score + README badge', '~', '✓', '✓'],
                  ['You can recompute it yourself', '✕', '✓', '✓'],
                  ['Independent (not a vendor grading its own gateway/listings)', '✕', '~', '✓'],
                  ['Cryptographically SIGNED — tamper-evident, offline-verifiable', '✕', '✕', '✓'],
                ].map(([prop, a, b, us]) => (
                  <tr key={prop}>
                    <td className="pr-4 text-text">{prop}</td>
                    <td className="px-3 text-center text-text-muted">{a}</td>
                    <td className="px-3 text-center text-text-muted">{b}</td>
                    <td className="px-3 text-center font-bold text-primary-light">{us}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-3 text-[12.5px] text-text-muted/80">Recompute proves the math. A signature proves <em>who</em> issued the score, <em>when</em>, and that the number in your README wasn't altered — the audit trail a live-fetched badge structurally can't give. (Signing covers the safety score; adoption is a separate directional signal.)</p>
        </div>
      </Reveal>

      <Reveal>
        <div className="mt-12 text-center">
          <Link to={rp("/rebrand/check")} className="inline-block font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Check a tool now →</Link>
        </div>
      </Reveal>
    </div>
  )
}
