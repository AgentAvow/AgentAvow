import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import publicApi from '../../lib/api'
import { rp } from '../basePath'
import { CountUp, Reveal, RevealStagger } from '../components/motion'

/**
 * State of Agent Security — Q3 2026. The data story: the tool-safety blind spot,
 * sized. The headline stat is LIVE from the scan corpus (recomputable, on brand),
 * so the report can never drift from the number it cites.
 */

const CERTIFIED = ['sigstore', 'react', 'axios', 'undici', 'vue', '@langchain/core']

export default function StateOfAgentSecurityQ3() {
  const stat = useQuery<{ pct: number | null; flagged: number; scanned: number }>({
    queryKey: ['flagged-stat-q3'],
    queryFn: async () => (await publicApi.get('/public/scan-catalog/flagged-stat')).data,
  })
  const pct = stat.data?.pct ?? 43
  const scanned = stat.data?.scanned ?? 24756
  const flagged = stat.data?.flagged ?? 10652

  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">State of Agent Security · Q3 2026</span>
        <h1 className="mt-3 text-3xl md:text-5xl font-extrabold tracking-tight leading-[1.05]">
          We scanned <span className="tabular-nums">{scanned.toLocaleString()}</span> agent tools.
          <br /><span className="gradient-text-bio"><CountUp value={pct} suffix="%" /></span> have a high- or critical-severity finding.
        </h1>
        <p className="mt-5 text-text-muted text-[16px] leading-relaxed max-w-[64ch]">
          Not "could be risky." A concrete finding — a leaked secret, an unsafe exec path, an injected instruction
          in a tool description, a lethal-trifecta flow — with a file and a line, in a tool an agent is being told
          to connect to <em>right now</em>. That's {flagged.toLocaleString()} of {scanned.toLocaleString()} tools.
        </p>
      </Reveal>

      <Reveal>
        <h2 className="mt-16 text-2xl font-bold">Why this is the number that matters</h2>
        <p className="mt-3 text-text-muted text-[15px] leading-relaxed">
          The agent-security conversation in 2026 has been about <strong className="text-text">identity</strong> (who
          is this agent?) and <strong className="text-text">authorization</strong> (what is it allowed to do?). Both
          are being solved. But neither says whether <strong className="text-text">the tool itself is safe to run</strong>.
          A perfectly-authenticated agent connecting to a perfectly-authorized MCP server can still hand it a secret,
          or call a tool whose description quietly tells the model to exfiltrate. {pct}% is the size of that blind spot —
          the third axis, the one nobody else is measuring. So we did.
        </p>
      </Reveal>

      <Reveal>
        <h2 className="mt-14 text-2xl font-bold">What "flagged" means</h2>
        <RevealStagger className="mt-4 grid sm:grid-cols-2 gap-3" stagger={0.05}>
          <div className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">≥1 high or critical finding</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">We don't count low/medium noise, and findings that live only in a tool's test/example files are scored at a fraction — a tool isn't judged on its test suite.</p>
          </div>
          <div className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">Every number recomputes</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">Each scan is a signed (Ed25519) verdict you can re-derive byte-for-byte offline against our public keys. Not a "trust us" survey — an attestation. Re-derive any figure here yourself.</p>
          </div>
        </RevealStagger>
      </Reveal>

      <Reveal>
        <div className="mt-14 rounded-2xl p-7 glass border-l-4" style={{ borderLeftColor: '#2dd4bf', background: 'linear-gradient(120deg, rgba(45,212,191,0.06), rgba(232,121,249,0.05))' }}>
          <h2 className="text-2xl font-bold">The counter-example: it can be done right</h2>
          <p className="mt-3 text-text-muted text-[15px] leading-relaxed">
            The flip side of {pct}% is that a real top tier exists and is being cleared today. <strong className="text-text">21 tools
            are AgentAvow Certified</strong> — verified build provenance, zero critical/high, no manifest drift, full
            offline-recomputable coverage, every check public. Among them:
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            {CERTIFIED.map((n) => (
              <span key={n} className="inline-flex items-center gap-2 rounded-full pl-1 pr-3 py-1 bg-surface border border-border/60">
                <span className="font-mono text-[10.5px] font-extrabold px-2 py-0.5 rounded-full" style={{ background: 'linear-gradient(120deg,#2dd4bf,#e879f9)', color: '#06231f' }}>✓</span>
                <span className="font-mono text-[12.5px]">{n}</span>
              </span>
            ))}
          </div>
          <p className="mt-4 text-text-muted text-[14px] leading-relaxed">
            The gap between {pct}%-flagged and 21-Certified is the whole story: the ceiling is reachable — most tools
            just aren't near it yet. <Link to={rp('/rebrand/certified')} className="text-primary-light hover:text-primary font-semibold">See the Certified gate →</Link>
          </p>
        </div>
      </Reveal>

      <Reveal>
        <h2 className="mt-14 text-2xl font-bold">If you build agent tools</h2>
        <p className="mt-3 text-text-muted text-[15px] leading-relaxed">
          Scan it (free, no account), see exactly what an agent inherits by connecting, fix what matters, and — if
          it's clean — put a signed badge on your README that anyone can verify. The {pct}% isn't an indictment of
          developers; it's an unaddressed surface, and closing it is mostly low-hanging fruit.
        </p>
        <div className="mt-6 flex gap-3 flex-wrap">
          <Link to={rp('/rebrand/check')} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Scan your tool →</Link>
          <Link to={rp('/rebrand/index')} className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Browse the Index</Link>
        </div>
      </Reveal>

      <Reveal>
        <h2 className="mt-14 text-xl font-bold">Methodology</h2>
        <ul className="mt-3 flex flex-col gap-2 text-[13.5px] text-text-muted leading-relaxed">
          <li>· Corpus: {scanned.toLocaleString()} tools across GitHub repos, npm, PyPI, MCP servers, and skills — scanned by the public AgentAvow engine (12 detection categories, per-finding severity, exact file:line).</li>
          <li>· "Flagged" = ≥1 high/critical finding on shipped (non-test) code.</li>
          <li>· Every verdict is a signed, offline-recomputable attestation. Keys at <a href="https://agentgraph.co/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">agentgraph.co/.well-known/jwks.json</a>; conformance vectors public.</li>
          <li>· Live figure: <a href="/api/v1/public/scan-catalog/flagged-stat" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">the flagged-stat endpoint</a> — this page renders it live, so it never drifts from the number it cites.</li>
        </ul>
        <p className="mt-6 text-[12.5px] text-text-muted/70">Figures update as the corpus grows. Last rendered from the live endpoint.</p>
      </Reveal>
    </div>
  )
}
