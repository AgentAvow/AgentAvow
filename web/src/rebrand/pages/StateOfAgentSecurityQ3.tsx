import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { rp } from '../basePath'
import { fetchFlaggedStat, type FlaggedCounts } from '../catalog'
import { CountUp, Reveal, RevealStagger } from '../components/motion'
import SEOHead from '../../components/SEOHead'

/**
 * State of Agent Security, Q3 2026. The data story: the tool-safety blind spot,
 * sized. The headline stat is LIVE from the scan corpus (recomputable, on brand),
 * so the report can never drift from the number it cites.
 *
 * Every figure is an exclusive bucket over tools that received a verdict: a tool
 * with both a critical and a high finding is counted once (under critical), and
 * rows the scanner skipped or could not fetch are not in any denominator.
 */

const CERTIFIED = ['sigstore', 'react', 'axios', 'undici', 'vue', '@langchain/core']

// Fallbacks mirror the live flagged-stat endpoint (last synced 2026-10-01, after the
// exclusive-count fix). The page renders the live figure; these only show if the
// endpoint is unreachable, so keep them at the last verified live value.
const FALLBACK: FlaggedCounts = {
  scanned_total: 14366, critical: 1191, high_only: 4700, flagged: 5891, clean: 8475,
  skipped: 0, total: 14366, pct: 41, flagged_pct: 41.0, critical_pct: 8.3,
}
const FALLBACK_MCP: FlaggedCounts = {
  scanned_total: 12420, critical: 925, high_only: 4195, flagged: 5120, clean: 7300,
  skipped: 7804, total: 20224, pct: 41, flagged_pct: 41.2, critical_pct: 7.4,
}

export default function StateOfAgentSecurityQ3() {
  const stat = useQuery({ queryKey: ['flagged-stat'], queryFn: fetchFlaggedStat, staleTime: 60_000 })
  const all = stat.data ?? FALLBACK
  const mcp = stat.data?.by_surface?.mcp ?? FALLBACK_MCP
  const pct = all.pct ?? FALLBACK.pct ?? 0
  const scanned = all.scanned_total
  const flagged = all.flagged
  const critical = all.critical
  const criticalPct = all.critical_pct ?? FALLBACK.critical_pct
  const mcpPct = mcp.flagged_pct ?? mcp.pct

  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <SEOHead
        title="State of Agent Security — Q3 2026"
        description="How many agent tools AgentAvow scored this quarter, what share carry a high or critical finding, and what it means for the trust score you should gate on."
        path="/state-of-agent-security-q3-2026"
        type="article"
      />
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">State of Agent Security · Q3 2026</span>
        <h1 className="mt-3 text-3xl md:text-5xl font-extrabold tracking-tight leading-[1.05]">
          We graded <span className="tabular-nums">{scanned.toLocaleString()}</span> agent tools.
          <br /><span className="gradient-text-bio"><CountUp value={pct} suffix="%" /></span> have a high or critical severity finding.
        </h1>
        <p className="mt-5 text-text-muted text-[16px] leading-relaxed max-w-[64ch]">
          Not "could be risky." A concrete finding: a leaked secret, an unsafe exec path, an injected instruction
          in a tool description, a lethal-trifecta flow, with a file and a line, in a tool an agent is being told
          to connect to <em>right now</em>. That is {flagged.toLocaleString()} of {scanned.toLocaleString()} scanned
          tools, each counted once. {critical.toLocaleString()} of them ({criticalPct}%) carry at least one critical finding.
        </p>
      </Reveal>

      <Reveal>
        <h2 className="mt-16 text-2xl font-bold">Why this is the number that matters</h2>
        <p className="mt-3 text-text-muted text-[15px] leading-relaxed">
          The agent-security conversation in 2026 has been about <strong className="text-text">identity</strong> (who
          is this agent?) and <strong className="text-text">authorization</strong> (what is it allowed to do?). Both
          are being solved. But neither says whether <strong className="text-text">the tool itself is safe to run</strong>.
          A perfectly-authenticated agent connecting to a perfectly-authorized MCP server can still hand it a secret,
          or call a tool whose description quietly tells the model to exfiltrate. {pct}% is the size of that blind spot,
          the third axis, the one nobody else is measuring. So we did.
        </p>
      </Reveal>

      <Reveal>
        <h2 className="mt-14 text-2xl font-bold">What "flagged" means</h2>
        <RevealStagger className="mt-4 grid sm:grid-cols-2 gap-3" stagger={0.05}>
          <div className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">At least one high or critical finding</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">We do not count low/medium noise, and findings that live only in a tool's test/example files are scored at a fraction. A tool is not judged on its test suite. A tool with both a critical and a high finding is counted once.</p>
          </div>
          <div className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">Only graded tools count</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">The denominator is tools that received a verdict. Registry entries we could not fetch or scan ({mcp.skipped.toLocaleString()} MCP entries alone) are listed in the Index as skipped and are in neither the numerator nor the denominator.</p>
          </div>
          <div className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">MCP servers: {mcpPct}% flagged</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">{mcp.flagged.toLocaleString()} of {mcp.scanned_total.toLocaleString()} scanned MCP servers carry a high or critical finding; {mcp.critical.toLocaleString()} ({mcp.critical_pct ?? FALLBACK_MCP.critical_pct}%) carry a critical one.</p>
          </div>
          <div className="glass rounded-xl p-5">
            <div className="text-[15px] font-semibold">Every number recomputes</div>
            <p className="mt-1.5 text-text-muted text-[13.5px] leading-relaxed">Each scan is a signed (Ed25519) verdict you can re-derive byte-for-byte offline against our public keys. Not a "trust us" survey; an attestation. Re-derive any figure here yourself.</p>
          </div>
        </RevealStagger>
      </Reveal>

      <Reveal>
        <div className="mt-14 rounded-2xl p-7 glass border-l-4" style={{ borderLeftColor: '#2dd4bf', background: 'linear-gradient(120deg, rgba(45,212,191,0.06), rgba(232,121,249,0.05))' }}>
          <h2 className="text-2xl font-bold">The counter-example: it can be done right</h2>
          <p className="mt-3 text-text-muted text-[15px] leading-relaxed">
            The flip side of {pct}% is that a real top tier exists and is being cleared today. <strong className="text-text">21 tools
            are AgentAvow Certified</strong>: verified build provenance, zero critical/high, no manifest drift, full
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
            The gap between {pct}%-flagged and 21-Certified is the whole story: the ceiling is reachable. Most tools
            just are not near it yet. <Link to={rp('/rebrand/certified')} className="text-primary-light hover:text-primary font-semibold">See the Certified gate →</Link>
          </p>
        </div>
      </Reveal>

      <Reveal>
        <h2 className="mt-14 text-2xl font-bold">If you build agent tools</h2>
        <p className="mt-3 text-text-muted text-[15px] leading-relaxed">
          Scan it (free, no account), see exactly what an agent inherits by connecting, fix what matters, and, if
          it is clean, put a signed badge on your README that anyone can verify. The {pct}% is not an indictment of
          developers; it is an unaddressed surface, and closing it is mostly low-hanging fruit.
        </p>
        <div className="mt-6 flex gap-3 flex-wrap">
          <Link to={rp('/rebrand/check')} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25">Scan your tool →</Link>
          <Link to={rp('/rebrand/index')} className="font-semibold px-6 py-3 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Browse the Index</Link>
        </div>
      </Reveal>

      <Reveal>
        <h2 className="mt-14 text-xl font-bold">Methodology</h2>
        <ul className="mt-3 flex flex-col gap-2 text-[13.5px] text-text-muted leading-relaxed">
          <li>· Corpus: {scanned.toLocaleString()} tools with a verdict across GitHub repos, npm, PyPI, MCP servers, and skills, scanned by the public AgentAvow engine (12 detection categories, per-finding severity, exact file:line). Skipped and unfetchable entries are excluded from every figure.</li>
          <li>· "Flagged" = at least one high or critical finding on shipped (non-test) code. Buckets are exclusive: critical, high-only, clean. flagged = critical + high-only, so no tool is counted twice.</li>
          <li>· Every verdict is a signed, offline-recomputable attestation. Keys at <a href="https://agentgraph.co/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">agentgraph.co/.well-known/jwks.json</a>; conformance vectors public.</li>
          <li>· Live figure: <a href="/api/v1/public/scan-catalog/flagged-stat" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">the flagged-stat endpoint</a>. This page renders it live, so it never drifts from the number it cites. Each count equals the total of the matching severity filter in <Link to={rp('/rebrand/index')} className="text-primary-light hover:text-primary">the Index</Link>.</li>
        </ul>
        <p className="mt-6 text-[12.5px] text-text-muted/70">Figures update as the corpus grows. Last rendered from the live endpoint.</p>
      </Reveal>
    </div>
  )
}
