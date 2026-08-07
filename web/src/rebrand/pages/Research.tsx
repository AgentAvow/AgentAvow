import { Reveal, RevealStagger } from '../components/motion'

/**
 * Research hub (rebrand) — self-published reports + specs. On a trust product,
 * publishing your own methodology is a credibility asset. We publish OUR work
 * (reports, the CTEF format, conformance vectors) rather than naming partners.
 */

const REPORTS: { title: string; sub: string; date: string; status: 'live' | 'upcoming'; href?: string }[] = [
  { title: 'State of Agent Security 2026', sub: 'Agent distribution surfaces + the signed-evidence substrate. 35k+ tools scanned, reproducible.', date: 'Q2 2026', status: 'live', href: '/state-of-agent-security-2026' },
  { title: 'State of Agent Security — Q3 2026', sub: 'The next quarterly cut, with the growing community-scan corpus.', date: 'Aug 2026', status: 'upcoming' },
]

const PUBLICATIONS: { title: string; sub: string; href: string }[] = [
  { title: 'CTEF — Cryptographic Trust Evidence Format', sub: 'The signed, reproducible evidence envelope. Versioned in the open.', href: 'https://github.com/AgentAvow/AgentAvow/tree/main/docs/standards' },
  { title: 'Conformance test vectors', sub: 'Validate your own implementation against ours.', href: 'https://agentgraph.co/.well-known/cte-test-vectors.json' },
  { title: 'Public signing keys (JWKS)', sub: 'Verify any attestation offline.', href: 'https://agentgraph.co/.well-known/jwks.json' },
]

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">{children}</span>
}

export default function RebrandResearch() {
  return (
    <div className="max-w-[880px] mx-auto px-6 py-16">
      <Reveal>
        <div className="max-w-[62ch]">
          <Eyebrow>Research</Eyebrow>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">What we're learning about agent-tool safety.</h1>
          <p className="mt-3 text-text-muted text-[15.5px] leading-relaxed">Quarterly reports and open specifications — every number backed by signed, reproducible scan evidence you can recompute yourself. We publish the methodology, not just the conclusions.</p>
        </div>
      </Reveal>

      <Reveal><h2 className="mt-12 text-xl font-bold">Reports</h2></Reveal>
      <RevealStagger className="flex flex-col gap-3 mt-4" stagger={0.05}>
        {REPORTS.map((r) => {
          const inner = (
            <div className="glass card-hover rounded-2xl p-6">
              <div className="flex items-center gap-3 flex-wrap">
                <span className={`font-mono text-[10.5px] uppercase tracking-wide px-2 py-0.5 rounded ${r.status === 'live' ? 'bg-success/15 text-success' : 'bg-surface-hover text-text-muted'}`}>{r.status === 'live' ? 'Live' : 'Upcoming'}</span>
                <span className="font-mono text-[12px] text-text-muted">{r.date}</span>
              </div>
              <h3 className="mt-2 text-lg font-bold">{r.title}</h3>
              <p className="mt-1 text-text-muted text-[14px]">{r.sub}</p>
              {r.href && <span className="inline-block mt-3 text-[13.5px] font-semibold text-primary-light">Read the report →</span>}
            </div>
          )
          return r.href ? <a key={r.title} href={r.href} className="block">{inner}</a> : <div key={r.title}>{inner}</div>
        })}
      </RevealStagger>

      <Reveal><h2 className="mt-12 text-xl font-bold">Open specifications</h2></Reveal>
      <RevealStagger className="flex flex-col gap-2.5 mt-4" stagger={0.04}>
        {PUBLICATIONS.map((p) => (
          <a key={p.title} href={p.href} target="_blank" rel="noopener noreferrer" className="glass card-hover rounded-xl px-5 py-4 block">
            <div className="flex items-center justify-between gap-3">
              <div className="text-[15px] font-semibold">{p.title}</div>
              <span className="text-primary-light text-[13px] shrink-0">↗</span>
            </div>
            <div className="text-[13.5px] text-text-muted mt-1">{p.sub}</div>
          </a>
        ))}
      </RevealStagger>
    </div>
  )
}
