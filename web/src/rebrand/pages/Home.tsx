import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, useReducedMotion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { fetchCatalog, rowIdentity } from '../catalog'
import { publicApi } from '../../lib/scanApi'
import { getGradeInfo } from '../../components/trust/gradeSystem'
import { Reveal, CountUp } from '../components/motion'
import { useRotatingPlaceholder } from '../lib/hooks'
import { DualScore } from '../components/DualScore'

const CHECK_HINTS = ['github.com/owner/repo', 'an MCP server', 'an npm package', 'a Python package', 'an agent skill']

/**
 * AgentAvow rebrand homepage.
 * The /check input IS the hero. Live catalog for counts + browse teaser.
 * Section order: hero → proof strip → two-audience fork → signed-result example →
 * how it works → three axes → browse teaser → developer → change-alerts/CI.
 */

// Real, scannable example repos — clicking a chip runs a real scan (works on prod;
// on-demand scans 502 locally without a GitHub token — see the /check note).
const EXAMPLES = [
  'modelcontextprotocol/servers',
  'agenttrust/mcp-server',
  'block/goose',
  'langchain-ai/langchain',
]

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">{children}</span>
}

/** Large animated trust-seal for the hero — echoes the logo, draws itself in on load. */
function HeroSeal() {
  const reduce = useReducedMotion()
  return (
    <motion.svg
      viewBox="0 0 96 96" className="w-[72px] h-[72px] mx-auto mb-6" aria-hidden="true"
      initial={reduce ? false : { opacity: 0, scale: 0.85 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.6, ease: 'easeOut' }}
    >
      <defs>
        <linearGradient id="seal-g" x1="0" y1="0" x2="96" y2="96">
          <stop stopColor="#2DD4BF" /><stop offset="1" stopColor="#E879F9" />
        </linearGradient>
      </defs>
      <motion.circle
        cx="48" cy="48" r="40" fill="none" stroke="url(#seal-g)" strokeWidth="3"
        style={{ transformBox: 'fill-box', transformOrigin: 'center' }}
        animate={reduce ? {} : { rotate: 360 }}
        transition={{ duration: 16, ease: 'linear', repeat: Infinity }}
        strokeDasharray="4 10" strokeLinecap="round"
      />
      <circle cx="48" cy="48" r="30" fill="none" stroke="var(--color-primary-light)" strokeWidth="1.5" opacity="0.35" />
      <motion.path
        d="M34 49l9 9 19-20" fill="none" stroke="var(--color-primary-light)" strokeWidth="5"
        strokeLinecap="round" strokeLinejoin="round" pathLength={1}
        initial={reduce ? false : { pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 0.7, ease: 'easeOut', delay: 0.35 }}
      />
    </motion.svg>
  )
}

export default function RebrandHome() {
  const [value, setValue] = useState('')
  const navigate = useNavigate()
  const hint = useRotatingPlaceholder(CHECK_HINTS)
  const runCheck = (input: string) => {
    const m = input.trim().match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
    navigate(m ? `/rebrand/check/${m[1]}/${m[2]}` : '/rebrand/check')
  }

  const { data: cat } = useQuery({
    queryKey: ['rebrand-home-catalog'],
    queryFn: () => fetchCatalog({ surface: 'mcp', sort: 'score-desc', limit: 6 }),
    staleTime: 5 * 60_000,
  })
  const s = cat?.summary
  const teaser = (cat?.rows ?? []).filter((r) => r.trust_score != null).slice(0, 3)
  // A real scored tool for the signed-result example (no mock/fabricated data).
  const example = (() => {
    const row = teaser[0]
    if (!row) return null
    const { display, repoPath } = rowIdentity(row)
    return { row, display, repoPath, g: getGradeInfo(row.trust_score as number) }
  })()
  // Real adoption for the example card (stars/checks/watchers) — no "coming soon".
  const { data: exAdopt } = useQuery({
    queryKey: ['home-ex-adopt', example?.repoPath],
    queryFn: async () => (await publicApi.get<{ checks: number; watchers: number; stars: number | null }>(`/public/scan/${example!.repoPath}/checks`)).data,
    enabled: !!example?.repoPath,
    staleTime: 5 * 60_000,
  })
  const exAdoption = exAdopt
    ? {
        label: exAdopt.stars != null && exAdopt.stars > 0 ? `★ ${exAdopt.stars.toLocaleString()}` : `${exAdopt.checks.toLocaleString()} checks`,
        sub: `${exAdopt.watchers} watching · on AgentAvow`,
      }
    : null

  return (
    <div>
      {/* ① HERO = the check itself */}
      <section className="text-center pt-16 pb-8 px-6">
        <motion.div
          className="max-w-[1080px] mx-auto"
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        >
          <HeroSeal />
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold leading-[1.06] tracking-tight">
            Is this AI tool <span className="gradient-text-bio">safe</span> to connect?
          </h1>
          <p className="mt-5 mx-auto max-w-[50ch] text-lg text-text-muted font-light">
            Scan any tool, MCP server, or skill your agent connects to. Get a signed safety grade in seconds
            — free, no signup, and verifiable offline.
          </p>

          <form
            onSubmit={(e) => { e.preventDefault(); runCheck(value) }}
            className="glass mt-8 mx-auto max-w-[600px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10"
          >
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 self-center text-text-muted shrink-0">
              <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              aria-label="Check a tool"
              placeholder={value ? '' : hint}
              className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[15.5px] text-text placeholder:text-text-muted"
            />
            <button type="submit" className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow whitespace-nowrap">
              Check
            </button>
          </form>

          <div className="mt-4 flex flex-wrap gap-2 justify-center items-center">
            <span className="font-mono text-[11.5px] text-text-muted/70">try one:</span>
            {EXAMPLES.map((c) => (
              <button
                key={c}
                onClick={() => { setValue(c); runCheck(c) }}
                className="font-mono text-[12.5px] text-text-muted bg-surface border border-border rounded-full px-3 py-1.5 hover:border-primary-light hover:text-primary-light transition-colors"
              >
                {c}
              </button>
            ))}
          </div>
        </motion.div>
      </section>

      {/* ② PROOF-OF-SCALE STRIP — LIVE, numbers count up. Moved up: scale credibility first. */}
      <section className="max-w-[1080px] mx-auto px-6 pt-4 pb-10">
        <Reveal>
          <div className="glass rounded-2xl p-8 flex flex-wrap gap-x-10 gap-y-4 justify-center text-center">
            {[
              [s?.total_scans ?? 0, 'tools scanned'],
              [s?.by_surface?.mcp ?? 0, 'MCP servers'],
              [s?.by_surface?.x402 ?? 0, 'x402 endpoints'],
              [s?.repo_scans_total ?? 0, 'repos scanned'],
              [12, 'detection categories'],
            ].map(([n, l]) => (
              <div key={l as string}>
                {s || n === 12
                  ? <CountUp value={n as number} className="block text-3xl tracking-tight tabular-nums gradient-text font-bold" />
                  : <b className="block text-3xl tracking-tight tabular-nums gradient-text">—</b>}
                <span className="text-[13px] text-text-muted">{l}</span>
              </div>
            ))}
            <div className="basis-full font-mono text-[11.5px] text-text-muted/70 mt-1">
              live from the scan catalog · a one-time launch corpus (not continuously re-scanned)
            </div>
          </div>
        </Reveal>
      </section>

      {/* ③ TWO-AUDIENCE FORK — styled to stand out */}
      <section className="max-w-[1080px] mx-auto px-6 py-14">
        <Reveal className="grid md:grid-cols-2 gap-4">
          <Link to="/rebrand/browse" className="group glass card-hover rounded-2xl p-6 flex flex-col gap-2 border-l-4 border-primary/60 relative overflow-hidden">
            <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-primary/10 blur-2xl group-hover:bg-primary/20 transition-colors" />
            <div className="font-mono text-[11px] uppercase tracking-wide text-primary-light">Checking a tool</div>
            <h3 className="text-xl font-bold">Browse the trust catalog</h3>
            <p className="text-text-muted text-[14.5px] flex-1">
              See tools ranked by grade before you connect one — with the exact reason for each score, not a
              star rating.
            </p>
            <span className="mt-2 self-start text-[14.5px] font-semibold text-primary-light group-hover:translate-x-1 transition-transform">Browse the catalog →</span>
          </Link>
          <Link to="/rebrand/badge" className="group glass card-hover rounded-2xl p-6 flex flex-col gap-2 border-l-4 border-accent/60 relative overflow-hidden">
            <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-accent/10 blur-2xl group-hover:bg-accent/20 transition-colors" />
            <div className="font-mono text-[11px] uppercase tracking-wide text-accent">Building a tool</div>
            <h3 className="text-xl font-bold">Get a signed badge</h3>
            <p className="text-text-muted text-[14.5px] flex-1">
              Drop a signed trust badge in your README in one line. Every viewer can verify the grade — and
              gate your CI on it.
            </p>
            <span className="mt-2 self-start text-[14.5px] font-semibold text-accent group-hover:translate-x-1 transition-transform">Get your badge →</span>
          </Link>
        </Reveal>
      </section>

      {/* ④ SIGNED RESULT EXAMPLE — the trust score, verifiable */}
      <section id="proof" className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <Reveal>
          <div className="text-center max-w-[56ch] mx-auto">
            <Eyebrow>A trust score you can verify</Eyebrow>
            <h2 className="mt-3 text-2xl md:text-3xl font-bold">Two scores, one signed record.</h2>
            <p className="mt-3 text-text-muted">
              Attestation Trust is your signed safety grade. Adoption shows how much the ecosystem actually
              uses a tool — real usage, not opinions.
            </p>
          </div>

          {example ? (
            <div className="glass rounded-2xl overflow-hidden max-w-[620px] mx-auto mt-8">
              <div className="flex items-center gap-4 p-5 border-b border-border/60">
                <div className={`w-14 h-14 rounded-2xl grid place-items-center text-2xl font-extrabold ${example.g.textClass} ${example.g.bgClass}`}>{example.g.grade}</div>
                <div className="min-w-0">
                  <div className="font-mono text-[13px] text-text-muted break-all">{example.display}</div>
                  <div className="mt-1 text-[12px] font-semibold gradient-text">a real scan · {example.row.trust_score}/100</div>
                </div>
              </div>
              <div className="p-4 border-b border-border/60"><DualScore score={example.row.trust_score as number} adoption={exAdoption} /></div>
              <div className="p-5 flex flex-wrap gap-5 text-[13px] text-text-muted">
                <span><b className="text-danger tabular-nums">{example.row.critical ?? 0}</b> critical</span>
                <span><b className="text-warning tabular-nums">{example.row.high ?? 0}</b> high</span>
                <span><b className="text-text tabular-nums">{example.row.findings_count ?? 0}</b> total findings</span>
              </div>
              <div className="flex items-center gap-2.5 p-4 border-t border-dashed border-border flex-wrap">
                <span className="flex items-center gap-2 font-mono text-[12px] text-success">
                  <svg viewBox="0 0 24 24" fill="none" className="w-[18px] h-[18px]">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" />
                    <path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  Signed · Ed25519 / JWS
                </span>
                {example.repoPath && <Link to={`/rebrand/check/${example.repoPath}`} className="ml-auto text-[13px] font-semibold text-primary-light hover:text-primary">See the full report →</Link>}
              </div>
            </div>
          ) : (
            <div className="glass rounded-2xl max-w-[620px] mx-auto mt-8 h-[260px] animate-pulse" />
          )}
        </Reveal>
      </section>

      {/* ⑤ HOW IT WORKS — moved above browse */}
      <section id="how" className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <Reveal>
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
        </Reveal>
      </section>

      {/* ⑤b THREE AXES — where AgentAvow fits (identity kept on the homepage as reference) */}
      <section className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <Reveal>
          <div className="max-w-[58ch]">
            <Eyebrow>The three axes of agent trust</Eyebrow>
            <h2 className="mt-3 text-2xl md:text-3xl font-bold">Identity and authorization are handled. The tool it connects to isn't.</h2>
            <p className="mt-3 text-text-muted">A perfectly identified, fully authorized agent can still connect to a poisoned tool. That third axis is the one we own.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-4 mt-8">
            <div className="glass rounded-2xl p-6">
              <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Axis 01 · Identity</div>
              <h3 className="mt-2 text-lg font-semibold">Who's behind this agent?</h3>
              <p className="mt-2 text-text-muted text-[14px]">Verifiable identity + provenance — DIDs, operator accountability.</p>
            </div>
            <div className="glass rounded-2xl p-6">
              <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted">Axis 02 · Authorization</div>
              <h3 className="mt-2 text-lg font-semibold">Is it allowed to act?</h3>
              <p className="mt-2 text-text-muted text-[14px]">Permission + policy for what an agent may do — OAuth-style controls.</p>
            </div>
            <div className="glass card-hover rounded-2xl p-6 border-l-4 border-primary relative overflow-hidden">
              <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-primary/15 blur-2xl" />
              <div className="font-mono text-[11px] uppercase tracking-wide text-primary-light">Axis 03 · Tool-safety</div>
              <h3 className="mt-2 text-lg font-semibold gradient-text">Is what it connects to safe?</h3>
              <p className="mt-2 text-text-muted text-[14px]">The unguarded surface — the tools, MCP servers, and skills an agent uses. This is AgentAvow.</p>
            </div>
          </div>
        </Reveal>
      </section>

      {/* ⑥ BROWSE TEASER (live) */}
      <section className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <Reveal>
          <div className="max-w-[56ch]">
            <Eyebrow>Browse</Eyebrow>
            <h2 className="mt-3 text-2xl md:text-3xl font-bold">See how the tools you're about to trust actually score.</h2>
            <p className="mt-3 text-text-muted">Safest-first. Open any tool for the evidence behind its grade.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-3.5 mt-8">
            {teaser.length > 0
              ? teaser.map((row) => {
                  const { display, repoPath } = rowIdentity(row)
                  const g = getGradeInfo(row.trust_score as number)
                  return (
                    <Link key={display} to={repoPath ? `/rebrand/check/${repoPath}` : '/rebrand/browse'} className="glass card-hover rounded-xl p-[18px] block">
                      <div className="flex items-center justify-between gap-2.5">
                        <span className="font-mono text-[13.5px] break-all">{display}</span>
                        <span className={`font-extrabold text-[13px] px-2.5 py-0.5 rounded-lg ${g.textClass} ${g.bgClass}`}>{g.grade}</span>
                      </div>
                      <div className="mt-3 text-[12.5px] text-primary-light">Why this grade →</div>
                    </Link>
                  )
                })
              : Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="glass rounded-xl p-[18px] animate-pulse h-[86px]" />
                ))}
          </div>
          <div className="mt-6"><Link to="/rebrand/browse" className="text-[14px] font-semibold text-primary-light hover:text-primary">Browse the full catalog →</Link></div>
        </Reveal>
      </section>

      {/* ⑦ DEVELOPER STRIP — the badge loop */}
      <section id="developers" className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <Reveal>
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
              <p className="text-text-muted text-[14.5px]">The badge regenerates on every view, so it never goes stale. It's signed and links back to a full, verifiable report — no account required to mint one.</p>
              <Link to="/rebrand/badge" className="inline-block mt-4 font-mono text-[13px] text-primary-light hover:text-primary">Wire it into CI with the GitHub Action · SDK · CLI →</Link>
            </div>
          </div>
        </Reveal>
      </section>

      {/* ⑧ TWO EARNED PATHS — change alerts + CI gate */}
      <section className="max-w-[1080px] mx-auto px-6 py-14 border-t border-border/60">
        <Reveal>
          <div className="text-center max-w-[56ch] mx-auto">
            <Eyebrow>Stay safe over time</Eyebrow>
            <h2 className="mt-2.5 text-2xl md:text-3xl font-bold">A tool is only safe until it <span className="gradient-text">changes</span>.</h2>
            <p className="mt-3 text-text-muted">Vetting once isn't enough — tools get updated, and a clean scan can quietly go bad. Two ways to never get caught by it.</p>
          </div>
          <div className="grid md:grid-cols-2 gap-4 mt-8">
            <div className="glass rounded-2xl p-7 flex flex-col">
              <div className="font-mono text-[11.5px] uppercase tracking-wide text-primary-light">For anyone</div>
              <h3 className="mt-2 text-xl font-semibold">Get change alerts</h3>
              <p className="mt-2 text-text-muted text-[14.5px] flex-1">Watch the tools you depend on. We re-scan them and alert you the moment a grade drops or a signed definition changes — the rug-pull you'd otherwise miss.</p>
              <Link to="/rebrand/login" className="mt-5 self-start font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Get change alerts →</Link>
            </div>
            <div className="glass rounded-2xl p-7 flex flex-col">
              <div className="font-mono text-[11.5px] uppercase tracking-wide text-accent">For developers</div>
              <h3 className="mt-2 text-xl font-semibold">Add to your CI</h3>
              <p className="mt-2 text-text-muted text-[14.5px] flex-1">Run the scan on every pull request with the GitHub Action. Gate merges on a minimum grade so a dependency can never silently regress in your pipeline.</p>
              <Link to="/rebrand/badge" className="mt-5 self-start font-semibold px-5 py-2.5 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Add to your CI →</Link>
            </div>
          </div>
        </Reveal>
      </section>
    </div>
  )
}
