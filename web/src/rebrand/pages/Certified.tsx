import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import api from '../../lib/api'
import { isCertified, certifiedMarkNote, decisionOf, decisionPhrase } from '../../components/trust/gradeSystem'
import { rp } from '../basePath'
import { type CatalogRow, rowIdentity } from '../catalog'
import { AdoptionMini, CertifiedBadge, TrustMini } from '../components/TrustMark'
import { Reveal } from '../components/motion'
import { CtaBand, PageHeader, SECTION_CLASS, SectionH2 } from '../components/PageBits'
import SEOHead from '../../components/SEOHead'

const PKG_SURFACES = ['npm', 'pypi', 'crates', 'docker', 'hf']

/** Per-surface check link for a certified catalog row. */
function certLink(row: CatalogRow): string | null {
  const fn = row.full_name || ''
  if (PKG_SURFACES.includes(row.surface)) {
    const nm = (row.name || '').includes(':') ? (row.name || '').split(':').slice(1).join(':') : row.name
    return nm ? rp(`/rebrand/check/pkg/${row.surface}/${nm}`) : null
  }
  if (fn.includes('/')) return rp(`/rebrand/check/${fn}`)
  return null
}

/**
 * Certified — the public, legible gate. Documents exactly what earns the top tier
 * (a conjunctive gate — every check must pass) and the hard disqualifiers, then
 * renders the gate LIVE against any tool. The wedge vs opaque directory scores:
 * we show why something does or doesn't pass.
 */

// The six conjunctive checks — keys match backend `certified.checks`
// (src/scanner/scan.py:_certified_status). [key, the gate's sentence, the short label
// the live check uses].
const CHECKS: [string, string, string][] = [
  ['artifact_scanned', 'The published artifact was scanned — not just the source repo.', 'The published package was checked, not just its repo'],
  ['provenance_verified', 'Build provenance is cryptographically verified (npm Sigstore / PyPI PEP 740) and binds to the source repo.', 'Build provenance verified'],
  ['no_drift', 'The published artifact matches its source: no added or modified files, no install hook.', 'The package matches its source'],
  ['no_critical_or_high', 'Zero critical or high findings — and nothing known-malicious.', 'No critical or high finding'],
  ['recompute_ready', 'The verdict is offline-recomputable — full coverage metadata is recorded.', 'Anyone can recompute it offline'],
  ['full_coverage', 'The entire tree was scanned, not sampled.', 'Every file read'],
]

/** The hero badge shows a real Certified tool: zod while it holds the mark, else the
 * top of the live cohort. */
const HERO_TOOL = 'npm:zod'

const DISQUALIFIERS: [string, string][] = [
  ['Any critical finding', 'A shipped critical caps the score at 45 — Certified is off the table until it’s fixed.'],
  ['A known-malicious dependency', 'A dependency flagged malicious (MAL) costs 70 points and the answer is Do not connect. No exceptions.'],
  ['Unverified build provenance', 'The most common reason a good tool isn’t Certified: it publishes no cryptographic build attestation, so we can’t prove the artifact came from the source you claim.'],
  ['Sampled or partial coverage', 'If we couldn’t scan the whole tree, we won’t certify what we didn’t see.'],
  ['Any answer but Safe to connect', 'A deprecation, an advisory against this version, a high finding or a sandbox catch makes the answer Review, and the mark comes off until it reads Safe again. So does a score under 81, a sandbox run still in progress, or too little code to inspect.'],
]

interface Certified { eligible: boolean; checks: Record<string, boolean> }

function toPath(raw: string): string | null {
  const s = raw.trim()
  const gh = s.match(/github\.com\/([^/]+)\/([^/#?]+)/i)
  if (gh) return `/public/scan/${gh[1]}/${gh[2].replace(/\.git$/, '')}`
  const m = s.match(/^([\w.-]+)\/([\w.-]+)$/)
  if (m) return `/public/scan/${m[1]}/${m[2]}`
  return null
}

const CERT_SURFACE_LABEL: Record<string, string> = {
  npm: 'npm packages', pypi: 'Python packages', github: 'GitHub repos', mcp: 'MCP servers',
  crates: 'Rust crates', docker: 'container images', huggingface: 'Hugging Face models', openclaw: 'skills',
}

export default function RebrandCertified() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState<{ target: string; certified: Certified; mark: boolean; note: string; score: number | null; decision: ReturnType<typeof decisionOf>['decision'] } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [cohort, setCohort] = useState<CatalogRow[]>([])
  const [hero, setHero] = useState<CatalogRow | null>(null)
  const [cohortTotal, setCohortTotal] = useState<number | null>(null)
  const [bySurface, setBySurface] = useState<[string, number][]>([])

  useEffect(() => {
    let alive = true
    // One read of the whole Certified set (it is small): the first 16 are the cohort,
    // and the per-surface split is what the Browse filters show for each tab.
    api.get<{ rows: CatalogRow[]; total?: number }>('/public/scan-catalog', {
      params: { grade: 'certified', sort: 'score-desc', limit: 200 },
    }).then((r) => {
      if (!alive) return
      const rows = r.data.rows ?? []
      setCohort(rows.slice(0, 16))
      const marked = rows.filter((row) => row.trust_score != null && isCertified(row))
      setHero(marked.find((row) => row.full_name === HERO_TOOL) ?? marked[0] ?? null)
      setCohortTotal(r.data.total ?? rows.length)
      const counts: Record<string, number> = {}
      for (const row of rows) counts[row.surface] = (counts[row.surface] ?? 0) + 1
      setBySurface(Object.entries(counts).sort((a, b) => b[1] - a[1]))
    }).catch(() => { /* non-blocking */ })
    return () => { alive = false }
  }, [])

  const run = async () => {
    const path = toPath(input)
    if (!path) { setError('Enter an owner/repo or a GitHub URL.'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const res = await api.get<{ certified?: Certified; trust_score?: number | null }>(path)
      setResult({
        target: input.trim(), certified: res.data.certified ?? { eligible: false, checks: {} },
        mark: isCertified(res.data), note: certifiedMarkNote(res.data),
        score: typeof res.data.trust_score === 'number' ? res.data.trust_score : null,
        decision: decisionOf(res.data).decision,
      })
    } catch {
      setError('Could not scan that target — check it and try again.')
    } finally {
      setLoading(false)
    }
  }

  const heroName = hero ? (hero.name || rowIdentity(hero).display) : null

  return (
    <div>
      <SEOHead
        title="Certified — the earned mark beside Safe to connect"
        description="Certified is a public gate above the trust score: every check must pass, no averaging. See why a tool does or doesn't earn it, and which tools have."
        path="/certified"
      />
      <PageHeader
        width={860}
        eyebrow="Certified"
        title={<>The top tier is <span className="gradient-text-bio">earned</span>, and the gate is public.</>}
        lede={<>Most directories give you an opaque number and ask you to trust it. Certified is the opposite: a <b className="font-medium text-text">conjunctive gate</b> — every check below must pass, no averaging, no cheating — published in full, so you can see exactly why a tool does or doesn't earn it.</>}
      >
        {/* A live certified tool; the prerender names no tool, so it keeps the space. */}
        <div className="mt-[22px] flex items-center gap-4 flex-wrap min-h-[124px]">
          {hero && heroName ? (
            <>
              <CertifiedBadge score={hero.trust_score as number} size="lg" />
              <p className="text-[12.5px] text-text-muted max-w-[30ch]">The mark: the trust score inside it, shown once, and only on a tool that earned it. This one is {heroName}'s.</p>
            </>
          ) : null}
        </div>
      </PageHeader>

      {/* proof — the real cohort, live from the catalog */}
      {cohort.length > 0 && (
        <section className={SECTION_CLASS}>
          <div className="max-w-[860px] mx-auto px-6">
            <Reveal>
              <SectionH2 size="sub">It's not theoretical — {cohortTotal ?? cohort.length} tools are Certified today</SectionH2>
              <p className="mt-1.5 text-text-muted text-[14.5px] max-w-[64ch]">Earned, not assigned — each one publishes verifiable build provenance and clears every check below. Recognize a few? That's the point.</p>
              {bySurface.length > 0 && (
                <p className="mt-2 font-mono text-[12px] text-text-muted">
                  {bySurface.map(([surf, n], i) => (
                    <span key={surf}>{i > 0 && ' · '}<Link className="hover:text-primary-light" to={rp(`/rebrand/browse?surface=${surf}&grade=certified`)}>{n} {CERT_SURFACE_LABEL[surf] || surf}</Link></span>
                  ))}
                </p>
              )}
              <p className="mt-2 text-text-muted text-[12.5px] max-w-[64ch]">Certified needs a published package with verifiable build provenance: npm (Sigstore), PyPI (PEP 740 Trusted Publishing) or a GitHub repo whose package provenance points back at it. An MCP server checked by URL can earn it only through its published package; hosted code we can't inspect can't be certified.</p>
              <div className="mt-3.5 flex flex-wrap gap-2">
                {cohort.map((row) => {
                  const href = certLink(row)
                  const label = rowIdentity(row).display
                  const pill = (
                    <span className="inline-flex items-center gap-2 max-w-full rounded-full pl-1 pr-3 py-1 bg-surface border border-border hover:border-primary-light transition-colors font-mono text-[12.5px] text-text">
                      {row.trust_score != null && isCertified(row) ? <CertifiedBadge score={row.trust_score} size="sm" /> : row.trust_score != null ? <TrustMini score={row.trust_score} /> : null}
                      <span className="min-w-0 [overflow-wrap:anywhere]">{label}</span>
                      <span className="pl-[9px] ml-0.5 border-l border-border"><AdoptionMini count={row.adoption_count} unit={row.adoption_unit} /></span>
                    </span>
                  )
                  return href
                    ? <Link key={label} to={href} className="max-w-full">{pill}</Link>
                    : <span key={label} className="max-w-full">{pill}</span>
                })}
              </div>
              <Link to={rp('/rebrand/index') + '#certified'} className="inline-block mt-3.5 text-[14px] font-semibold text-primary-light hover:text-primary">See the Certified board on the Trust Index →</Link>
            </Reveal>
          </div>
        </section>
      )}

      {/* the gate */}
      <section className={SECTION_CLASS}>
        <div className="max-w-[860px] mx-auto px-6">
          <Reveal>
            <SectionH2 size="sub">What it takes — all six, or it's not Certified</SectionH2>
            <div className="mt-4 glass rounded-2xl border border-border/60 px-[18px] py-1">
              {CHECKS.map(([key, label]) => (
                <div key={key} className="flex gap-3 py-3 border-b border-border/60 last:border-0">
                  <span className="mt-px shrink-0 w-[22px] h-[22px] grid place-items-center rounded-full text-[12px] font-extrabold text-primary-light border border-primary-light" aria-hidden="true">✓</span>
                  <div className="min-w-0">
                    <p className="text-[14px]">{label}</p>
                    <code className="font-mono text-[11px] text-text-muted">{key}</code>
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-3 text-text-muted text-[13.5px] max-w-[66ch]">Plus the answer: the mark shows only beside <b className="font-medium text-text">Safe to connect, at a trust score of 81 or above</b>, once the sandbox result is in and with enough code to inspect (8 or more files). A tool that passes the six checks but reads Review keeps a "Certified checks pass" note on its page, not the mark. The score and trust tier are never gated, only the Certified mark is.</p>
          </Reveal>
        </div>
      </section>

      {/* disqualifiers */}
      <section className={SECTION_CLASS}>
        <div className="max-w-[860px] mx-auto px-6">
          <Reveal>
            <SectionH2 size="sub">Hard disqualifiers</SectionH2>
            <p className="mt-1.5 text-text-muted text-[14.5px] max-w-[62ch]">Publishing the gate is only half of it — here's what fails a tool outright, so no one has to guess.</p>
            <div className="mt-4 grid sm:grid-cols-2 gap-3">
              {DISQUALIFIERS.map(([h, p], i) => (
                <div key={h} className={`relative glass rounded-2xl border border-border/60 py-4 pr-[18px] pl-[22px] ${i === DISQUALIFIERS.length - 1 && DISQUALIFIERS.length % 2 ? 'sm:col-span-2' : ''}`}>
                  <span className="absolute left-0 top-3.5 bottom-3.5 w-[3px] rounded-r-[3px] bg-danger/75" aria-hidden="true" />
                  <h3 className="text-[15px] font-bold">{h}</h3>
                  <p className="text-[13.5px] text-text-muted mt-1">{p}</p>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      {/* live check */}
      <section className={SECTION_CLASS}>
        <div className="max-w-[860px] mx-auto px-6">
          <Reveal>
            <SectionH2 size="sub">Check any tool against the gate</SectionH2>
            <form onSubmit={(e) => { e.preventDefault(); run() }} className="glass mt-4 flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                aria-label="Tool to check"
                placeholder="owner/repo or a GitHub URL"
                className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[14.5px] text-text placeholder:text-text-muted"
              />
              <button type="submit" disabled={loading} className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 disabled:opacity-60 whitespace-nowrap">
                {loading ? 'Scanning…' : 'Check the gate →'}
              </button>
            </form>
            {error && <p className="mt-3 text-[13px] text-danger">{error}</p>}
            {result && <GateResult result={result} />}
          </Reveal>
        </div>
      </section>

      <section className={SECTION_CLASS}>
        <div className="max-w-[860px] mx-auto px-6">
          <Reveal>
            <CtaBand
              title="Ship a tool that clears the bar."
              line="Run a store preflight, or claim your tool and add its badge."
              primary={{ label: 'Run a store preflight', to: rp('/rebrand/preflight') }}
              secondary={{ label: 'For developers', to: rp('/rebrand/for-developers') }}
            />
          </Reveal>
        </div>
      </section>
    </div>
  )
}

/** The live gate result: the badge only when earned (else the plain score), the six
 * checks with plain labels, and the deciding answer line. */
function GateResult({ result }: { result: { target: string; certified: Certified; mark: boolean; note: string; score: number | null; decision: ReturnType<typeof decisionOf>['decision'] } }) {
  const p = decisionPhrase(result.decision)
  const answerOk = result.decision === 'safe' && result.score != null && result.score >= 81
  const path = toPath(result.target)
  const report = path ? rp(`/rebrand/check/${path.replace('/public/scan/', '')}`) : null
  return (
    <div className={`mt-3.5 glass rounded-2xl border px-5 py-4 ${result.mark ? 'border-primary-light/45' : 'border-border/60'}`}>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <span className="flex items-center gap-2.5 flex-wrap min-w-0">
          <b className="font-mono text-[14px] [overflow-wrap:anywhere]">{result.target}</b>
          {result.score != null && (result.mark ? <CertifiedBadge score={result.score} size="sm" /> : <TrustMini score={result.score} />)}
          {!result.mark && (
            <span className={`text-[11.5px] font-mono uppercase tracking-wide px-2 py-0.5 rounded ${result.certified.eligible ? 'bg-warning/10 text-warning' : 'bg-surface-hover text-text-muted'}`}>
              {result.certified.eligible ? 'Checks pass · no mark' : 'Not certified'}
            </span>
          )}
        </span>
        {report && <Link to={report} className="text-[13.5px] font-semibold text-primary-light hover:text-primary">Open the full result →</Link>}
      </div>
      {!result.mark && result.note && <p className="mt-2 text-[13px] text-text-muted">{result.note}</p>}
      <ul className="mt-3 list-none p-0 m-0">
        {CHECKS.map(([key, , short]) => {
          const ok = result.certified.checks[key]
          return (
            <li key={key} className="flex gap-2.5 items-baseline flex-wrap py-2 border-b border-border/60 text-[13.5px]">
              <span className={`shrink-0 w-4 text-center font-bold ${ok ? 'text-success' : 'text-danger'}`} aria-label={ok ? 'pass' : 'fail'}>{ok ? '✓' : '✕'}</span>
              <span className="min-w-0 flex-1">{short}</span>
              <code className="font-mono text-[11px] text-text-muted">{key}</code>
            </li>
          )
        })}
        <li className="flex gap-2.5 items-baseline py-2 text-[13.5px] font-semibold">
          <span className={`shrink-0 w-4 text-center font-bold ${answerOk ? 'text-success' : 'text-danger'}`} aria-label={answerOk ? 'pass' : 'fail'}>{answerOk ? '✓' : '✕'}</span>
          <span>Answer: Safe to connect at 81+ <span className="font-normal text-text-muted">(reads {p.phrase}{result.score != null ? ` at ${result.score}` : ''})</span></span>
        </li>
      </ul>
    </div>
  )
}
