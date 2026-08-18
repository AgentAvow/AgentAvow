import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import api from '../../lib/api'
import { rp } from '../basePath'
import { type CatalogRow, rowIdentity } from '../catalog'
import { CertifiedMark } from '../components/TrustMark'
import { Reveal } from '../components/motion'

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
// (src/scanner/scan.py:_certified_status).
const CHECKS: [string, string][] = [
  ['artifact_scanned', 'The published artifact was scanned — not just the source repo.'],
  ['provenance_verified', 'Build provenance is cryptographically verified (npm Sigstore / PyPI PEP 740) and binds to the source repo.'],
  ['no_drift', 'No unexpected files, modifications, or install hooks added since the last signed scan.'],
  ['no_critical_or_high', 'Zero critical or high findings — and nothing known-malicious.'],
  ['recompute_ready', 'The verdict is offline-recomputable — full coverage metadata is recorded.'],
  ['full_coverage', 'The entire tree was scanned, not sampled.'],
]

const DISQUALIFIERS: [string, string][] = [
  ['Any critical finding', 'A single unresolved critical caps the grade at B — Certified is off the table until it’s fixed.'],
  ['A known-malicious dependency', 'A dependency flagged malicious (MAL) forces the score to F. No exceptions.'],
  ['Unverified build provenance', 'The most common reason a good tool isn’t Certified: it publishes no cryptographic build attestation, so we can’t prove the artifact came from the source you claim.'],
  ['Sampled or partial coverage', 'If we couldn’t scan the whole tree, we won’t certify what we didn’t see.'],
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

export default function RebrandCertified() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState<{ target: string; certified: Certified } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [cohort, setCohort] = useState<CatalogRow[]>([])
  const [cohortTotal, setCohortTotal] = useState<number | null>(null)

  useEffect(() => {
    let alive = true
    api.get<{ rows: CatalogRow[]; total?: number }>('/public/scan-catalog', {
      params: { grade: 'certified', sort: 'score-desc', limit: 16 },
    }).then((r) => {
      if (!alive) return
      setCohort(r.data.rows ?? [])
      setCohortTotal(r.data.total ?? null)
    }).catch(() => { /* non-blocking */ })
    return () => { alive = false }
  }, [])

  const run = async () => {
    const path = toPath(input)
    if (!path) { setError('Enter an owner/repo or a GitHub URL.'); return }
    setLoading(true); setError(''); setResult(null)
    try {
      const res = await api.get<{ certified?: Certified }>(path)
      setResult({ target: input.trim(), certified: res.data.certified ?? { eligible: false, checks: {} } })
    } catch {
      setError('Could not scan that target — check it and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <Reveal>
        <div className="flex items-start justify-between gap-6 flex-wrap">
          <div className="max-w-[60ch]">
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Certified</span>
            <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight leading-[1.08]">The top tier is <span className="gradient-text-bio">earned</span>, and the gate is public.</h1>
            <p className="mt-4 text-text-muted text-[15.5px] leading-relaxed">
              Most directories give you an opaque number and ask you to trust it. Certified is the opposite:
              a <strong className="text-text">conjunctive gate</strong> — every check below must pass, no averaging, no cheating —
              published in full, so you can see exactly why a tool does or doesn't earn it.
            </p>
          </div>
          <div className="shrink-0"><CertifiedMark score={97} /></div>
        </div>
      </Reveal>

      {/* proof — the real cohort, live from the catalog */}
      {cohort.length > 0 && (
        <Reveal>
          <div className="mt-12">
            <h2 className="text-xl font-bold">It's not theoretical — {cohortTotal ?? cohort.length} tools are Certified today</h2>
            <p className="mt-1.5 text-text-muted text-[14px] max-w-[64ch]">Earned, not assigned — each one publishes verifiable build provenance and clears every check below. Recognize a few? That's the point.</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {cohort.map((row) => {
                const href = certLink(row)
                const label = rowIdentity(row).display
                const pill = (
                  <span className="inline-flex items-center gap-2 rounded-full pl-1 pr-3 py-1 bg-surface border border-border/60 hover:border-primary-light/60 transition-colors">
                    <span className="font-mono text-[10.5px] font-extrabold px-2 py-0.5 rounded-full" style={{ background: 'linear-gradient(120deg,#2dd4bf,#e879f9)', color: '#06231f' }}>✓ {row.trust_score}</span>
                    <span className="font-mono text-[12.5px]">{label}</span>
                  </span>
                )
                return href
                  ? <Link key={label} to={href}>{pill}</Link>
                  : <span key={label}>{pill}</span>
              })}
            </div>
            <Link to={rp('/rebrand/index')} className="inline-block mt-4 text-[13px] font-semibold text-primary-light hover:text-primary">See the full Certified board →</Link>
          </div>
        </Reveal>
      )}

      {/* the gate */}
      <Reveal>
        <h2 className="mt-14 text-xl font-bold">What it takes — all six, or it's not Certified</h2>
        <div className="mt-5 glass rounded-2xl px-6 py-2">
          {CHECKS.map(([key, label]) => (
            <div key={key} className="flex gap-3 py-3.5 border-b border-border/40 last:border-0">
              <span className="mt-0.5 shrink-0 w-5 h-5 grid place-items-center rounded-full text-[12px] font-bold text-primary-light bg-surface border border-primary-light/30">✓</span>
              <div className="min-w-0">
                <code className="font-mono text-[11.5px] text-text-muted">{key}</code>
                <p className="text-[13.5px] mt-0.5 leading-snug">{label}</p>
              </div>
            </div>
          ))}
        </div>
        <p className="mt-3 text-text-muted text-[13px] max-w-[64ch]">Plus the score bar: <strong className="text-text">81+ with zero critical or high findings</strong>. The score and trust tier are never gated — only the Certified label is.</p>
      </Reveal>

      {/* disqualifiers */}
      <Reveal>
        <h2 className="mt-14 text-xl font-bold">Hard disqualifiers</h2>
        <p className="mt-1.5 text-text-muted text-[14px] max-w-[62ch]">Publishing the gate is only half of it — here's what fails a tool outright, so no one has to guess.</p>
        <div className="mt-5 grid sm:grid-cols-2 gap-3">
          {DISQUALIFIERS.map(([h, p]) => (
            <div key={h} className="rounded-xl border border-border/60 p-4 border-l-4 border-l-danger/60">
              <div className="text-[14px] font-semibold">{h}</div>
              <p className="text-[13px] text-text-muted mt-1 leading-relaxed">{p}</p>
            </div>
          ))}
        </div>
      </Reveal>

      {/* live check */}
      <Reveal>
        <h2 className="mt-14 text-xl font-bold">Check any tool against the gate</h2>
        <div className="mt-4 flex gap-2.5 flex-wrap">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
            placeholder="owner/repo or a GitHub URL"
            className="flex-1 min-w-[240px] px-4 py-3 rounded-xl bg-surface border border-border focus:border-primary-light outline-none text-[14px] font-mono"
          />
          <button onClick={run} disabled={loading} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 disabled:opacity-60">
            {loading ? 'Scanning…' : 'Check the gate →'}
          </button>
        </div>
        {error && <p className="mt-3 text-[13px] text-danger">{error}</p>}
        {result && (
          <div className={`mt-5 glass rounded-2xl px-6 py-4 border-l-4 ${result.certified.eligible ? 'border-success' : 'border-warning'}`}>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[15px] font-bold">{result.target}</span>
              <span className={`text-[12px] font-mono uppercase tracking-wide px-2 py-0.5 rounded ${result.certified.eligible ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning'}`}>
                {result.certified.eligible ? 'Certified' : 'Not certified'}
              </span>
            </div>
            <div className="mt-3">
              {CHECKS.map(([key, label]) => {
                const ok = result.certified.checks[key]
                return (
                  <div key={key} className="flex gap-2.5 py-2 border-b border-border/40 last:border-0">
                    <span className={`shrink-0 w-4 h-4 grid place-items-center rounded-full text-[10px] font-bold ${ok ? 'text-success' : 'text-danger'}`}>{ok ? '✓' : '✕'}</span>
                    <span className="text-[13px] text-text-muted leading-snug"><code className="font-mono text-[11.5px]">{key}</code> — {label}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </Reveal>

      <Reveal>
        <div className="mt-14 flex gap-4 text-[14px] flex-wrap">
          <Link to={rp('/rebrand/preflight')} className="font-semibold text-primary-light hover:text-primary">Run a store preflight →</Link>
          <Link to={rp('/rebrand/for-developers')} className="text-text-muted hover:text-text">For developers →</Link>
        </div>
      </Reveal>
    </div>
  )
}
