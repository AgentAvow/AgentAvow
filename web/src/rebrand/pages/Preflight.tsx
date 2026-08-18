import { useState } from 'react'
import { Link } from 'react-router-dom'

import { getTrustTier } from '../../components/trust/gradeSystem'
import api from '../../lib/api'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

/**
 * Connector Preflight — a pre-submission readiness check for the Anthropic Claude
 * connectors directory + OpenAI apps directory. Point it at an MCP server or repo;
 * it scans and checks against the stores' published rejection gates, and hands back
 * a Directory-Ready verdict with the signed score as the byproduct.
 */

interface Gate {
  id: string
  label: string
  status: 'pass' | 'fail' | 'warn' | 'unknown' | 'na'
  severity: 'blocker' | 'warning'
  detail: string
  stores: string[]
}
interface Preflight {
  target: string
  surface: string
  directory_ready: boolean
  headline: string
  trust_score: number
  trust_tier: string
  certified: boolean
  gates: Gate[]
  summary: { blockers_total: number; blockers_failed: number; warnings: number }
  signed: { report_url: string; jwks_url: string }
}

const STATUS_UI: Record<Gate['status'], { icon: string; cls: string }> = {
  pass: { icon: '✓', cls: 'text-success' },
  fail: { icon: '✕', cls: 'text-danger' },
  warn: { icon: '!', cls: 'text-warning' },
  unknown: { icon: '?', cls: 'text-text-muted' },
  na: { icon: '–', cls: 'text-text-muted' },
}
const STORE_LABEL: Record<string, string> = { anthropic: 'Claude', openai: 'OpenAI' }

/** Parse "owner/repo", a github URL, or an https MCP endpoint into an API path. */
function toRequest(raw: string): { path: string; kind: 'repo' | 'mcp' } | null {
  const s = raw.trim()
  if (!s) return null
  if (/^https?:\/\//i.test(s)) {
    const gh = s.match(/github\.com\/([^/]+)\/([^/#?]+)/i)
    if (gh) return { path: `/public/preflight/${gh[1]}/${gh[2].replace(/\.git$/, '')}`, kind: 'repo' }
    return { path: `/public/preflight/mcp?endpoint=${encodeURIComponent(s)}`, kind: 'mcp' }
  }
  const m = s.match(/^([\w.-]+)\/([\w.-]+)$/)
  if (m) return { path: `/public/preflight/${m[1]}/${m[2]}`, kind: 'repo' }
  return null
}

function GateRow({ g }: { g: Gate }) {
  const ui = STATUS_UI[g.status]
  return (
    <div className="flex gap-3 py-3 border-b border-border/40 last:border-0">
      <span className={`mt-0.5 shrink-0 w-5 h-5 grid place-items-center rounded-full text-[12px] font-bold ${ui.cls} bg-surface border border-current/30`}>{ui.icon}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[14px] font-semibold">{g.label}</span>
          {g.severity === 'blocker' && <span className="text-[10px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded bg-danger/10 text-danger">blocker</span>}
          <span className="ml-auto flex gap-1">
            {g.stores.map((st) => (
              <span key={st} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-border/60 text-text-muted">{STORE_LABEL[st] ?? st}</span>
            ))}
          </span>
        </div>
        <p className="text-[12.5px] text-text-muted mt-0.5 leading-snug">{g.detail}</p>
      </div>
    </div>
  )
}

export default function RebrandPreflight() {
  const [input, setInput] = useState('')
  const [data, setData] = useState<Preflight | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const run = async () => {
    const req = toRequest(input)
    if (!req) { setError('Enter an owner/repo, a GitHub URL, or an https:// MCP endpoint.'); return }
    setLoading(true); setError(''); setData(null)
    try {
      const res = await api.get<Preflight>(req.path)
      setData(res.data)
    } catch (e) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(detail || 'Could not run preflight — check the target and try again.')
    } finally {
      setLoading(false)
    }
  }

  const tier = data ? getTrustTier(data.trust_score) : null
  const blockers = data?.gates.filter((g) => g.severity === 'blocker') ?? []
  const warnings = data?.gates.filter((g) => g.severity === 'warning') ?? []

  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Connector Preflight</span>
        <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight leading-[1.08]">
          Will your connector pass <span className="gradient-text-bio">app-store review</span>?
        </h1>
        <p className="mt-4 text-text-muted text-[15.5px] leading-relaxed max-w-[64ch]">
          Before you submit to the <strong className="text-text">Claude connectors</strong> directory or <strong className="text-text">OpenAI apps</strong>,
          run a preflight. We scan your MCP server or repo and check it against the stores' own published
          rejection gates — safety-hint truthfulness, exfiltration surface, auth, injection-free descriptions —
          so you fix it here instead of losing a week to a rejection. You get a signed trust score either way.
        </p>
      </Reveal>

      <Reveal>
        <div className="mt-8 flex gap-2.5 flex-wrap">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
            placeholder="owner/repo, a GitHub URL, or https://your-server/mcp"
            className="flex-1 min-w-[240px] px-4 py-3 rounded-xl bg-surface border border-border focus:border-primary-light outline-none text-[14px] font-mono"
          />
          <button onClick={run} disabled={loading} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 disabled:opacity-60">
            {loading ? 'Checking…' : 'Run preflight →'}
          </button>
        </div>
        {error && <p className="mt-3 text-[13px] text-danger">{error}</p>}
      </Reveal>

      {loading && <div className="mt-8 glass rounded-2xl h-[220px] animate-pulse" />}

      {data && tier && (
        <Reveal>
          {/* verdict banner */}
          <div className={`mt-8 rounded-2xl p-6 border-l-4 glass ${data.directory_ready ? 'border-success' : 'border-warning'}`}>
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div>
                <div className={`text-[13px] font-mono uppercase tracking-wide ${data.directory_ready ? 'text-success' : 'text-warning'}`}>
                  {data.directory_ready ? '● Directory-Ready' : '● Needs changes before you submit'}
                </div>
                <h2 className="mt-1 text-2xl font-extrabold">{data.target}</h2>
                <p className="text-[13px] text-text-muted mt-0.5">
                  {data.summary.blockers_total - data.summary.blockers_failed}/{data.summary.blockers_total} blockers pass
                  {data.summary.warnings > 0 && ` · ${data.summary.warnings} warning${data.summary.warnings === 1 ? '' : 's'}`}
                </p>
              </div>
              <div className="text-right">
                <div className="font-mono text-[34px] font-bold tabular-nums leading-none" style={{ color: tier.color }}>{data.trust_score}</div>
                <div className="text-[11px] text-text-muted mt-1">{tier.name}{data.certified && ' · Certified'}</div>
              </div>
            </div>
          </div>

          {/* blockers */}
          <div className="mt-6 glass rounded-2xl px-6 py-4">
            <h3 className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-1">Blockers — must pass to be listed</h3>
            {blockers.map((g) => <GateRow key={g.id} g={g} />)}
          </div>

          {/* warnings */}
          {warnings.length > 0 && (
            <div className="mt-4 glass rounded-2xl px-6 py-4">
              <h3 className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-1">Recommended — clean these up</h3>
              {warnings.map((g) => <GateRow key={g.id} g={g} />)}
            </div>
          )}

          <div className="mt-5 flex gap-4 text-[13px] flex-wrap">
            <a href={data.signed.report_url} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary font-semibold">Full signed report ↗</a>
            <Link to={rp('/rebrand/for-developers')} className="text-primary-light hover:text-primary font-semibold">Get your README badge →</Link>
            <Link to={rp('/rebrand/certified')} className="text-text-muted hover:text-text">What Certified means →</Link>
          </div>
        </Reveal>
      )}

      {!data && !loading && (
        <Reveal>
          <div className="mt-10 grid sm:grid-cols-3 gap-3">
            {[
              ['Scan', 'We handshake your live MCP server (or scan the repo) and enumerate the real surface.'],
              ['Check the gates', "Each finding maps to a store's actual, published review criterion — not our opinion."],
              ['Fix, then submit', 'Clear the blockers here and walk into review already knowing you pass.'],
            ].map(([h, p]) => (
              <div key={h} className="glass rounded-xl p-4">
                <div className="text-[14px] font-semibold">{h}</div>
                <p className="text-[12.5px] text-text-muted mt-1 leading-relaxed">{p}</p>
              </div>
            ))}
          </div>
        </Reveal>
      )}
    </div>
  )
}
