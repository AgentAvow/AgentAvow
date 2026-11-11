import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'

import api from '../../lib/api'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'
import { CertifiedMark, DecisionLine, TrustBar } from '../components/TrustMark'
import SEOHead from '../../components/SEOHead'

/**
 * Connector Preflight — a pre-submission readiness check for the Claude directory
 * (MCP connectors and plugin bundles) and the ChatGPT apps directory. Point it at a live
 * MCP server or a repo; it scans and checks it against the stores' published review
 * rules (each gate cites its source), lists the rules a URL can't show as a manual
 * checklist, and says when the rules were last checked.
 */

interface Source { title: string; url: string }
interface Gate {
  id: string
  label: string
  status: 'pass' | 'fail' | 'warn' | 'unknown' | 'na'
  severity: 'blocker' | 'hold' | 'warning'
  detail: string
  stores: string[]
  basis?: 'documented' | 'observed' | 'agentavow'
  sources?: Source[]
  group?: 'connector' | 'plugin' | 'safety'
}
interface Preflight {
  target: string
  surface: 'mcp' | 'repo'
  directory_ready: boolean
  headline: string
  decision?: 'safe' | 'review' | 'do_not_connect'
  decision_reason?: string
  trust_score: number | null
  trust_tier: string
  certified: boolean
  gates: Gate[]
  summary: { blockers_total: number; blockers_failed: number; blockers_unknown?: number; holds?: number; warnings: number }
  signed: { report_url?: string; jwks_url?: string }
  scanned?: boolean
  rules_checked?: string
  plugin_folder?: string | null
  plugin_folders?: string[]
}
interface ManualItem { id: string; label: string; store: string; applies_to: 'connector' | 'plugin'; sources: Source[] }
interface Rules { rules_checked: string; stale_after_days: number; manual_checklist: ManualItem[] }

// Shown until /preflight/rules answers; the API is the source of truth.
const RULES_CHECKED_FALLBACK = '2026-11-07'

const STATUS_UI: Record<Gate['status'], { icon: string; cls: string }> = {
  pass: { icon: '✓', cls: 'text-success' },
  fail: { icon: '✕', cls: 'text-danger' },
  warn: { icon: '!', cls: 'text-warning' },
  unknown: { icon: '?', cls: 'text-text-muted' },
  na: { icon: '–', cls: 'text-text-muted' },
}
const STORE_LABEL: Record<string, string> = { anthropic: 'Claude', openai: 'ChatGPT' }

/** Parse "owner/repo", a GitHub URL (optionally to a plugin folder), or an https MCP
 *  endpoint into an API path. */
function toRequest(raw: string): { path: string; kind: 'repo' | 'mcp' } | null {
  const s = raw.trim()
  if (!s) return null
  if (/^https?:\/\//i.test(s)) {
    const gh = s.match(/github\.com\/([^/]+)\/([^/#?]+)(?:\/tree\/[^/#?]+\/([^#?]+))?/i)
    if (gh) {
      const folder = gh[3]?.replace(/\/+$/, '')
      const q = folder ? `?plugin=${encodeURIComponent(folder)}` : ''
      return { path: `/public/preflight/${gh[1]}/${gh[2].replace(/\.git$/, '')}${q}`, kind: 'repo' }
    }
    return { path: `/public/preflight/mcp?endpoint=${encodeURIComponent(s)}`, kind: 'mcp' }
  }
  const m = s.match(/^([\w.-]+)\/([\w.-]+)$/)
  if (m) return { path: `/public/preflight/${m[1]}/${m[2]}`, kind: 'repo' }
  return null
}

function daysSince(iso: string): number {
  const t = Date.parse(`${iso}T00:00:00Z`)
  return Number.isNaN(t) ? 0 : Math.floor((Date.now() - t) / 86_400_000)
}

function SourceLinks({ sources }: { sources?: Source[] }) {
  if (!sources?.length) return null
  return (
    <span className="block mt-1 text-[11.5px]">
      {sources.map((s, i) => (
        <span key={s.url}>
          {i > 0 && <span className="text-text-muted"> · </span>}
          <a href={s.url} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">{s.title} ↗</a>
        </span>
      ))}
    </span>
  )
}

function GateRow({ g }: { g: Gate }) {
  const ui = STATUS_UI[g.status]
  return (
    <div className="flex gap-3 py-3 border-b border-border/40 last:border-0">
      <span className={`mt-0.5 shrink-0 w-5 h-5 grid place-items-center rounded-full text-[12px] font-bold ${ui.cls} bg-surface border border-current/30`}>{ui.icon}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[14px] font-semibold">{g.label}</span>
          {g.basis === 'observed' && <span className="text-[10px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded bg-warning/10 text-warning">observed, not documented</span>}
          <span className="ml-auto flex gap-1">
            {g.stores.map((st) => (
              <span key={st} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-border/60 text-text-muted">{STORE_LABEL[st] ?? st}</span>
            ))}
          </span>
        </div>
        <p className="text-[12.5px] text-text-muted mt-0.5 leading-snug">{g.detail}</p>
        <SourceLinks sources={g.sources} />
      </div>
    </div>
  )
}

function Section({ title, note, gates }: { title: string; note: string; gates: Gate[] }) {
  if (!gates.length) return null
  return (
    <div className="mt-4 glass rounded-2xl px-6 py-4">
      <h3 className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-1">{title}</h3>
      <p className="text-[12.5px] text-text-muted mb-1">{note}</p>
      {gates.map((g) => <GateRow key={g.id} g={g} />)}
    </div>
  )
}

function Checklist({ items, kind }: { items: ManualItem[]; kind: 'connector' | 'plugin' | 'all' }) {
  const shown = items.filter((i) => kind === 'all' || i.applies_to === kind)
  if (!shown.length) return null
  const byStore = (['anthropic', 'openai'] as const).map((st) => [st, shown.filter((i) => i.store === st)] as const)
  return (
    <div className="mt-4 glass rounded-2xl px-6 py-4">
      <h3 className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-1">Check by hand</h3>
      <p className="text-[12.5px] text-text-muted mb-2">These rules can&apos;t be read from a URL or a repo. Each links to the rule.</p>
      {byStore.map(([st, list]) => list.length > 0 && (
        <div key={st} className="mt-2">
          <div className="text-[12px] font-semibold">{STORE_LABEL[st]}</div>
          <ul className="mt-1 space-y-1.5">
            {list.map((i) => (
              <li key={i.id} className="text-[12.5px] text-text-muted leading-snug flex gap-2">
                <span aria-hidden="true" className="mt-0.5 shrink-0 w-3.5 h-3.5 rounded border border-border" />
                <span>{i.label}. <SourceLinks sources={i.sources} /></span>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}

export default function RebrandPreflight() {
  // ?target= prefills and runs (a score page links here with its own target).
  const [sp] = useSearchParams()
  const initial = sp.get('target') || ''
  const [input, setInput] = useState(initial)
  const [data, setData] = useState<Preflight | null>(null)
  const [rules, setRules] = useState<Rules | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const autoRan = useRef(false)

  useEffect(() => {
    let live = true
    api.get<Rules>('/public/preflight/rules')
      .then((res) => { if (live) setRules(res.data) })
      .catch(() => { /* the fallback date still shows */ })
    return () => { live = false }
  }, [])

  const run = async (value: string = input) => {
    const req = toRequest(value)
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

  useEffect(() => {
    if (initial && !autoRan.current) { autoRan.current = true; void run(initial) }
    // run once for the prefilled target only
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial])

  const checked = data?.rules_checked || rules?.rules_checked || RULES_CHECKED_FALLBACK
  const stale = daysSince(checked) > (rules?.stale_after_days ?? 60)
  const gates = data?.gates ?? []
  const store = gates.filter((g) => g.basis !== 'agentavow')
  const blockers = store.filter((g) => g.severity === 'blocker')
  const holds = store.filter((g) => g.severity === 'hold' && g.status !== 'pass')
  const warnings = store.filter((g) => g.severity === 'warning' && g.status !== 'na')
  const notApplicable = store.filter((g) => g.status === 'na')
  const ours = gates.filter((g) => g.basis === 'agentavow')
  const hasPlugin = gates.some((g) => g.group === 'plugin' && g.id !== 'plugin_bundle' && g.status !== 'na')
  const checklistKind: 'connector' | 'plugin' | 'all' = !data ? 'all' : data.surface === 'mcp' ? 'connector' : hasPlugin ? 'plugin' : 'all'
  const ready = data?.directory_ready ?? false

  return (
    <div className="max-w-[820px] mx-auto px-6 py-16">
      <SEOHead
        title="Connector preflight — will it pass app-store review?"
        description="Check your MCP server or Claude plugin against Claude directory and ChatGPT app review rules before you submit, with a source for every rule. Free."
        path="/preflight"
      />
      <Reveal>
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Connector Preflight</span>
        <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight leading-[1.08]">
          Will your connector pass <span className="gradient-text-bio">app-store review</span>?
        </h1>
        <p className="mt-4 text-text-muted text-[15.5px] leading-relaxed max-w-[64ch]">
          Before you submit to the <strong className="text-text">Claude directory</strong> (an MCP connector or a plugin) or to <strong className="text-text">ChatGPT apps</strong>,
          run a preflight. We read your live MCP server or your repo and check it against each store&apos;s published review rules:
          tool titles and safety hints, read and write tools kept apart, OAuth discovery, plugin bundle rules, and descriptions free of injected instructions.
          Every check links to its rule, so you fix it here instead of losing a week to a rejection.
        </p>
        <p className={`mt-3 text-[12.5px] font-mono ${stale ? 'text-warning' : 'text-text-muted'}`} data-testid="rules-checked">
          Rules last checked: {checked}
          {stale && ' · the stores may have changed their rules since; re-check the linked sources'}
        </p>
      </Reveal>

      <Reveal>
        <div className="mt-8 flex gap-2.5 flex-wrap">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
            placeholder="owner/repo, a GitHub URL (to a plugin folder), or https://your-server/mcp"
            className="flex-1 min-w-[240px] px-4 py-3 rounded-xl bg-surface border border-border focus:border-primary-light outline-none text-[14px] font-mono"
          />
          <button onClick={() => run()} disabled={loading} className="font-semibold px-6 py-3 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 disabled:opacity-60">
            {loading ? 'Checking…' : 'Run preflight →'}
          </button>
        </div>
        {error && <p className="mt-3 text-[13px] text-danger">{error}</p>}
      </Reveal>

      {loading && <div className="mt-8 glass rounded-2xl h-[220px] animate-pulse" />}

      {data && (
        <Reveal>
          {/* verdict banner */}
          <div className={`mt-8 rounded-2xl p-6 border-l-4 glass ${ready ? 'border-success' : 'border-warning'}`}>
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <div>
                <div className={`text-[13px] font-mono uppercase tracking-wide ${ready ? 'text-success' : 'text-warning'}`}>
                  ● {data.headline}
                </div>
                <h2 className="mt-1 text-2xl font-extrabold">{data.target}{data.plugin_folder ? <span className="text-text-muted font-mono text-[15px]"> / {data.plugin_folder}</span> : null}</h2>
                {data.trust_score != null && (
                  <DecisionLine row={{ trust_score: data.trust_score, decision: data.decision, decision_reason: data.decision_reason, certified_mark: data.certified }} className="mt-1 text-[14px]" />
                )}
                <p className="text-[13px] text-text-muted mt-0.5">
                  {data.summary.blockers_total - data.summary.blockers_failed}/{data.summary.blockers_total} blockers pass
                  {(data.summary.holds ?? 0) > 0 && ` · ${data.summary.holds} held for a reviewer`}
                  {data.summary.warnings > 0 && ` · ${data.summary.warnings} warning${data.summary.warnings === 1 ? '' : 's'}`}
                </p>
              </div>
              {/* the trust mark in the badge design: the bar with the score to its right
                  (the Certified mark only when the result carries certified_mark) */}
              {data.trust_score != null && (
                <div className="shrink-0">
                  {data.certified ? <CertifiedMark score={data.trust_score} scale={0.85} /> : <TrustBar score={data.trust_score} scale={0.85} />}
                </div>
              )}
            </div>
          </div>

          <Section title="Blockers — must pass to be listed" gates={blockers}
            note="A failed blocker is a predicted rejection or refusal. A ? means we couldn't read it; confirm it by hand." />
          <Section title="Held for a reviewer" gates={holds}
            note="The Claude plugin directory lets you submit these, but a person reads the version before it can go live." />
          <Section title="Recommended — clean these up" gates={warnings}
            note="Warnings don't block a listing on their own. A tool annotation that reads wrong only from its description wording is a warning; one backed by evidence (a command parameter on a read-only tool, or the sandbox seeing it write) is a blocker." />
          <Section title="AgentAvow's own signals" gates={ours}
            note="Not store rules. Shown for safety; they never decide Directory-Ready." />
          {notApplicable.length > 0 && <Section title="Not applicable" gates={notApplicable} note="" />}

          <div className="mt-5 flex gap-4 text-[13px] flex-wrap">
            {data.signed.report_url && <a href={data.signed.report_url} target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary font-semibold">Full signed report ↗</a>}
            <Link to={rp('/rebrand/for-developers') + '#badge'} className="text-primary-light hover:text-primary font-semibold">Get your README badge →</Link>
            <Link to={rp('/rebrand/certified')} className="text-text-muted hover:text-text">What Certified means →</Link>
          </div>
        </Reveal>
      )}

      {!data && !loading && (
        <Reveal>
          <div className="mt-10 grid sm:grid-cols-3 gap-3">
            {[
              ['Scan', 'We handshake your live MCP server (or read the repo and its plugin folder) and list the real surface.'],
              ['Check the rules', "Each check maps to a store's published review rule and links to it. Rules the Claude directory applies but hasn't documented are marked observed."],
              ['Fix, then submit', 'Clear the blockers here, then walk the by-hand checklist below before you open the portal.'],
            ].map(([h, p]) => (
              <div key={h} className="glass rounded-xl p-4">
                <div className="text-[14px] font-semibold">{h}</div>
                <p className="text-[12.5px] text-text-muted mt-1 leading-relaxed">{p}</p>
              </div>
            ))}
          </div>
        </Reveal>
      )}

      {rules && rules.manual_checklist.length > 0 && !loading && (
        <Reveal>
          <Checklist items={rules.manual_checklist} kind={checklistKind} />
        </Reveal>
      )}
    </div>
  )
}
