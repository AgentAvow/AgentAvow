import { useState, useCallback, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Helmet } from 'react-helmet-async'
import { rp } from '../basePath'
import api from '../../lib/api'
import { Reveal } from '../components/motion'

/**
 * AgentAvow API Sandbox (rebrand-native) — try the public tool-safety scan API
 * with zero signup. An ephemeral 15-min token unlocks a curated, read-only
 * subset of the scan API (check a tool, browse the catalog, platform stats).
 *
 * Contract (unchanged): POST /sandbox/token · GET /sandbox/endpoints ·
 * POST /sandbox/execute { endpoint, method }.
 */

// ─── Types ───

interface SandboxEndpoint {
  method: string
  path: string
  description: string
  params: Record<string, string>
  curl: string
}

interface SandboxToken {
  token: string
  entity_id: string
  display_name: string
  expires_in: number
}

interface RunState {
  data?: unknown
  error?: string
  loading?: boolean
}

// Nicer labels/blurbs per known endpoint key (server descriptions are terse).
const META: Record<string, { label: string; blurb: string }> = {
  check_tool: {
    label: 'Check a tool',
    blurb: "Fetch a real signed safety grade for a known repo — the same verdict a public caller gets.",
  },
  list_catalog: {
    label: 'Browse catalog',
    blurb: 'List recently scanned tools across every surface (MCP, npm, PyPI, agent skills, x402).',
  },
  platform_stats: {
    label: 'Platform stats',
    blurb: 'Aggregate scan numbers — how many tools were scanned and how many carry findings.',
  },
}

// Preferred display order; anything else falls in after these.
const ORDER = ['check_tool', 'list_catalog', 'platform_stats']

function orderedKeys(endpoints: Record<string, SandboxEndpoint>): string[] {
  const keys = Object.keys(endpoints)
  const known = ORDER.filter((k) => keys.includes(k))
  const rest = keys.filter((k) => !ORDER.includes(k))
  return [...known, ...rest]
}

// ─── Copy-to-clipboard wrapper (matches Badge/Check house style) ───

function Copyable({ text, children }: { text: string; children: React.ReactNode }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    if (navigator.clipboard) navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  return (
    <div className="relative group">
      {children}
      <button
        onClick={copy}
        className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light transition-colors"
      >
        {copied ? 'copied ✓' : 'copy'}
      </button>
    </div>
  )
}

// ─── Main page ───

export default function RebrandSandbox() {
  const [token, setToken] = useState<SandboxToken | null>(null)
  const [endpoints, setEndpoints] = useState<Record<string, SandboxEndpoint> | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, RunState>>({})

  // Load the endpoint catalog on mount (no auth needed — cards render from it).
  useEffect(() => {
    let cancelled = false
    api
      .get<{ endpoints: Record<string, SandboxEndpoint> }>('/sandbox/endpoints')
      .then((res) => {
        if (!cancelled) setEndpoints(res.data.endpoints)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const msg =
          (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
          'Could not load sandbox endpoints.'
        setLoadError(msg)
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Mint an ephemeral token on first Run, then reuse it.
  const ensureToken = useCallback(async (): Promise<SandboxToken> => {
    if (token) return token
    const res = await api.post<SandboxToken>('/sandbox/token')
    setToken(res.data)
    return res.data
  }, [token])

  const run = useCallback(
    async (key: string) => {
      setResults((prev) => ({ ...prev, [key]: { loading: true } }))
      try {
        const tok = await ensureToken()
        const res = await api.post(
          '/sandbox/execute',
          { endpoint: key, method: 'GET' },
          { headers: { Authorization: `Bearer ${tok.token}` } },
        )
        setResults((prev) => ({ ...prev, [key]: { data: res.data, loading: false } }))
      } catch (err: unknown) {
        const msg =
          (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ||
          'Request failed. The sandbox is rate-limited to 10 requests/minute.'
        setResults((prev) => ({ ...prev, [key]: { error: msg, loading: false } }))
      }
    },
    [ensureToken],
  )

  const keys = endpoints ? orderedKeys(endpoints) : []

  return (
    <div className="max-w-[880px] mx-auto px-6 py-14">
      <Helmet>
        <title>API Sandbox — AgentAvow</title>
        <meta
          name="description"
          content="Try the AgentAvow tool-safety scan API with no signup. Mint a 15-minute token and run live, read-only calls against the public scan API."
        />
      </Helmet>

      {/* Intro */}
      <Reveal>
        <div className="max-w-[62ch]">
          <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">
            API Sandbox
          </span>
          <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">
            Try the <span className="gradient-text-bio">AgentAvow API</span> — no signup.
          </h1>
          <p className="mt-3 text-text-muted leading-relaxed">
            Run live, read-only calls against the public tool-safety scan API. We mint an ephemeral
            token behind the scenes on your first run — it expires in 15 minutes and is rate-limited
            to 10 requests per minute. No email, no password, no account.
          </p>
        </div>
      </Reveal>

      {loadError && (
        <div className="mt-8 glass rounded-2xl p-5 border-l-4 border-danger/60">
          <p className="text-[14px] text-text-muted">
            <span className="font-semibold text-text">Couldn&apos;t load the sandbox.</span> {loadError}
          </p>
        </div>
      )}

      {/* Example cards */}
      <div className="mt-8 flex flex-col gap-4">
        {!endpoints && !loadError && (
          <div className="glass rounded-2xl p-6 text-text-muted text-[14px]">Loading examples…</div>
        )}

        {keys.map((key, i) => {
          const ep = endpoints![key]
          const meta = META[key] ?? { label: key, blurb: ep.description }
          const state = results[key]
          return (
            <Reveal key={key} delay={i * 0.05}>
              <div className="glass rounded-2xl p-6">
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2.5">
                      <h2 className="text-[16px] font-bold">{meta.label}</h2>
                      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-success/10 text-success border border-success/25">
                        {ep.method}
                      </span>
                    </div>
                    <p className="mt-1 text-[13.5px] text-text-muted leading-relaxed">{meta.blurb}</p>
                    <code className="inline-block mt-2 font-mono text-[11.5px] text-primary-light bg-surface px-2 py-1 rounded break-all">
                      {ep.path}
                    </code>
                  </div>
                  <button
                    onClick={() => run(key)}
                    disabled={state?.loading}
                    className="shrink-0 font-semibold text-[13.5px] px-5 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/20 hover:shadow-primary/40 transition-shadow disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {state?.loading ? 'Running…' : 'Run'}
                  </button>
                </div>

                {/* curl */}
                <div className="mt-4">
                  <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mb-1.5">curl</div>
                  <Copyable text={ep.curl}>
                    <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl px-4 py-3 pr-16 text-primary-light/80 overflow-x-auto whitespace-pre-wrap break-all">
                      {ep.curl}
                    </pre>
                  </Copyable>
                </div>

                {/* result */}
                {state?.data != null && (
                  <div className="mt-4">
                    <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mb-1.5">
                      Response
                    </div>
                    <Copyable text={JSON.stringify(state.data, null, 2)}>
                      <pre className="font-mono text-[12px] bg-surface border border-border rounded-xl p-4 pr-16 text-text-muted overflow-x-auto max-h-96 overflow-y-auto whitespace-pre-wrap break-words">
                        {JSON.stringify(state.data, null, 2)}
                      </pre>
                    </Copyable>
                  </div>
                )}

                {state?.error && (
                  <div className="mt-4 rounded-xl border border-danger/30 bg-danger/10 px-4 py-3">
                    <p className="text-[13px] text-danger">{state.error}</p>
                  </div>
                )}
              </div>
            </Reveal>
          )
        })}
      </div>

      {/* Token status + next steps */}
      <Reveal>
        <div className="mt-8 glass rounded-2xl p-6">
          {token ? (
            <div className="flex items-center gap-2 text-[13px]">
              <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
              <span className="font-semibold text-success">Sandbox token active</span>
              <span className="text-text-muted">— expires in 15 minutes, then a new one is minted automatically.</span>
            </div>
          ) : (
            <p className="text-[13.5px] text-text-muted">
              Hit <span className="font-semibold text-text">Run</span> on any example above — we mint an
              ephemeral token for you on the first call.
            </p>
          )}
          <p className="mt-4 text-[13.5px] text-text-muted leading-relaxed">
            Ready for the full API? Read the{' '}
            <Link to={rp('/rebrand/docs')} className="text-primary-light font-semibold hover:text-primary underline-offset-2 hover:underline">
              developer docs
            </Link>{' '}
            or create an{' '}
            <Link to={rp('/rebrand/account')} className="text-primary-light font-semibold hover:text-primary underline-offset-2 hover:underline">
              API key on your account
            </Link>{' '}
            to scan on your own schedule, watch tools for change-alerts, and gate CI on a minimum grade.
          </p>
        </div>
      </Reveal>
    </div>
  )
}
