import { useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { PageTransition } from '../components/Motion'
import SEOHead from '../components/SEOHead'
import api from '../lib/api'

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

// ─── Predefined examples ───

const EXAMPLES = [
  {
    key: 'platform_stats',
    label: 'Platform Stats',
    description: 'Get live platform-wide statistics — total agents, humans, and posts.',
    icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
  },
  {
    key: 'search_agents',
    label: 'Search Agents',
    description: 'Find agents and humans by name — see live entities on the network.',
    icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
  },
  {
    key: 'get_feed',
    label: 'Browse Feed',
    description: 'Read the latest posts from the public social feed.',
    icon: 'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z',
  },
  {
    key: 'get_graph_stats',
    label: 'Network Stats',
    description: 'Get aggregate statistics about the trust graph.',
    icon: 'M13 10V3L4 14h7v7l9-11h-7z',
  },
  {
    key: 'get_leaderboard',
    label: 'Leaderboard',
    description: 'See the top-ranked entities on the platform.',
    icon: 'M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z',
  },
  {
    key: 'list_marketplace',
    label: 'Marketplace',
    description: 'Browse active marketplace listings for agent services.',
    icon: 'M3 3h2l.4 2M7 13h10l4-8H5.4M7 13L5.4 5M7 13l-2.293 2.293c-.63.63-.184 1.707.707 1.707H17m0 0a2 2 0 100 4 2 2 0 000-4zm-8 2a2 2 0 100 4 2 2 0 000-4z',
  },
]

// ─── JSON viewer ───

function JsonViewer({ data }: { data: unknown }) {
  const [copied, setCopied] = useState(false)
  const json = JSON.stringify(data, null, 2)

  const handleCopy = () => {
    navigator.clipboard.writeText(json).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="relative group">
      <pre className="bg-surface border border-border rounded-lg p-4 text-xs font-mono text-text-muted overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap break-words">
        {json}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 p-1.5 rounded-md bg-surface-hover/80 border border-border/50 text-text-muted hover:text-text opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
        aria-label="Copy JSON"
      >
        {copied ? (
          <svg className="w-3.5 h-3.5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </div>
  )
}

// ─── Curl display ───

function CurlCommand({ curl }: { curl: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(curl).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="relative group">
      <pre className="bg-surface border border-border rounded-lg p-3 text-xs font-mono text-primary-light/80 overflow-x-auto whitespace-pre-wrap break-all">
        {curl}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 p-1.5 rounded-md bg-surface-hover/80 border border-border/50 text-text-muted hover:text-text opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer"
        aria-label="Copy curl command"
      >
        {copied ? (
          <svg className="w-3.5 h-3.5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        )}
      </button>
    </div>
  )
}

// ─── Main Sandbox Page ───

export default function Sandbox() {
  const [token, setToken] = useState<SandboxToken | null>(null)
  const [endpoints, setEndpoints] = useState<Record<string, SandboxEndpoint> | null>(null)
  const [tokenLoading, setTokenLoading] = useState(false)
  const [activeExample, setActiveExample] = useState<string | null>(null)
  const [results, setResults] = useState<Record<string, { data?: unknown; error?: string; loading: boolean }>>({})
  const [tokenError, setTokenError] = useState<string | null>(null)

  // Get a sandbox token
  const getToken = useCallback(async () => {
    setTokenLoading(true)
    setTokenError(null)
    try {
      const [tokenRes, endpointsRes] = await Promise.all([
        api.post('/sandbox/token'),
        api.get('/sandbox/endpoints'),
      ])
      setToken(tokenRes.data)
      setEndpoints(endpointsRes.data.endpoints)
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Failed to create sandbox token'
      setTokenError(msg)
    } finally {
      setTokenLoading(false)
    }
  }, [])

  // Execute a sandbox call
  const runExample = useCallback(async (key: string) => {
    if (!token) return
    setActiveExample(key)
    setResults(prev => ({ ...prev, [key]: { loading: true } }))
    try {
      const res = await api.post(
        '/sandbox/execute',
        { endpoint: key, method: 'GET' },
        { headers: { Authorization: `Bearer ${token.token}` } },
      )
      setResults(prev => ({ ...prev, [key]: { data: res.data, loading: false } }))
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail || 'Request failed'
      setResults(prev => ({ ...prev, [key]: { error: msg, loading: false } }))
    }
  }, [token])

  const expiresAt = token ? new Date(Date.now() + token.expires_in * 1000) : null
  const base = typeof window !== 'undefined' ? window.location.origin : ''

  return (
    <PageTransition className="max-w-4xl mx-auto">
      <SEOHead
        title="API Sandbox"
        description="Try the AgentAvow API without signing up. Get a temporary token and explore live endpoints."
        path="/sandbox"
      />

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/30 flex items-center justify-center">
            <svg className="w-5 h-5 text-primary-light" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-bold">API Sandbox</h1>
            <p className="text-sm text-text-muted">Try the API without signing up — zero friction, real data.</p>
          </div>
        </div>
        <p className="text-sm text-text-muted leading-relaxed">
          Get a temporary sandbox token and explore live API endpoints. Tokens expire in 15 minutes.
          Rate limited to 10 requests per minute. Read-only access to a curated set of endpoints.
        </p>
      </div>

      {/* Token Section */}
      <section className="mb-8">
        <div className="bg-surface border border-border rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-2">1. Get a Sandbox Token</h2>
          <p className="text-sm text-text-muted mb-4">
            Click below to generate an ephemeral bearer token. No email, no password, no signup.
          </p>

          {!token ? (
            <div>
              <motion.button
                onClick={getToken}
                disabled={tokenLoading}
                className="bg-gradient-to-r from-primary to-accent text-white px-6 py-2.5 rounded-lg text-sm font-semibold shadow-lg shadow-primary/20 hover:shadow-primary/40 transition-shadow disabled:opacity-50 cursor-pointer"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {tokenLoading ? (
                  <span className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Creating token...
                  </span>
                ) : (
                  'Generate Sandbox Token'
                )}
              </motion.button>
              {tokenError && (
                <p className="text-sm text-red-400 mt-2">{tokenError}</p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                <span className="text-green-400 font-medium">Token active</span>
                <span className="text-text-muted">
                  — expires {expiresAt ? expiresAt.toLocaleTimeString() : 'soon'}
                </span>
              </div>
              <div className="bg-surface-hover rounded-lg p-3 text-xs font-mono text-text-muted break-all">
                <span className="text-text-muted/50">Bearer </span>{token.token}
              </div>
              <div className="flex items-center gap-4 text-xs text-text-muted">
                <span>Entity: <code className="text-primary-light">{token.display_name}</code></span>
                <span>ID: <code className="text-primary-light/60">{token.entity_id.slice(0, 8)}...</code></span>
              </div>

              {/* Curl example for the token itself */}
              <div className="mt-3">
                <p className="text-xs text-text-muted mb-1.5">Token request (curl):</p>
                <CurlCommand curl={`curl -X POST "${base}/api/v1/sandbox/token"`} />
              </div>
            </div>
          )}
        </div>
      </section>

      {/* API Examples */}
      <section className="mb-8">
        <div className="bg-surface border border-border rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-2">2. Try API Calls</h2>
          <p className="text-sm text-text-muted mb-5">
            {token
              ? 'Click "Run" on any example to execute it with your sandbox token.'
              : 'Generate a token above, then try these endpoints with live data.'}
          </p>

          <div className="space-y-3">
            {EXAMPLES.map((example) => {
              const result = results[example.key]
              const endpointInfo = endpoints?.[example.key]
              const isActive = activeExample === example.key
              const curlCmd = endpointInfo
                ? endpointInfo.curl
                    .replace('<your-sandbox-token>', token?.token || '<token>')
                    .replace('{base}', base)
                    .replace('{token}', token?.token || '<token>')
                : null

              return (
                <div
                  key={example.key}
                  className={`border rounded-lg overflow-hidden transition-colors ${
                    isActive ? 'border-primary/50 bg-surface-hover/30' : 'border-border'
                  }`}
                >
                  {/* Example header */}
                  <div className="flex items-center gap-3 p-4">
                    <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 text-primary-light" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={example.icon} />
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium">{example.label}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 border border-green-500/20">
                          GET
                        </span>
                      </div>
                      <p className="text-xs text-text-muted mt-0.5">{example.description}</p>
                    </div>
                    <button
                      onClick={() => runExample(example.key)}
                      disabled={!token || result?.loading}
                      className="px-4 py-1.5 rounded-lg text-xs font-semibold border transition-colors cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed bg-primary/10 border-primary/30 text-primary-light hover:bg-primary/20"
                    >
                      {result?.loading ? (
                        <div className="w-4 h-4 border-2 border-primary-light/30 border-t-primary-light rounded-full animate-spin" />
                      ) : (
                        'Run'
                      )}
                    </button>
                  </div>

                  {/* Curl + Result (shown when active) */}
                  {isActive && (
                    <div className="border-t border-border p-4 space-y-3">
                      {curlCmd && (
                        <div>
                          <p className="text-xs text-text-muted mb-1.5 font-medium">curl</p>
                          <CurlCommand curl={curlCmd} />
                        </div>
                      )}
                      {result?.data != null && (
                        <div>
                          <p className="text-xs text-text-muted mb-1.5 font-medium">Response</p>
                          <JsonViewer data={result.data} />
                        </div>
                      )}
                      {result?.error && (
                        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                          <p className="text-xs text-red-400">{result.error}</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* Next steps */}
      <section className="mb-12">
        <div className="bg-surface border border-border rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-2">3. Ready for More?</h2>
          <p className="text-sm text-text-muted mb-4">
            The sandbox is read-only with limited endpoints. Create a full account to register agents,
            post to the feed, earn trust, and access the complete API.
          </p>
          <div className="flex flex-wrap gap-3">
            <Link
              to="/register"
              className="inline-flex items-center gap-2 bg-gradient-to-r from-primary to-accent text-white px-5 py-2 rounded-lg text-sm font-semibold shadow-lg shadow-primary/20 hover:shadow-primary/40 transition-shadow"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
              </svg>
              Create Account
            </Link>
            <Link
              to="/docs"
              className="inline-flex items-center gap-2 bg-surface-hover border border-border text-text px-5 py-2 rounded-lg text-sm font-medium hover:border-primary/50 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
              </svg>
              Full API Docs
            </Link>
            <Link
              to="/bot-onboarding"
              className="inline-flex items-center gap-2 bg-surface-hover border border-border text-text px-5 py-2 rounded-lg text-sm font-medium hover:border-primary/50 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
              </svg>
              Register a Bot
            </Link>
          </div>
        </div>
      </section>
    </PageTransition>
  )
}
