import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { PageTransition } from '../components/Motion'
import { TableRowSkeleton } from '../components/Skeleton'
import SEOHead from '../components/SEOHead'

/**
 * /x402 — x402 Bazaar trust-surface explorer.
 *
 * Two surfaces, one page:
 *   1. The batch view: results of the most recent `scan_x402.py` pass,
 *      read from /x402/explorer. Updated when the nightly scan finishes.
 *   2. The rescan tool: any operator pastes their declared endpoint and
 *      gets back the *live* posture (status, content-type, x402 header,
 *      final URL after redirects). Intentionally does NOT return a
 *      letter grade — the grade is derived server-side and published
 *      separately. This is a surface check, not an attestation.
 */

interface X402ExplorerEntry {
  endpoint_url: string
  http_status: number | null
  has_x402_header: boolean
  content_type: string
  scanned: boolean
}

interface X402ExplorerResponse {
  count: number
  results: X402ExplorerEntry[]
}

interface X402RescanResponse {
  endpoint_url: string
  http_status: number | null
  head_status: number | null
  has_x402_header: boolean
  content_type: string
  content_length: number
  tls_verified: boolean
  final_url: string | null
  error: string | null
}

function statusPill(s: number | null): string {
  if (s === null) return 'bg-surface text-text-muted'
  if (s === 402) return 'bg-blue-400/15 text-blue-400'
  if (s >= 200 && s < 300) return 'bg-success/15 text-success'
  if (s >= 300 && s < 400) return 'bg-warning/15 text-warning'
  return 'bg-danger/15 text-danger'
}

export default function X402Explorer() {
  const [endpoint, setEndpoint] = useState('')
  const [rescanResult, setRescanResult] = useState<X402RescanResponse | null>(null)

  useEffect(() => {
    document.title = 'x402 Trust Explorer - AgentAvow'
  }, [])

  const { data, isLoading, isError, refetch } = useQuery<X402ExplorerResponse>({
    queryKey: ['x402-explorer'],
    queryFn: async () => {
      const { data } = await api.get('/x402/explorer')
      return data
    },
    staleTime: 5 * 60_000,
  })

  const rescan = useMutation({
    mutationFn: async (url: string) => {
      const { data } = await api.post<X402RescanResponse>('/x402/rescan', null, {
        params: { endpoint: url },
      })
      return data
    },
    onSuccess: (res) => setRescanResult(res),
    onError: () => setRescanResult(null),
  })

  const canRescan = endpoint.trim().length > 7 && /^https?:\/\//i.test(endpoint.trim())

  return (
    <PageTransition className="max-w-3xl mx-auto pt-4 px-4">
      <SEOHead
        title="x402 Trust Explorer"
        description="Live trust surface for x402 Bazaar endpoints — HTTP 402 posture, declared surface, TLS, rescan any endpoint for its live state."
        path="/x402"
      />

      <header className="mb-6">
        <h1 className="text-2xl font-bold mb-2">x402 Trust Explorer</h1>
        <p className="text-sm text-text-muted max-w-2xl">
          Observable posture for endpoints listed on the{' '}
          <a
            href="https://bazaar.x402.org"
            target="_blank"
            rel="noreferrer"
            className="text-primary-light hover:underline"
          >
            x402 Bazaar
          </a>
          . The batch view below is the most recent scan pass; the rescan tool
          lets operators refresh their own endpoint's live surface on demand.
          This is a surface check — not an attestation. Letter grades are
          derived server-side and published at the operator's profile.
        </p>
      </header>

      {/* ── Rescan tool ──────────────────────────────────────────── */}
      <section className="bg-surface border border-border rounded-lg p-4 mb-8">
        <h2 className="text-sm font-semibold mb-2">Rescan an endpoint</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (canRescan) rescan.mutate(endpoint.trim())
          }}
          className="flex gap-2 flex-wrap"
        >
          <input
            type="url"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://api.example.com/paid-endpoint"
            className="flex-1 min-w-[240px] px-3 py-2 text-sm bg-background border border-border rounded focus:outline-none focus:border-primary/60"
            aria-label="Endpoint URL"
          />
          <button
            type="submit"
            disabled={!canRescan || rescan.isPending}
            className="px-4 py-2 text-sm bg-primary/20 text-primary-light border border-primary/40 rounded hover:bg-primary/30 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {rescan.isPending ? 'Probing…' : 'Rescan'}
          </button>
        </form>

        {rescan.isError && (
          <p className="mt-3 text-xs text-danger">
            {(rescan.error as Error & { response?: { data?: { detail?: string } } })?.response?.data?.detail
              || 'Rescan failed. Check the URL and try again.'}
          </p>
        )}

        {rescanResult && (
          <div className="mt-4 p-3 bg-background border border-border rounded text-xs font-mono">
            {rescanResult.error ? (
              <div className="text-danger">Error: {rescanResult.error}</div>
            ) : (
              <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
                <dt className="text-text-muted">endpoint</dt>
                <dd className="truncate">{rescanResult.endpoint_url}</dd>
                <dt className="text-text-muted">http</dt>
                <dd>
                  <span className={`px-1.5 py-0.5 rounded ${statusPill(rescanResult.http_status)}`}>
                    {rescanResult.http_status ?? '—'}
                  </span>
                </dd>
                <dt className="text-text-muted">x402 header</dt>
                <dd>{rescanResult.has_x402_header ? 'present' : 'absent'}</dd>
                <dt className="text-text-muted">content-type</dt>
                <dd>{rescanResult.content_type || '—'}</dd>
                {rescanResult.final_url && rescanResult.final_url !== rescanResult.endpoint_url && (
                  <>
                    <dt className="text-text-muted">redirected to</dt>
                    <dd className="truncate">{rescanResult.final_url}</dd>
                  </>
                )}
              </dl>
            )}
          </div>
        )}
      </section>

      {/* ── Batch explorer ───────────────────────────────────────── */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold">
            Latest batch scan{data ? ` — ${data.count} endpoints` : ''}
          </h2>
          <button
            onClick={() => refetch()}
            className="text-xs text-primary-light hover:underline cursor-pointer"
          >
            Refresh
          </button>
        </div>

        {isLoading && (
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <table className="w-full">
              <tbody>
                {Array.from({ length: 6 }).map((_, i) => (
                  <TableRowSkeleton key={i} cols={4} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {isError && (
          <div className="text-center py-6 text-sm text-danger">
            Failed to load scan results.{' '}
            <button onClick={() => refetch()} className="underline cursor-pointer">
              Retry
            </button>
          </div>
        )}

        {!isLoading && !isError && (!data || data.count === 0) && (
          <div className="bg-surface border border-border rounded-lg p-6 text-center text-sm text-text-muted">
            No scan results yet. Check back after the next nightly pass.
          </div>
        )}

        {!isLoading && !isError && data && data.count > 0 && (
          <div className="bg-surface border border-border rounded-lg overflow-x-auto">
            <table className="w-full min-w-[560px]">
              <caption className="sr-only">x402 endpoint scan results</caption>
              <thead>
                <tr className="text-xs text-text-muted uppercase tracking-wider border-b border-border">
                  <th className="text-left px-4 py-2.5">Endpoint</th>
                  <th className="text-right px-4 py-2.5">Status</th>
                  <th className="text-center px-4 py-2.5">x402</th>
                  <th className="text-left px-4 py-2.5">Content-type</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((row) => (
                  <tr
                    key={row.endpoint_url}
                    className="border-b border-border/50 last:border-b-0 hover:bg-surface-hover transition-colors"
                  >
                    <td className="px-4 py-3 text-xs font-mono truncate max-w-[320px]">
                      <a
                        href={row.endpoint_url}
                        target="_blank"
                        rel="noreferrer"
                        className="hover:text-primary-light"
                      >
                        {row.endpoint_url}
                      </a>
                    </td>
                    <td className="px-4 py-3 text-right text-xs">
                      {row.scanned ? (
                        <span className={`px-1.5 py-0.5 rounded ${statusPill(row.http_status)}`}>
                          {row.http_status ?? '—'}
                        </span>
                      ) : (
                        <span className="text-text-muted">err</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-center text-xs">
                      {row.has_x402_header ? (
                        <span className="text-success">✓</span>
                      ) : (
                        <span className="text-text-muted">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-text-muted truncate max-w-[200px]">
                      {row.content_type || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </PageTransition>
  )
}
