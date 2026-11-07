/* eslint-disable react-refresh/only-export-components -- a build script's entry, never hot-reloaded */
/**
 * Server entry for the build-time prerender (web/scripts/prerender.mjs). It renders
 * the real page components, so the snapshot can't drift from the live page. Pages
 * are imported directly: renderToString can't wait on App.tsx's lazy() chunks.
 */
import type { ReactNode } from 'react'
import { renderToString } from 'react-dom/server'
import { Route, Routes, StaticRouter } from 'react-router-dom'
import { dehydrate, QueryClient, QueryClientProvider, type Query } from '@tanstack/react-query'
import { HelmetProvider } from 'react-helmet-async'
import { AuthProvider } from './hooks/useAuth'
import api from './lib/api'
import { publicApi } from './lib/scanApi'
import RebrandLayout from './rebrand/RebrandLayout'
import Badge from './rebrand/pages/Badge'
import Browse from './rebrand/pages/Browse'
import Certified from './rebrand/pages/Certified'
import Check from './rebrand/pages/Check'
import FAQ from './rebrand/pages/FAQ'
import ForDevelopers from './rebrand/pages/ForDevelopers'
import Home from './rebrand/pages/Home'
import HowItWorks from './rebrand/pages/HowItWorks'
import Preflight from './rebrand/pages/Preflight'
import Research from './rebrand/pages/Research'
import Sandbox from './rebrand/pages/Sandbox'
import StateOfAgentSecurityQ3 from './rebrand/pages/StateOfAgentSecurityQ3'
import Submit from './rebrand/pages/Submit'
import TrustIndex from './rebrand/pages/TrustIndex'

/**
 * /claim is left out on purpose: it has no page of its own, only a redirect to the
 * signed-in tools page, so there is nothing to render.
 */
const PAGES: Record<string, ReactNode> = {
  '/': <Home />,
  '/faq': <FAQ />,
  '/state-of-agent-security-q3-2026': <StateOfAgentSecurityQ3 />,
  '/research': <Research />,
  '/how-it-works': <HowItWorks />,
  '/check': <Check />,
  '/browse': <Browse />,
  '/index': <TrustIndex />,
  '/for-developers': <ForDevelopers />,
  '/submit': <Submit />,
  '/certified': <Certified />,
  '/preflight': <Preflight />,
  '/badge': <Badge />,
  '/sandbox': <Sandbox />,
}

export const ROUTES = Object.keys(PAGES)

/**
 * The only queries the build fetches: aggregate figures, plus the home page's example
 * of a top-scoring tool. Lists that name tools and their answers stay out of static
 * HTML until conflicting catalog rows are resolved (audit fix 5), so /index ships
 * without its boards and /browse without its rows. home-ex-adopt stays out as well:
 * its endpoint adds to a tool's public check count on every call.
 */
const BUILD_QUERIES = new Set(['flagged-stat', 'rebrand-home-catalog', 'rebrand-catalog', 'trust-index'])

/** Fetched for their totals only: the rows are dropped, and the browser fetches its own. */
const TOTALS_ONLY_QUERIES = new Set(['rebrand-catalog', 'trust-index'])

const rootKey = (q: Query) => String(q.queryKey[0])

function html(url: string, client: QueryClient, helmetContext: object): string {
  return renderToString(
    <HelmetProvider context={helmetContext}>
      <QueryClientProvider client={client}>
        <StaticRouter location={url}>
          <AuthProvider>
            <Routes>
              <Route path="/" element={<RebrandLayout />}>
                {ROUTES.map((path) => (
                  path === '/'
                    ? <Route key={path} index element={PAGES[path]} />
                    : <Route key={path} path={path.slice(1)} element={PAGES[path]} />
                ))}
              </Route>
            </Routes>
          </AuthProvider>
        </StaticRouter>
      </QueryClientProvider>
    </HelmetProvider>,
  )
}

/**
 * Render a page, fetching its figures from apiOrigin. A failed fetch only costs the
 * figure: the query is dropped and the page shows the same fallback a browser would.
 */
export async function render(url: string, apiOrigin: string, timeoutMs: number) {
  for (const client of [api, publicApi]) {
    client.defaults.baseURL = `${apiOrigin}/api/v1`
    client.defaults.timeout = timeoutMs
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const fetched = new Set<string>()
  const failed: string[] = []

  // useQuery registers each query during render, so one pass shows what the page
  // needs. Later passes catch queries that depend on earlier results.
  for (let pass = 0; pass < 3; pass++) {
    html(url, client, {})
    const todo = client.getQueryCache().getAll().filter(
      (q) => BUILD_QUERIES.has(rootKey(q)) && !fetched.has(q.queryHash) && q.state.status === 'pending',
    )
    if (!todo.length) break
    await Promise.all(todo.map(async (q) => {
      fetched.add(q.queryHash)
      try {
        const data = await q.fetch() as { rows?: unknown[] }
        if (TOTALS_ONLY_QUERIES.has(rootKey(q))) client.setQueryData(q.queryKey, { ...data, rows: [] })
      } catch {
        failed.push(rootKey(q))
        client.getQueryCache().remove(q)
      }
    }))
  }

  const helmetContext = {}
  const body = html(url, client, helmetContext)
  const state = dehydrate(client, {
    shouldDehydrateQuery: (q) => q.state.status === 'success' && !TOTALS_ONLY_QUERIES.has(rootKey(q)),
  })
  return { body, state, failed, helmetContext }
}
