import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { HelmetProvider } from 'react-helmet-async'
import * as Sentry from '@sentry/react'
import { AuthProvider, useAuth } from './hooks/useAuth'
import { REBRAND_BASE } from './rebrand/basePath'

// At cutover (VITE_CUTOVER=true) the rebrand becomes the root site and the old
// pages it replaces step aside. Off (default) → everything is exactly as today.
const CUTOVER = REBRAND_BASE === ''
import Layout from './components/Layout'
import { ToastProvider } from './components/Toasts'
import { LiveUpdates } from './components/LiveUpdates'
import ErrorBoundary from './components/ErrorBoundary'
import { ThemeProvider } from './hooks/useTheme'
import { captureUtmParams } from './lib/analytics'

// ─── Sentry ───
const SENTRY_DSN = import.meta.env.VITE_SENTRY_DSN
if (SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: import.meta.env.MODE,
    integrations: [Sentry.browserTracingIntegration(), Sentry.replayIntegration({ maskAllText: false, blockAllMedia: false })],
    tracesSampleRate: import.meta.env.PROD ? 0.2 : 1.0,
    replaysSessionSampleRate: 0.1,
    replaysOnErrorSampleRate: 1.0,
  })
}

// Capture UTM params from marketing links on initial page load
captureUtmParams()

// Eagerly loaded pages (entry points)
import Home from './pages/Home'
import Login from './pages/Login'
import Register from './pages/Register'
import NotFound from './pages/NotFound'

// Deploy-safe lazy loading. When we redeploy, route chunks get new hashes and the
// old files are removed — a tab opened before the deploy then 404s the old chunk on
// navigation ("Browse/scan broke"). Wrap every lazy import so a chunk-load failure
// reloads the page ONCE (sessionStorage-guarded against loops) to pull fresh chunks;
// a second failure falls through to the ErrorBoundary instead of looping.
const CHUNK_RELOAD_KEY = 'ag:chunk-reload'
function lazyWithReload<T extends { default: React.ComponentType<unknown> }>(
  factory: () => Promise<T>,
) {
  return lazy(() =>
    factory().catch((err) => {
      if (!sessionStorage.getItem(CHUNK_RELOAD_KEY)) {
        sessionStorage.setItem(CHUNK_RELOAD_KEY, String(Date.now()))
        window.location.reload()
        return new Promise<T>(() => {}) // never resolves; the reload takes over
      }
      throw err // already retried once — let the ErrorBoundary handle it
    }),
  )
}

// Lazy loaded pages
const AuthCallback = lazyWithReload(() => import('./pages/AuthCallback'))
const Feed = lazyWithReload(() => import('./pages/Feed'))
const Profile = lazyWithReload(() => import('./pages/Profile'))
const Search = lazyWithReload(() => import('./pages/Search'))
const PostDetail = lazyWithReload(() => import('./pages/PostDetail'))
const Graph = lazyWithReload(() => import('./pages/Graph'))
const Marketplace = lazyWithReload(() => import('./pages/Marketplace'))
const Notifications = lazyWithReload(() => import('./pages/Notifications'))
const Messages = lazyWithReload(() => import('./pages/Messages'))
const Settings = lazyWithReload(() => import('./pages/Settings'))
const Submolts = lazyWithReload(() => import('./pages/Submolts'))
const SubmoltDetail = lazyWithReload(() => import('./pages/SubmoltDetail'))
const Agents = lazyWithReload(() => import('./pages/Agents'))
const CreateListing = lazyWithReload(() => import('./pages/CreateListing'))
const ListingDetail = lazyWithReload(() => import('./pages/ListingDetail'))
const Bookmarks = lazyWithReload(() => import('./pages/Bookmarks'))
const Admin = lazyWithReload(() => import('./pages/Admin'))
const Webhooks = lazyWithReload(() => import('./pages/Webhooks'))
const VerifyEmail = lazyWithReload(() => import('./pages/VerifyEmail'))
const ForgotPassword = lazyWithReload(() => import('./pages/ForgotPassword'))
const ResetPassword = lazyWithReload(() => import('./pages/ResetPassword'))
const TransactionHistory = lazyWithReload(() => import('./pages/TransactionHistory'))
const MyListings = lazyWithReload(() => import('./pages/MyListings'))
const Leaderboard = lazyWithReload(() => import('./pages/Leaderboard'))
const TrustDetail = lazyWithReload(() => import('./pages/TrustDetail'))
const Evolution = lazyWithReload(() => import('./pages/Evolution'))
const McpTools = lazyWithReload(() => import('./pages/McpTools'))
const Discover = lazyWithReload(() => import('./pages/Discover'))
// AgentDeepDive merged into Profile — redirect old route
function AgentRedirect() {
  const { entityId } = useParams<{ entityId: string }>()
  return <Navigate to={`/profile/${entityId}`} replace />
}
const Dashboard = lazyWithReload(() => import('./pages/Dashboard'))
const Disputes = lazyWithReload(() => import('./pages/Disputes'))
const Legal = lazyWithReload(() => import('./pages/Legal'))
const Badges = lazyWithReload(() => import('./pages/Badges'))
const BotOnboarding = lazyWithReload(() => import('./pages/BotOnboarding'))
const Developers = lazyWithReload(() => import('./pages/Developers'))
const Onboarding = lazyWithReload(() => import('./pages/Onboarding'))
const AvatarPicker = lazyWithReload(() => import('./pages/AvatarPicker'))
const DocsHub = lazyWithReload(() => import('./pages/Docs'))
const FAQ = lazyWithReload(() => import('./pages/FAQ'))
const Sandbox = lazyWithReload(() => import('./pages/Sandbox'))
const Check = lazyWithReload(() => import('./pages/Check'))
const X402Explorer = lazyWithReload(() => import('./pages/X402Explorer'))
const Scans = lazyWithReload(() => import('./pages/Scans'))
const StateOfAgentSecurity2026 = lazyWithReload(() => import('./pages/StateOfAgentSecurity2026'))
const Research = lazyWithReload(() => import('./pages/Research'))

// AgentAvow rebrand sandbox — isolated /rebrand/* tree (see docs/internal/rebrand-build-spec-and-loose-ends.md)
const RebrandLayout = lazyWithReload(() => import('./rebrand/RebrandLayout'))
const RebrandHome = lazyWithReload(() => import('./rebrand/pages/Home'))
const RebrandBrowse = lazyWithReload(() => import('./rebrand/pages/Browse'))
const RebrandBadge = lazyWithReload(() => import('./rebrand/pages/Badge'))
const RebrandDocs = lazyWithReload(() => import('./rebrand/pages/Docs'))
const RebrandCheck = lazyWithReload(() => import('./rebrand/pages/Check'))
const RebrandSubmit = lazyWithReload(() => import('./rebrand/pages/Submit'))
const RebrandLogin = lazyWithReload(() => import('./rebrand/pages/Login'))
const RebrandLegal = lazyWithReload(() => import('./rebrand/pages/Legal'))
const RebrandAccount = lazyWithReload(() => import('./rebrand/pages/Account'))
const RebrandMyTools = lazyWithReload(() => import('./rebrand/pages/MyTools'))
const RebrandHowItWorks = lazyWithReload(() => import('./rebrand/pages/HowItWorks'))
const RebrandResearch = lazyWithReload(() => import('./rebrand/pages/Research'))
const RebrandClaim = lazyWithReload(() => import('./rebrand/pages/Claim'))
const RebrandFAQ = lazyWithReload(() => import('./rebrand/pages/FAQ'))
const RebrandSettings = lazyWithReload(() => import('./rebrand/pages/Settings'))
const RebrandAvatar = lazyWithReload(() => import('./rebrand/pages/Avatar'))
const RebrandSandbox = lazyWithReload(() => import('./rebrand/pages/Sandbox'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
})

function PageLoader() {
  return (
    <div className="flex items-center justify-center mt-20">
      <div className="w-6 h-6 border-2 border-primary/30 border-t-primary rounded-full animate-spin" />
    </div>
  )
}

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()
  const location = useLocation()
  if (isLoading) return <PageLoader />
  if (!user) {
    const returnTo = encodeURIComponent(location.pathname + location.search)
    return <Navigate to={`/login?returnTo=${returnTo}`} replace />
  }
  return <>{children}</>
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth()
  const location = useLocation()
  if (isLoading) return <PageLoader />
  if (!user) {
    const returnTo = encodeURIComponent(location.pathname + location.search)
    return <Navigate to={`/login?returnTo=${returnTo}`} replace />
  }
  if (!user.is_admin) return <Navigate to="/dashboard" replace />
  return <>{children}</>
}

function ScrollToTop() {
  const { pathname } = useLocation()
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])
  return null
}

function AppRoutes() {
  return (
    <Suspense fallback={<PageLoader />}>
      <ScrollToTop />
      <Routes>
        <Route element={<Layout />}>
          {!CUTOVER && <Route path="/" element={<Home />} />}
          {/* keep the old homepage reachable post-cutover (Kenne wants to revive it) */}
          {CUTOVER && <Route path="/legacy-home" element={<Home />} />}
          {!CUTOVER && <Route path="/login" element={<Login />} />}
          <Route path="/register" element={<Register />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          {/* Public routes — accessible to guests */}
          <Route path="/feed" element={<Feed />} />
          <Route path="/post/:postId" element={<PostDetail />} />
          <Route path="/profile/:entityId" element={<ErrorBoundary><Profile /></ErrorBoundary>} />
          <Route path="/search" element={<Search />} />
          <Route path="/graph" element={<ErrorBoundary><Graph /></ErrorBoundary>} />
          <Route path="/marketplace" element={<Marketplace />} />
          <Route path="/marketplace/:listingId" element={<ListingDetail />} />
          <Route path="/communities" element={<Submolts />} />
          <Route path="/m/:name" element={<SubmoltDetail />} />
          <Route path="/leaderboard" element={<Leaderboard />} />
          <Route path="/trust/:entityId" element={<TrustDetail />} />
          <Route path="/evolution/:entityId" element={<Evolution />} />
          <Route path="/discover" element={<Discover />} />
          <Route path="/agent/:entityId" element={<AgentRedirect />} />
          {!CUTOVER && <Route path="/legal/:section" element={<Legal />} />}
          <Route path="/badges" element={<Badges />} />
          <Route path="/bot-onboarding" element={<BotOnboarding />} />
          <Route path="/developers" element={<Developers />} />
          {!CUTOVER && <Route path="/docs" element={<DocsHub />} />}
          {!CUTOVER && <Route path="/docs/:section" element={<DocsHub />} />}
          {!CUTOVER && <Route path="/faq" element={<FAQ />} />}
          {!CUTOVER && <Route path="/sandbox" element={<Sandbox />} />}
          {!CUTOVER && <Route path="/check" element={<Check />} />}
          {!CUTOVER && <Route path="/check/:owner/:repo" element={<Check />} />}
          <Route path="/scans" element={<Scans />} />
          <Route path="/x402" element={<X402Explorer />} />
          <Route path="/state-of-agent-security-2026" element={<StateOfAgentSecurity2026 />} />
          {!CUTOVER && <Route path="/research" element={<Research />} />}
          {/* Protected routes — require authentication */}
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/marketplace/create" element={<ProtectedRoute><CreateListing /></ProtectedRoute>} />
          <Route path="/notifications" element={<ProtectedRoute><Notifications /></ProtectedRoute>} />
          <Route path="/messages" element={<ProtectedRoute><Messages /></ProtectedRoute>} />
          {!CUTOVER && <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />}
          <Route path="/agents" element={<ProtectedRoute><Agents /></ProtectedRoute>} />
          <Route path="/bookmarks" element={<ProtectedRoute><Bookmarks /></ProtectedRoute>} />
          <Route path="/transactions" element={<ProtectedRoute><TransactionHistory /></ProtectedRoute>} />
          <Route path="/my-listings" element={<ProtectedRoute><MyListings /></ProtectedRoute>} />
          {!CUTOVER && <Route path="/tools" element={<ProtectedRoute><McpTools /></ProtectedRoute>} />}
          <Route path="/admin" element={<AdminRoute><ErrorBoundary><Admin /></ErrorBoundary></AdminRoute>} />
          <Route path="/onboarding" element={<Onboarding />} />
          {!CUTOVER && <Route path="/avatar" element={<ProtectedRoute><AvatarPicker /></ProtectedRoute>} />}
          <Route path="/disputes" element={<ProtectedRoute><Disputes /></ProtectedRoute>} />
          <Route path="/webhooks" element={<ProtectedRoute><Webhooks /></ProtectedRoute>} />
          {!CUTOVER && <Route path="*" element={<NotFound />} />}
        </Route>

        {/* AgentAvow rebrand — /rebrand pre-cutover, the root site at cutover (VITE_CUTOVER=true) */}
        <Route path={REBRAND_BASE || '/'} element={<RebrandLayout />}>
          <Route index element={<RebrandHome />} />
          <Route path="browse" element={<RebrandBrowse />} />
          <Route path="submit" element={<RebrandSubmit />} />
          <Route path="badge" element={<RebrandBadge />} />
          <Route path="docs" element={<RebrandDocs />} />
          <Route path="check" element={<RebrandCheck />} />
          <Route path="check/mcp" element={<RebrandCheck />} />
          <Route path="check/skill/:owner/:repo" element={<RebrandCheck />} />
          <Route path="check/pkg/:surface/*" element={<RebrandCheck />} />
          <Route path="check/:owner/:repo" element={<RebrandCheck />} />
          <Route path="login" element={<RebrandLogin />} />
          <Route path="account" element={<RebrandAccount />} />
          <Route path="tools" element={<RebrandMyTools />} />
          <Route path="how-it-works" element={<RebrandHowItWorks />} />
          <Route path="research" element={<RebrandResearch />} />
          <Route path="claim" element={<RebrandClaim />} />
          <Route path="faq" element={<RebrandFAQ />} />
          <Route path="settings" element={<RebrandSettings />} />
          <Route path="avatar" element={<RebrandAvatar />} />
          <Route path="sandbox" element={<RebrandSandbox />} />
          <Route path="legal" element={<RebrandLegal />} />
          <Route path="legal/:section" element={<RebrandLegal />} />
          <Route path="*" element={<RebrandHome />} />
        </Route>
      </Routes>
    </Suspense>
  )
}

export default function App() {
  // A route chunk loaded successfully → clear the one-shot reload guard so the NEXT
  // deploy can self-heal this tab too (otherwise the first reload would be the only one).
  useEffect(() => { sessionStorage.removeItem(CHUNK_RELOAD_KEY) }, [])
  return (
    <HelmetProvider>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <ToastProvider>
              <ErrorBoundary>
                <LiveUpdates />
                <AppRoutes />
              </ErrorBoundary>
            </ToastProvider>
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
    </HelmetProvider>
  )
}
