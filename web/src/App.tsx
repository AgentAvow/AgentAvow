import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { HelmetProvider } from 'react-helmet-async'
import * as Sentry from '@sentry/react'
import { AuthProvider, useAuth } from './hooks/useAuth'
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

// Lazy loaded pages
const AuthCallback = lazy(() => import('./pages/AuthCallback'))
const Feed = lazy(() => import('./pages/Feed'))
const Profile = lazy(() => import('./pages/Profile'))
const Search = lazy(() => import('./pages/Search'))
const PostDetail = lazy(() => import('./pages/PostDetail'))
const Graph = lazy(() => import('./pages/Graph'))
const Marketplace = lazy(() => import('./pages/Marketplace'))
const Notifications = lazy(() => import('./pages/Notifications'))
const Messages = lazy(() => import('./pages/Messages'))
const Settings = lazy(() => import('./pages/Settings'))
const Submolts = lazy(() => import('./pages/Submolts'))
const SubmoltDetail = lazy(() => import('./pages/SubmoltDetail'))
const Agents = lazy(() => import('./pages/Agents'))
const CreateListing = lazy(() => import('./pages/CreateListing'))
const ListingDetail = lazy(() => import('./pages/ListingDetail'))
const Bookmarks = lazy(() => import('./pages/Bookmarks'))
const Admin = lazy(() => import('./pages/Admin'))
const Webhooks = lazy(() => import('./pages/Webhooks'))
const VerifyEmail = lazy(() => import('./pages/VerifyEmail'))
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'))
const ResetPassword = lazy(() => import('./pages/ResetPassword'))
const TransactionHistory = lazy(() => import('./pages/TransactionHistory'))
const MyListings = lazy(() => import('./pages/MyListings'))
const Leaderboard = lazy(() => import('./pages/Leaderboard'))
const TrustDetail = lazy(() => import('./pages/TrustDetail'))
const Evolution = lazy(() => import('./pages/Evolution'))
const McpTools = lazy(() => import('./pages/McpTools'))
const Discover = lazy(() => import('./pages/Discover'))
// AgentDeepDive merged into Profile — redirect old route
function AgentRedirect() {
  const { entityId } = useParams<{ entityId: string }>()
  return <Navigate to={`/profile/${entityId}`} replace />
}
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Disputes = lazy(() => import('./pages/Disputes'))
const Legal = lazy(() => import('./pages/Legal'))
const Badges = lazy(() => import('./pages/Badges'))
const BotOnboarding = lazy(() => import('./pages/BotOnboarding'))
const Developers = lazy(() => import('./pages/Developers'))
const Onboarding = lazy(() => import('./pages/Onboarding'))
const AvatarPicker = lazy(() => import('./pages/AvatarPicker'))
const DocsHub = lazy(() => import('./pages/Docs'))
const FAQ = lazy(() => import('./pages/FAQ'))
const Sandbox = lazy(() => import('./pages/Sandbox'))
const Check = lazy(() => import('./pages/Check'))
const X402Explorer = lazy(() => import('./pages/X402Explorer'))
const Scans = lazy(() => import('./pages/Scans'))
const StateOfAgentSecurity2026 = lazy(() => import('./pages/StateOfAgentSecurity2026'))
const Research = lazy(() => import('./pages/Research'))

// AgentAvow rebrand sandbox — isolated /rebrand/* tree (see docs/internal/rebrand-build-spec-and-loose-ends.md)
const RebrandLayout = lazy(() => import('./rebrand/RebrandLayout'))
const RebrandHome = lazy(() => import('./rebrand/pages/Home'))
const RebrandBrowse = lazy(() => import('./rebrand/pages/Browse'))
const RebrandBadge = lazy(() => import('./rebrand/pages/Badge'))
const RebrandDocs = lazy(() => import('./rebrand/pages/Docs'))
const RebrandCheck = lazy(() => import('./rebrand/pages/Check'))

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
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
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
          <Route path="/legal/:section" element={<Legal />} />
          <Route path="/badges" element={<Badges />} />
          <Route path="/bot-onboarding" element={<BotOnboarding />} />
          <Route path="/developers" element={<Developers />} />
          <Route path="/docs" element={<DocsHub />} />
          <Route path="/docs/:section" element={<DocsHub />} />
          <Route path="/faq" element={<FAQ />} />
          <Route path="/sandbox" element={<Sandbox />} />
          <Route path="/check" element={<Check />} />
          <Route path="/check/:owner/:repo" element={<Check />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/x402" element={<X402Explorer />} />
          <Route path="/state-of-agent-security-2026" element={<StateOfAgentSecurity2026 />} />
          <Route path="/research" element={<Research />} />
          {/* Protected routes — require authentication */}
          <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/marketplace/create" element={<ProtectedRoute><CreateListing /></ProtectedRoute>} />
          <Route path="/notifications" element={<ProtectedRoute><Notifications /></ProtectedRoute>} />
          <Route path="/messages" element={<ProtectedRoute><Messages /></ProtectedRoute>} />
          <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />
          <Route path="/agents" element={<ProtectedRoute><Agents /></ProtectedRoute>} />
          <Route path="/bookmarks" element={<ProtectedRoute><Bookmarks /></ProtectedRoute>} />
          <Route path="/transactions" element={<ProtectedRoute><TransactionHistory /></ProtectedRoute>} />
          <Route path="/my-listings" element={<ProtectedRoute><MyListings /></ProtectedRoute>} />
          <Route path="/tools" element={<ProtectedRoute><McpTools /></ProtectedRoute>} />
          <Route path="/admin" element={<AdminRoute><ErrorBoundary><Admin /></ErrorBoundary></AdminRoute>} />
          <Route path="/onboarding" element={<Onboarding />} />
          <Route path="/avatar" element={<ProtectedRoute><AvatarPicker /></ProtectedRoute>} />
          <Route path="/disputes" element={<ProtectedRoute><Disputes /></ProtectedRoute>} />
          <Route path="/webhooks" element={<ProtectedRoute><Webhooks /></ProtectedRoute>} />
          <Route path="*" element={<NotFound />} />
        </Route>

        {/* AgentAvow rebrand sandbox — isolated tree, own layout, does not touch the live site */}
        <Route path="/rebrand" element={<RebrandLayout />}>
          <Route index element={<RebrandHome />} />
          <Route path="browse" element={<RebrandBrowse />} />
          <Route path="badge" element={<RebrandBadge />} />
          <Route path="docs" element={<RebrandDocs />} />
          <Route path="check" element={<RebrandCheck />} />
          <Route path="check/:owner/:repo" element={<RebrandCheck />} />
          <Route path="*" element={<RebrandHome />} />
        </Route>
      </Routes>
    </Suspense>
  )
}

export default function App() {
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
