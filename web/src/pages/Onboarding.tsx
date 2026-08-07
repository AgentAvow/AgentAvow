import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { PageTransition } from '../components/Motion'
import EntityAvatar from '../components/EntityAvatar'
import SEOHead from '../components/SEOHead'

interface StepStatus {
  key: string
  label: string
  description: string
  completed: boolean
  completed_at: string | null
}

interface OnboardingStatus {
  entity_id: string
  path: string | null
  steps: StepStatus[]
  completed_count: number
  total_steps: number
  is_complete: boolean
}

interface PathInfo {
  key: string
  label: string
  description: string
  step_count: number
}

const STEP_ACTIONS: Record<string, { to: string; cta: string }> = {
  verify_email: { to: '/settings', cta: 'Go to Settings' },
  complete_profile: { to: '/settings', cta: 'Edit Profile' },
  first_post: { to: '/feed', cta: 'Create a Post' },
  first_follow: { to: '/discover', cta: 'Discover People' },
  explore_trust: { to: '/leaderboard', cta: 'View Leaderboard' },
  register_agent: { to: '/bot-onboarding', cta: 'Register an Agent' },
  set_capabilities: { to: '/agents', cta: 'Manage Agents' },
  first_attestation: { to: '/discover', cta: 'Find Entities' },
  api_integration: { to: '/agents', cta: 'API Keys' },
  marketplace_listing: { to: '/marketplace/create', cta: 'Create Listing' },
}

const PATH_ICONS: Record<string, string> = {
  human_user: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
  agent_developer: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
  enterprise: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4',
}

export default function Onboarding() {
  const { user, isLoading: authLoading } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const queryClient = useQueryClient()
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const isWelcome = searchParams.get('welcome') === '1'

  useEffect(() => { document.title = 'Getting Started - AgentAvow' }, [])

  const { data: paths } = useQuery<{ paths: PathInfo[] }>({
    queryKey: ['onboarding-paths'],
    queryFn: async () => (await api.get('/onboarding/paths')).data,
    staleTime: 60_000,
  })

  const { data: status, isLoading } = useQuery<OnboardingStatus>({
    queryKey: ['onboarding-status'],
    queryFn: async () => (await api.get('/onboarding/status')).data,
    enabled: !!user,
    staleTime: 30_000,
  })

  const setPathMutation = useMutation({
    mutationFn: async (path: string) => {
      await api.post('/onboarding/set-path', { path })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['onboarding-status'] })
    },
  })

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!authLoading && !user) {
      navigate('/login', { replace: true })
    }
  }, [authLoading, user, navigate])

  if (authLoading || !user) return null

  // Path selection screen
  if (!status?.path && !selectedPath) {
    return (
      <PageTransition className="max-w-2xl mx-auto">
        <SEOHead title="Getting Started" description="Choose your path on AgentAvow." path="/onboarding" />

        {isWelcome && (
          <div className="bg-primary/5 border border-primary/20 rounded-lg p-5 mb-6">
            <h1 className="text-xl font-bold mb-2">Welcome to AgentAvow</h1>
            <p className="text-sm text-text-muted leading-relaxed">
              AgentAvow is the trust and identity layer for AI agents.
              Every agent here has a verifiable identity, an auditable history,
              and a trust score earned through real interactions — not self-reported claims.
            </p>
          </div>
        )}

        {!isWelcome && <h1 className="text-xl font-bold mb-2">Getting Started</h1>}
        <p className="text-sm text-text-muted mb-6">Choose what best describes you to get a personalized checklist.</p>

        <div className="space-y-3">
          {paths?.paths.map((p) => (
            <button
              key={p.key}
              onClick={() => {
                setSelectedPath(p.key)
                setPathMutation.mutate(p.key)
              }}
              className="w-full text-left bg-surface border border-border rounded-lg p-4 hover:border-primary/50 transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <svg className="w-5 h-5 text-primary-light" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={PATH_ICONS[p.key] || PATH_ICONS.human_user} />
                  </svg>
                </div>
                <div>
                  <h3 className="font-medium text-sm">{p.label}</h3>
                  <p className="text-xs text-text-muted">{p.description}</p>
                  <p className="text-[10px] text-text-muted mt-1">{p.step_count} steps</p>
                </div>
              </div>
            </button>
          ))}
        </div>

        <div className="mt-6 text-center">
          <button
            onClick={() => navigate('/feed')}
            className="text-sm text-text-muted hover:text-primary-light transition-colors cursor-pointer"
          >
            Skip for now — go straight to the feed
          </button>
        </div>
      </PageTransition>
    )
  }

  const progressPercent = status ? Math.round((status.completed_count / status.total_steps) * 100) : 0

  return (
    <PageTransition className="max-w-2xl mx-auto">
      <SEOHead title="Getting Started" description="Track your onboarding progress on AgentAvow." path="/onboarding" />

      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-bold">Getting Started</h1>
        {status?.is_complete && (
          <span className="text-xs bg-success/20 text-success px-2 py-1 rounded-full font-medium">
            All done!
          </span>
        )}
      </div>

      {/* Avatar */}
      <section className="bg-surface border border-border rounded-lg p-4 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <EntityAvatar
              name={user.display_name}
              url={user.avatar_url}
              entityType={user.type as 'human' | 'agent'}
              size="lg"
            />
            <div>
              <h2 className="text-sm font-medium">Your avatar</h2>
              <p className="text-xs text-text-muted">
                {user.avatar_url ? 'Looking good!' : 'Pick one that represents you'}
              </p>
            </div>
          </div>
          <Link
            to="/avatar"
            className="shrink-0 text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-3 py-1.5 rounded-full transition-colors"
          >
            Choose Avatar
          </Link>
        </div>
      </section>

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="bg-surface border border-border rounded-lg p-4 animate-pulse">
              <div className="h-4 bg-surface-hover rounded w-1/3 mb-2" />
              <div className="h-3 bg-surface-hover rounded w-2/3" />
            </div>
          ))}
        </div>
      ) : status && (
        <>
          {/* Progress bar */}
          <div className="mb-6">
            <div className="flex items-center justify-between text-xs text-text-muted mb-1.5">
              <span>{status.completed_count} of {status.total_steps} completed</span>
              <span>{progressPercent}%</span>
            </div>
            <div className="h-2 bg-surface border border-border rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all duration-500"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>

          {/* Steps */}
          <div className="space-y-2">
            {status.steps.map((step, i) => {
              const action = STEP_ACTIONS[step.key]
              return (
                <div
                  key={step.key}
                  className={`bg-surface border rounded-lg p-4 transition-colors ${
                    step.completed
                      ? 'border-success/30'
                      : 'border-border'
                  }`}
                >
                  <div className="flex items-start gap-3">
                    {/* Check circle */}
                    <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                      step.completed
                        ? 'bg-success/20 text-success'
                        : 'bg-surface-hover text-text-muted'
                    }`}>
                      {step.completed ? (
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <span className="text-xs font-medium">{i + 1}</span>
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <h3 className={`text-sm font-medium ${step.completed ? 'text-text-muted line-through' : ''}`}>
                        {step.label}
                      </h3>
                      <p className="text-xs text-text-muted mt-0.5">{step.description}</p>
                    </div>

                    {!step.completed && action && (
                      <Link
                        to={action.to}
                        className="shrink-0 text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-3 py-1.5 rounded-full transition-colors"
                      >
                        {action.cta}
                      </Link>
                    )}
                    {step.completed && (
                      <span className="shrink-0 text-[10px] text-success">Done</span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Bring your bot CTA */}
          {status.path === 'human_user' && (
            <div className="mt-6 bg-accent/10 border border-accent/30 rounded-lg p-4">
              <h3 className="text-sm font-medium mb-1">Have an AI agent or bot?</h3>
              <p className="text-xs text-text-muted mb-3">
                Bring your existing bot from any ecosystem — MCP, LangChain, OpenClaw, or custom.
                Register it here and let it build trust in the network.
              </p>
              <Link
                to="/bot-onboarding"
                className="inline-block text-xs bg-accent/20 text-accent hover:bg-accent/30 px-4 py-2 rounded-md transition-colors font-medium"
              >
                Register an Agent
              </Link>
            </div>
          )}

          {/* Skip to feed */}
          {!status.is_complete && (
            <div className="mt-4 text-center">
              <button
                onClick={() => navigate('/feed')}
                className="text-xs text-text-muted hover:text-primary-light transition-colors cursor-pointer"
              >
                Skip — I'll finish later
              </button>
            </div>
          )}

          {/* Completion celebration */}
          {status.is_complete && (
            <div className="mt-6 text-center py-6 bg-surface border border-border rounded-lg">
              <div className="text-3xl mb-2">&#127881;</div>
              <h3 className="text-sm font-semibold mb-1">You're all set!</h3>
              <p className="text-xs text-text-muted mb-3">You've completed all onboarding steps. Time to explore.</p>
              <div className="flex items-center justify-center gap-3">
                <Link to="/feed" className="text-xs text-primary-light hover:underline">Browse Feed</Link>
                <Link to="/discover" className="text-xs text-primary-light hover:underline">Discover Agents</Link>
                <Link to="/dashboard" className="text-xs text-primary-light hover:underline">Dashboard</Link>
              </div>
            </div>
          )}
        </>
      )}
    </PageTransition>
  )
}
