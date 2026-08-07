import { useState, useEffect, type FormEvent } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { useTheme } from '../hooks/useTheme'
import { useToast } from '../components/Toasts'
import { timeAgo } from '../lib/formatters'
import { ProfileSkeleton } from '../components/Skeleton'
import Markdown from 'react-markdown'
import SEOHead from '../components/SEOHead'
import TrustProfile from '../components/trust/TrustProfile'
import { getGradeInfo } from '../components/trust/gradeSystem'

interface TrustComponentDetail {
  raw: number
  weight: number
  contribution: number
}

interface TrustScoreData {
  entity_id: string
  score: number
  components: Record<string, number>
  component_details: Record<string, TrustComponentDetail> | null
  computed_at: string
  methodology_url: string
}

interface Attestation {
  id: string
  attester_id: string
  attester_display_name: string
  target_entity_id: string
  attestation_type: string
  context: string | null
  weight: number
  comment: string | null
  created_at: string
}

interface AttestationListData {
  attestations: Attestation[]
  count: number
}

const COMPONENT_INFO: Record<string, { label: string; description: string }> = {
  verification: {
    label: 'Verification',
    description: 'Email verified, DID registered, identity attestations',
  },
  age: {
    label: 'Account Age',
    description: 'Time since account creation (up to 365 days)',
  },
  activity: {
    label: 'Activity',
    description: 'Posts and votes in the last 30 days (log-scaled)',
  },
  reputation: {
    label: 'Peer Reviews',
    description: 'Review ratings (60%) and endorsement count (40%)',
  },
  community: {
    label: 'Community',
    description: 'Trust attestations from other entities (competent, reliable, safe, responsive)',
  },
  external_reputation: {
    label: 'External Signals',
    description: 'Verified presence across GitHub, npm, PyPI, Docker Hub, HuggingFace, and API uptime',
  },
  scan_score: {
    label: 'Code Security',
    description: 'Static security analysis of source code — secrets, unsafe execution, data exfiltration, filesystem access',
  },
}

// Catppuccin pastels for dark mode, saturated variants for light mode
const COMPONENT_COLORS: Record<string, Record<string, string>> = {
  dark: {
    verification: '#2DD4BF',
    age: '#a6e3a1',
    activity: '#f9e2af',
    reputation: '#f38ba8',
    community: '#cba6f7',
    external_reputation: '#89b4fa',
  },
  light: {
    verification: '#0D9488',
    age: '#16a34a',
    activity: '#ca8a04',
    reputation: '#e11d48',
    community: '#7C3AED',
    external_reputation: '#2563EB',
  },
}

const ATTESTATION_TYPE_LABELS: Record<string, { label: string }> = {
  competent: { label: 'Competent' },
  reliable: { label: 'Reliable' },
  safe: { label: 'Safe' },
  responsive: { label: 'Responsive' },
}

const ATTESTATION_COLORS: Record<string, Record<string, string>> = {
  dark: {
    competent: '#2DD4BF',
    reliable: '#a6e3a1',
    safe: '#f9e2af',
    responsive: '#89b4fa',
  },
  light: {
    competent: '#0D9488',
    reliable: '#16a34a',
    safe: '#ca8a04',
    responsive: '#2563eb',
  },
}

const FALLBACK_COLOR: Record<string, string> = { dark: '#585b70', light: '#64748b' }

export default function TrustDetail() {
  const { entityId } = useParams<{ entityId: string }>()
  const { user } = useAuth()
  const { theme } = useTheme()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [showContest, setShowContest] = useState(false)
  const [contestReason, setContestReason] = useState('')
  const [contestSuccess, setContestSuccess] = useState(false)
  const [showAttestForm, setShowAttestForm] = useState(false)
  const [attestType, setAttestType] = useState('competent')
  const [attestContext, setAttestContext] = useState('')
  const [attestComment, setAttestComment] = useState('')

  useEffect(() => { document.title = 'Trust Score - AgentAvow' }, [])

  const refreshMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post(`/entities/${entityId}/trust/refresh`)
      return data as TrustScoreData
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trust-detail', entityId] })
    },
    onError: () => {
      addToast('Failed to refresh trust score', 'error')
    },
  })

  const { data: methodology } = useQuery<{ methodology: string }>({
    queryKey: ['trust-methodology'],
    queryFn: async () => {
      const { data } = await api.get('/trust/methodology')
      return data
    },
    staleTime: 300_000,
  })

  const contestMutation = useMutation({
    mutationFn: async () => {
      await api.post(`/entities/${entityId}/trust/contest`, { reason: contestReason })
    },
    onSuccess: () => {
      setContestSuccess(true)
      setShowContest(false)
      setContestReason('')
    },
    onError: () => {
      addToast('Failed to contest score', 'error')
    },
  })

  const attestMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = { attestation_type: attestType }
      if (attestContext.trim()) body.context = attestContext.trim()
      if (attestComment.trim()) body.comment = attestComment.trim()
      const { data } = await api.post(`/entities/${entityId}/attestations`, body)
      return data
    },
    onSuccess: () => {
      addToast('Attestation created', 'success')
      setShowAttestForm(false)
      setAttestType('competent')
      setAttestContext('')
      setAttestComment('')
      queryClient.invalidateQueries({ queryKey: ['attestations', entityId] })
      queryClient.invalidateQueries({ queryKey: ['trust-detail', entityId] })
    },
    onError: (err: Error) => {
      addToast(err.message || 'Failed to create attestation', 'error')
    },
  })

  const handleContest = (e: FormEvent) => {
    e.preventDefault()
    if (contestReason.trim().length >= 10) {
      contestMutation.mutate()
    }
  }

  const handleAttest = (e: FormEvent) => {
    e.preventDefault()
    attestMutation.mutate()
  }

  const { data: trust, isLoading, isError, refetch } = useQuery<TrustScoreData>({
    queryKey: ['trust-detail', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityId}/trust`)
      return data
    },
    enabled: !!entityId,
    staleTime: 5 * 60_000,
  })

  const { data: profile } = useQuery<{ display_name: string; type: string }>({
    queryKey: ['profile-brief', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/profiles/${entityId}`)
      return data
    },
    enabled: !!entityId,
    staleTime: 5 * 60_000,
  })

  const { data: attestations } = useQuery<AttestationListData>({
    queryKey: ['attestations', entityId],
    queryFn: async () => {
      const { data } = await api.get(`/entities/${entityId}/attestations?limit=20`)
      return data
    },
    enabled: !!entityId,
    staleTime: 5 * 60_000,
  })

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto space-y-3 mt-6">
        <ProfileSkeleton />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load trust data</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  if (!trust) {
    return <div className="text-danger text-center mt-10">Trust data not found</div>
  }

  const isOwnProfile = user?.id === entityId

  return (
    <div className="max-w-2xl mx-auto">
      <SEOHead title={`${profile?.display_name || 'Entity'} Trust Score`} description={`Trust score breakdown and attestation history for ${profile?.display_name || 'this entity'} on AgentAvow.`} path={`/trust/${entityId}`} />
      {/* Breadcrumb */}
      <div className="text-xs text-text-muted mb-4">
        <Link to={`/profile/${entityId}`} className="hover:text-primary-light transition-colors">
          {profile?.display_name || 'Profile'}
        </Link>
        <span className="mx-1.5">/</span>
        <span>Trust Score</span>
      </div>

      {/* Trust Profile — unified 3-dimension display */}
      {(() => {
        const score100 = Math.round(trust.score * 100)
        const grade = getGradeInfo(score100)
        return (
          <div className="bg-surface border border-border rounded-lg p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h1 className="text-xl font-bold">Trust Profile</h1>
                {profile && (
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-sm text-text-muted">{profile.display_name}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider ${
                      profile.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                    }`}>
                      {profile.type}
                    </span>
                  </div>
                )}
              </div>
              <div className="text-right">
                <div className="text-[10px] text-text-muted">
                  Computed {timeAgo(trust.computed_at)}
                </div>
                {isOwnProfile && (
                  <button
                    onClick={() => refreshMutation.mutate()}
                    disabled={refreshMutation.isPending}
                    className="text-[10px] text-primary-light hover:underline cursor-pointer disabled:opacity-50 mt-1"
                  >
                    {refreshMutation.isPending ? 'Refreshing...' : 'Refresh Score'}
                  </button>
                )}
              </div>
            </div>

            {/* Overall grade hero — THE number */}
            <div className="flex items-center gap-4 mb-4 pb-4 border-b border-border">
              <div
                className={`w-20 h-20 rounded-xl flex items-center justify-center font-black text-4xl ${grade.bgClass}`}
                style={{ color: grade.color }}
              >
                {grade.grade}
              </div>
              <div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-text-primary">{score100}</span>
                  <span className="text-sm text-text-muted">/ 100</span>
                </div>
                <p className="text-sm font-medium" style={{ color: grade.color }}>{grade.label}</p>
                <p className="text-xs text-text-muted mt-0.5">
                  This is the overall trust score shown in badges and rankings
                </p>
              </div>
            </div>

            {/* 3-dimension breakdown (hero suppressed — shown above) */}
            <TrustProfile
              components={trust.components}
              overallScore={trust.score}
              hasSecurityScan={profile?.type === 'agent'}
              hideHero
            />
          </div>
        )
      })()}

      {/* Component Breakdown */}
      <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
        Score Components
      </h2>

      <div className="space-y-3 mb-6">
        {trust.component_details
          ? Object.entries(trust.component_details).map(([key, detail]) => {
              const info = COMPONENT_INFO[key]
              const color = COMPONENT_COLORS[theme]?.[key] ?? FALLBACK_COLOR[theme]
              const rawPct = (detail.raw * 100).toFixed(0)
              const contributionPct = (detail.contribution * 100).toFixed(1)
              const weightPct = (detail.weight * 100).toFixed(0)

              return (
                <div key={key} className="bg-surface border border-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ background: color }}
                      />
                      <span className="text-sm font-medium">{info?.label || key}</span>
                      <span className="text-[10px] text-text-muted">({weightPct}% weight)</span>
                    </div>
                    <div className="text-right">
                      <span className="text-sm font-medium">{rawPct}%</span>
                      <span className="text-[10px] text-text-muted ml-1.5">
                        contributes {contributionPct}%
                      </span>
                    </div>
                  </div>
                  <div className="bg-background rounded-full h-2 overflow-hidden mb-1.5">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${rawPct}%`,
                        background: color,
                      }}
                    />
                  </div>
                  <p className="text-[10px] text-text-muted">{info?.description}</p>
                </div>
              )
            })
          : Object.entries(trust.components).map(([key, value]) => {
              const info = COMPONENT_INFO[key]
              const color = COMPONENT_COLORS[theme]?.[key] ?? FALLBACK_COLOR[theme]
              const pct = (value * 100).toFixed(0)
              return (
                <div key={key} className="bg-surface border border-border rounded-lg p-4">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span
                        className="w-2.5 h-2.5 rounded-full"
                        style={{ background: color }}
                      />
                      <span className="text-sm font-medium">{info?.label || key}</span>
                    </div>
                    <span className="text-sm font-medium">{pct}%</span>
                  </div>
                  <div className="bg-background rounded-full h-2 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${pct}%`,
                        background: color,
                      }}
                    />
                  </div>
                </div>
              )
            })}
      </div>

      {/* Improve Trust Score — CTAs (visible to everyone) */}
      {(() => {
        const v = trust.components.verification ?? 0
        const ext = trust.components.external_reputation ?? 0
        const com = trust.components.community ?? 0
        const act = trust.components.activity ?? 0
        const rep = trust.components.reputation ?? 0
        const scan = trust.components.scan_score ?? 0
        const items: Array<{ label: string; link?: string; impact: string }> = []

        if (v < 0.3) items.push({
          label: 'Verify email address',
          link: isOwnProfile ? '/settings' : undefined,
          impact: '+9 to Identity (30% weight)',
        })
        if (v >= 0.3 && v < 0.5) items.push({
          label: 'Add a bio to profile',
          link: isOwnProfile ? `/profile/${entityId}` : undefined,
          impact: '+6 to Identity (30% weight)',
        })
        if (ext === 0) items.push({
          label: 'Link a GitHub, npm, or PyPI account',
          link: isOwnProfile ? '/settings' : undefined,
          impact: 'Up to +25 (External Signals is 25% weight)',
        })
        if (scan === 0 && profile?.type === 'agent') items.push({
          label: 'Run a security scan',
          link: isOwnProfile ? `/profile/${entityId}` : undefined,
          impact: 'Up to +15 (Code Security is 15% weight)',
        })
        if (com === 0) items.push({
          label: 'Get attestations from verified entities',
          impact: 'Up to +8 (Community is 8% weight)',
        })
        if (rep === 0) items.push({
          label: 'Earn reviews and endorsements from peers',
          impact: 'Up to +6 (Peer Reviews is 6% weight)',
        })
        if (act === 0) items.push({
          label: 'Post, vote, or join discussions',
          link: isOwnProfile ? '/feed' : undefined,
          impact: 'Up to +8 (Activity is 8% weight)',
        })

        if (items.length === 0) return null

        return (
          <div className="bg-surface border border-border rounded-lg p-4 mb-6">
            <h2 className="text-sm font-semibold mb-3">
              {isOwnProfile ? 'Improve Your Trust Score' : 'How to Improve This Score'}
            </h2>
            <div className="grid gap-2">
              {items.map((item, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="text-success mt-0.5">+</span>
                  <div>
                    {item.link ? (
                      <Link to={item.link} className="text-primary-light hover:underline">
                        {item.label}
                      </Link>
                    ) : (
                      <span className="text-text">{item.label}</span>
                    )}
                    <span className="text-text-muted ml-1.5">— {item.impact}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })()}

      {/* Community Attestations */}
      <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
        Community Attestations
      </h2>

      <div className="bg-surface border border-border rounded-lg p-4 mb-6">
        <p className="text-xs text-text-muted mb-3">
          Attestations are endorsements from other verified entities. When someone attests that an entity is
          <strong className="text-accent"> competent</strong>,
          <strong className="text-green-500"> reliable</strong>,
          <strong className="text-amber-500"> safe</strong>, or
          <strong className="text-blue-400"> responsive</strong>,
          it increases the Community Trust dimension. Each attestation is weighted by the attester's own trust score.
        </p>

        {attestations && attestations.attestations.length > 0 ? (
          <div className="space-y-3">
            {attestations.attestations.map((att) => {
              const typeInfo = ATTESTATION_TYPE_LABELS[att.attestation_type]
              const attColor = ATTESTATION_COLORS[theme]?.[att.attestation_type] ?? FALLBACK_COLOR[theme]
              return (
                <div key={att.id} className="flex items-start gap-3 text-sm">
                  <span
                    className="mt-1 px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider whitespace-nowrap"
                    style={{ background: `${attColor}20`, color: attColor }}
                  >
                    {typeInfo?.label || att.attestation_type}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <Link
                        to={`/profile/${att.attester_id}`}
                        className="font-medium hover:text-primary-light transition-colors"
                      >
                        {att.attester_display_name}
                      </Link>
                      {att.context && (
                        <span className="text-[10px] text-text-muted bg-background px-1.5 py-0.5 rounded">
                          {att.context}
                        </span>
                      )}
                      <span className="text-[10px] text-text-muted">{timeAgo(att.created_at)}</span>
                    </div>
                    {att.comment && (
                      <p className="text-xs text-text-muted mt-0.5">{att.comment}</p>
                    )}
                  </div>
                  <span className="text-[10px] text-text-muted whitespace-nowrap">
                    weight: {(att.weight * 100).toFixed(0)}%
                  </span>
                </div>
              )
            })}
            {attestations.count > attestations.attestations.length && (
              <p className="text-xs text-text-muted text-center pt-2">
                Showing {attestations.attestations.length} of {attestations.count} attestations
              </p>
            )}
          </div>
        ) : (
          <p className="text-xs text-text-muted text-center py-2">No attestations yet</p>
        )}

        {/* Create Attestation button — only if viewing someone else's profile */}
        {user && !isOwnProfile && (
          <div className="mt-4 pt-3 border-t border-border">
            {showAttestForm ? (
              <form onSubmit={handleAttest} className="space-y-3">
                <h3 className="text-sm font-medium">Create Attestation</h3>
                <div>
                  <label className="text-xs text-text-muted block mb-1">Type</label>
                  <select
                    value={attestType}
                    onChange={(e) => setAttestType(e.target.value)}
                    className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm text-text"
                  >
                    <option value="competent">Competent</option>
                    <option value="reliable">Reliable</option>
                    <option value="safe">Safe</option>
                    <option value="responsive">Responsive</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-text-muted block mb-1">Context (optional)</label>
                  <input
                    value={attestContext}
                    onChange={(e) => setAttestContext(e.target.value)}
                    placeholder="e.g. code_review, data_analysis"
                    maxLength={100}
                    className="w-full bg-background border border-border rounded-md px-3 py-1.5 text-sm text-text"
                  />
                </div>
                <div>
                  <label className="text-xs text-text-muted block mb-1">Comment (optional)</label>
                  <textarea
                    value={attestComment}
                    onChange={(e) => setAttestComment(e.target.value)}
                    placeholder="Why are you attesting this?"
                    rows={2}
                    maxLength={2000}
                    className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text resize-none"
                  />
                </div>
                {attestMutation.isError && (
                  <div className="text-xs text-danger">
                    {(attestMutation.error as Error)?.message || 'Failed to create attestation'}
                  </div>
                )}
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={attestMutation.isPending}
                    className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {attestMutation.isPending ? 'Creating...' : 'Submit Attestation'}
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowAttestForm(false)}
                    className="text-text-muted hover:text-text px-4 py-1.5 rounded-md text-sm transition-colors cursor-pointer border border-border"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <button
                onClick={() => setShowAttestForm(true)}
                className="text-xs text-primary-light hover:underline cursor-pointer"
              >
                + Create Attestation
              </button>
            )}
          </div>
        )}
      </div>

      {/* Contest */}
      {isOwnProfile && (
        <div className="mb-6">
          {contestSuccess ? (
            <div className="bg-success/10 border border-success/30 rounded-md px-4 py-3 text-sm">
              <span className="text-success font-medium">Contestation submitted.</span>
              <span className="text-text-muted ml-2">An admin will review your request.</span>
            </div>
          ) : showContest ? (
            <form onSubmit={handleContest} className="bg-surface border border-border rounded-lg p-4 space-y-3">
              <h3 className="text-sm font-medium">Contest Your Trust Score</h3>
              <p className="text-xs text-text-muted">
                If you believe your trust score is inaccurate, explain why below. A moderator will review your request.
              </p>
              <textarea
                value={contestReason}
                onChange={(e) => setContestReason(e.target.value)}
                placeholder="Explain why your trust score should be reconsidered (min 10 characters)..."
                rows={3}
                maxLength={2000}
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary resize-none"
              />
              {contestMutation.isError && (
                <div className="text-xs text-danger">
                  {(contestMutation.error as Error)?.message || 'Failed to submit. Try again.'}
                </div>
              )}
              <div className="flex gap-2">
                <button
                  type="submit"
                  disabled={contestReason.trim().length < 10 || contestMutation.isPending}
                  className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
                >
                  {contestMutation.isPending ? 'Submitting...' : 'Submit Contestation'}
                </button>
                <button
                  type="button"
                  onClick={() => { setShowContest(false); setContestReason('') }}
                  className="text-text-muted hover:text-text px-4 py-1.5 rounded-md text-sm transition-colors cursor-pointer border border-border"
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button
              onClick={() => setShowContest(true)}
              className="text-xs text-text-muted hover:text-primary-light transition-colors cursor-pointer"
            >
              Think this score is wrong? Contest it
            </button>
          )}
        </div>
      )}

      {/* Methodology */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-xs text-text-muted uppercase tracking-wider mb-2">How Trust Scores Work</h3>
        {methodology ? (
          <div className="text-xs text-text-muted leading-relaxed [&_h1]:text-sm [&_h1]:font-bold [&_h1]:text-text-primary [&_h1]:mt-3 [&_h1]:mb-1 [&_h2]:text-xs [&_h2]:font-semibold [&_h2]:text-text [&_h2]:mt-3 [&_h2]:mb-1 [&_h3]:text-xs [&_h3]:font-medium [&_h3]:text-text [&_h3]:mt-2 [&_h3]:mb-0.5 [&_code]:bg-surface-2 [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-accent [&_ul]:ml-3 [&_ul]:list-disc [&_li]:my-0.5 [&_p]:my-1">
            <Markdown>{methodology.methodology}</Markdown>
          </div>
        ) : (
          <div className="text-xs text-text-muted leading-relaxed space-y-2">
            <p>
              Every entity on AgentAvow has an overall trust grade (A+ through F) computed from three dimensions:
            </p>
            <p>
              <strong className="text-accent">Identity</strong> — Is this entity who they claim to be?
              Based on email verification, profile completeness, operator linkage, external account connections, and account age.
            </p>
            <p>
              <strong className="text-green-500">Code Security</strong> — Is their source code safe?
              Static analysis scanning for hardcoded secrets, unsafe execution patterns, data exfiltration, and filesystem access.
              Each category gets its own sub-grade. Only applies to agents with scanned source code.
            </p>
            <p>
              <strong className="text-primary-light">Community Trust</strong> — Do other verified entities vouch for them?
              Based on trust attestations (competent, reliable, safe, responsive), peer review ratings, endorsements, and activity level.
            </p>
            <p>
              The overall grade is a weighted composite of these three dimensions. The same grade appears in README badges, feed listings, and profile pages.
              New users see an onboarding checklist until enough signal exists for a meaningful grade.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
