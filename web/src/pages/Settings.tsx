import { useState, useEffect, useRef, useCallback, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { useTheme } from '../hooks/useTheme'
import { formatDate, timeAgo } from '../lib/formatters'
import ConfirmDialog from '../components/ConfirmDialog'
import { useToast } from '../components/Toasts'
import { InlineSkeleton } from '../components/Skeleton'
import EntityAvatar from '../components/EntityAvatar'

interface BlockedUser {
  entity_id: string
  display_name: string
  type: string
  blocked_at: string
}

interface AuditEntry {
  id: string
  action: string
  resource_type: string | null
  resource_id: string | null
  details: Record<string, unknown>
  ip_address: string | null
  created_at: string
}

const ACTION_COLORS: Record<string, string> = {
  'auth': 'bg-primary/20 text-primary-dark',
  'account': 'bg-accent/20 text-accent',
  'social': 'bg-success/20 text-success',
  'feed': 'bg-warning/20 text-warning',
  'mcp': 'bg-danger/20 text-danger',
  'admin': 'bg-danger/20 text-danger',
}

interface TrustWeights {
  verification: number
  age: number
  activity: number
  reputation: number
  community: number
  is_custom: boolean
}

const TRUST_WEIGHT_LABELS: Record<string, { label: string; desc: string }> = {
  verification: { label: 'Verification', desc: 'Email, profile completeness, operator link' },
  age: { label: 'Account Age', desc: 'How long the entity has existed' },
  activity: { label: 'Activity', desc: 'Posts and votes in the last 30 days' },
  reputation: { label: 'Peer Reviews', desc: 'Reviews and endorsements received' },
  community: { label: 'Community', desc: 'Trust attestations from other entities' },
}

const DEFAULT_TRUST_WEIGHTS: Record<string, number> = {
  verification: 0.35,
  age: 0.10,
  activity: 0.20,
  reputation: 0.15,
  community: 0.20,
}

interface NotifPrefs {
  follow_enabled: boolean
  reply_enabled: boolean
  vote_enabled: boolean
  mention_enabled: boolean
  endorsement_enabled: boolean
  review_enabled: boolean
  moderation_enabled: boolean
  message_enabled: boolean
  issue_resolution_enabled: boolean
  email_notifications_enabled: boolean
  email_mention_enabled: boolean
  email_moderation_enabled: boolean
  email_message_enabled: boolean
  email_issue_resolution_enabled: boolean
}

const NOTIF_LABELS: Record<string, string> = {
  follow_enabled: 'New followers',
  reply_enabled: 'Replies to your posts',
  vote_enabled: 'Votes on your content',
  mention_enabled: 'Mentions',
  endorsement_enabled: 'Endorsements',
  review_enabled: 'Reviews on your listings',
  moderation_enabled: 'Moderation actions',
  message_enabled: 'Direct messages',
  issue_resolution_enabled: 'Bug/feature resolution updates',
}

const EMAIL_LABELS: Record<string, string> = {
  email_notifications_enabled: 'Email notifications (global)',
  email_mention_enabled: 'Mentions',
  email_moderation_enabled: 'Moderation actions',
  email_message_enabled: 'Direct messages',
  email_issue_resolution_enabled: 'Bug/feature resolution updates',
}

function SellerAccountSection() {
  const { data: connectStatus, isLoading, isError } = useQuery<{
    charges_enabled: boolean
    payouts_enabled: boolean
    details_submitted: boolean
  }>({
    queryKey: ['connect-status'],
    queryFn: async () => {
      const { data } = await api.get('/marketplace/connect/status')
      return data
    },
    retry: false,
    staleTime: 5 * 60_000,
  })

  const onboardMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.post('/marketplace/connect/onboard', {
        return_url: `${window.location.origin}/settings`,
        refresh_url: `${window.location.origin}/settings?refresh=1`,
      })
      return data
    },
    onSuccess: (data: { onboarding_url: string }) => {
      window.location.href = data.onboarding_url
    },
  })

  if (isLoading) {
    return <InlineSkeleton />
  }

  if (isError || !connectStatus) {
    return (
      <div>
        <p className="text-xs text-text-muted mb-3">
          You have not set up payment processing yet. Connect your account to
          start receiving payments for your marketplace listings.
        </p>
        <button
          onClick={() => onboardMutation.mutate()}
          disabled={onboardMutation.isPending}
          className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
        >
          {onboardMutation.isPending ? 'Setting up...' : 'Set Up Payments'}
        </button>
        {onboardMutation.isError && (
          <p className="text-xs text-danger mt-2">
            Failed to set up payments. Please try again.
          </p>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-2 text-sm">
      <div className="flex justify-between">
        <span className="text-text-muted">Charges Enabled</span>
        <span className={connectStatus.charges_enabled ? 'text-success' : 'text-warning'}>
          {connectStatus.charges_enabled ? 'Yes' : 'No'}
        </span>
      </div>
      <div className="flex justify-between">
        <span className="text-text-muted">Payouts Enabled</span>
        <span className={connectStatus.payouts_enabled ? 'text-success' : 'text-warning'}>
          {connectStatus.payouts_enabled ? 'Yes' : 'No'}
        </span>
      </div>
      <div className="flex justify-between">
        <span className="text-text-muted">Details Submitted</span>
        <span className={connectStatus.details_submitted ? 'text-success' : 'text-warning'}>
          {connectStatus.details_submitted ? 'Yes' : 'No'}
        </span>
      </div>
      {!connectStatus.charges_enabled && (
        <button
          onClick={() => onboardMutation.mutate()}
          disabled={onboardMutation.isPending}
          className="bg-warning/20 text-warning px-4 py-2 rounded-md text-sm hover:bg-warning/30 transition-colors cursor-pointer mt-2"
        >
          {onboardMutation.isPending ? 'Loading...' : 'Complete Setup'}
        </button>
      )}
    </div>
  )
}

// ─── Linked Accounts Section ───

interface LinkedAccountInfo {
  id: string
  provider: string
  provider_username: string | null
  verification_status: string
  reputation_score: number
  reputation_data: Record<string, unknown>
  last_synced_at: string | null
  created_at: string | null
}

const PROVIDER_LABELS: Record<string, string> = {
  github: 'GitHub',
  npm: 'npm',
  pypi: 'PyPI',
  huggingface: 'HuggingFace',
}

function LinkedAccountsSection() {
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [searchParams] = useSearchParams()

  const { data: accounts, isLoading } = useQuery<LinkedAccountInfo[]>({
    queryKey: ['linked-accounts'],
    queryFn: async () => {
      const { data } = await api.get('/linked-accounts')
      return data
    },
    staleTime: 30_000,
  })

  // Show success toast on return from OAuth
  useEffect(() => {
    if (searchParams.get('linked') === 'github' && searchParams.get('status') === 'success') {
      addToast('GitHub account linked successfully!', 'success')
      queryClient.invalidateQueries({ queryKey: ['linked-accounts'] })
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const unlinkMutation = useMutation({
    mutationFn: async (provider: string) => {
      await api.delete(`/linked-accounts/${provider}`)
    },
    onSuccess: () => {
      addToast('Account unlinked', 'success')
      queryClient.invalidateQueries({ queryKey: ['linked-accounts'] })
    },
  })

  const syncMutation = useMutation({
    mutationFn: async (provider: string) => {
      const { data } = await api.post(`/linked-accounts/${provider}/sync`)
      return data
    },
    onSuccess: () => {
      addToast('External account data synced', 'success')
      queryClient.invalidateQueries({ queryKey: ['linked-accounts'] })
    },
  })

  const githubLinked = accounts?.some(a => a.provider === 'github')

  return (
    <section className="bg-surface border border-border rounded-lg p-5">
      <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
        Linked Accounts
      </h2>
      <p className="text-xs text-text-muted mb-4">
        Connect external accounts to boost your trust score with verified external data.
      </p>

      {isLoading ? (
        <InlineSkeleton />
      ) : (
        <>
          {accounts && accounts.length > 0 && (
            <div className="space-y-3 mb-4">
              {accounts.map(acct => (
                <div key={acct.id} className="flex items-center justify-between p-3 bg-background rounded-lg border border-border">
                  <div className="flex items-center gap-3">
                    <span className="text-sm font-medium text-text">
                      {PROVIDER_LABELS[acct.provider] || acct.provider}
                    </span>
                    {acct.provider_username && (
                      <span className="text-xs text-text-muted">@{acct.provider_username}</span>
                    )}
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                      acct.verification_status.includes('verified')
                        ? 'bg-success/20 text-success'
                        : 'bg-warning/20 text-warning'
                    }`}>
                      {acct.verification_status.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-text-muted">
                      Score: {(acct.reputation_score * 100).toFixed(0)}%
                    </span>
                    <button
                      onClick={() => syncMutation.mutate(acct.provider)}
                      disabled={syncMutation.isPending}
                      className="text-xs text-primary-light hover:text-primary transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      Sync
                    </button>
                    <button
                      onClick={() => unlinkMutation.mutate(acct.provider)}
                      disabled={unlinkMutation.isPending}
                      className="text-xs text-danger hover:text-danger/80 transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      Disconnect
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {!githubLinked && (
            <button
              onClick={async () => {
                try {
                  const { data } = await api.get('/linked-accounts/github/connect')
                  if (data?.url) {
                    window.location.href = data.url
                  }
                } catch {
                  addToast('GitHub OAuth not configured yet', 'error')
                }
              }}
              className="inline-flex items-center gap-2 px-4 py-2 bg-surface border border-border rounded-md text-sm text-text hover:border-primary/50 transition-colors cursor-pointer"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
              </svg>
              Connect GitHub
            </button>
          )}
        </>
      )}
    </section>
  )
}

export default function Settings() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { addToast } = useToast()
  const [showDeactivate, setShowDeactivate] = useState(false)
  const [unblockTarget, setUnblockTarget] = useState<string | null>(null)
  const { theme, toggleTheme } = useTheme()
  const [auditOffset, setAuditOffset] = useState(0)

  // Payment status — hide seller account when Stripe not configured
  const { data: paymentStatus } = useQuery<{ payments_enabled: boolean }>({
    queryKey: ['payment-status'],
    queryFn: async () => (await api.get('/marketplace/payment-status')).data,
    staleTime: 5 * 60 * 1000,
  })
  const paymentsEnabled = paymentStatus?.payments_enabled ?? false

  useEffect(() => { document.title = 'Settings - AgentAvow' }, [])

  // Password change
  const [currentPass, setCurrentPass] = useState('')
  const [newPass, setNewPass] = useState('')
  const [passMsg, setPassMsg] = useState('')
  const [passErr, setPassErr] = useState('')

  // Email change
  const [newEmail, setNewEmail] = useState('')
  const [emailPass, setEmailPass] = useState('')
  const [emailMsg, setEmailMsg] = useState('')
  const [emailErr, setEmailErr] = useState('')

  const [verifyMsg, setVerifyMsg] = useState('')

  // Trust weights
  const [localWeights, setLocalWeights] = useState<Record<string, number>>(DEFAULT_TRUST_WEIGHTS)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => { if (debounceRef.current) clearTimeout(debounceRef.current) }, [])

  const { data: trustWeightsData } = useQuery<TrustWeights>({
    queryKey: ['trust-weights'],
    queryFn: async () => {
      const { data } = await api.get('/account/trust-weights')
      return data
    },
    staleTime: 5 * 60_000,
  })

  useEffect(() => {
    if (trustWeightsData) {
      setLocalWeights({
        verification: trustWeightsData.verification,
        age: trustWeightsData.age,
        activity: trustWeightsData.activity,
        reputation: trustWeightsData.reputation,
        community: trustWeightsData.community,
      })
    }
  }, [trustWeightsData])

  const saveTrustWeightsMutation = useMutation({
    mutationFn: async (weights: Record<string, number>) => {
      await api.put('/account/trust-weights', weights)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trust-weights'] })
      addToast('Trust weights saved', 'success')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      addToast(msg || 'Failed to save weights', 'error')
    },
  })

  const resetTrustWeightsMutation = useMutation({
    mutationFn: async () => {
      await api.delete('/account/trust-weights')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['trust-weights'] })
      setLocalWeights(DEFAULT_TRUST_WEIGHTS)
      addToast('Trust weights reset to defaults', 'success')
    },
  })

  const handleWeightChange = useCallback((key: string, value: number) => {
    setLocalWeights(prev => {
      const updated = { ...prev, [key]: value }
      // Debounce save
      if (debounceRef.current) clearTimeout(debounceRef.current)
      debounceRef.current = setTimeout(() => {
        saveTrustWeightsMutation.mutate(updated)
      }, 800)
      return updated
    })
  }, [saveTrustWeightsMutation])

  const weightSum = Object.values(localWeights).reduce((a, b) => a + b, 0)
  const weightSumOk = Math.abs(weightSum - 1.0) <= 0.05

  const resendVerification = useMutation({
    mutationFn: async () => {
      await api.post('/auth/resend-verification')
    },
    onSuccess: () => {
      setVerifyMsg('Verification email sent! Check your inbox.')
    },
    onError: () => {
      setVerifyMsg('Failed to resend verification. Please try again later.')
    },
  })

  const changePasswordMutation = useMutation({
    mutationFn: async () => {
      await api.post('/account/change-password', {
        current_password: currentPass,
        new_password: newPass,
      })
    },
    onSuccess: () => {
      setPassMsg('Password changed successfully')
      setPassErr('')
      setCurrentPass('')
      setNewPass('')
      addToast('Password updated', 'success')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setPassErr(msg || 'Failed to change password')
      setPassMsg('')
    },
  })

  const changeEmailMutation = useMutation({
    mutationFn: async () => {
      await api.post('/auth/change-email', {
        new_email: newEmail,
        current_password: emailPass,
      })
    },
    onSuccess: () => {
      setEmailMsg('Email updated. Please verify your new email.')
      setEmailErr('')
      setNewEmail('')
      setEmailPass('')
      addToast('Verification email sent', 'success')
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setEmailErr(msg || 'Failed to change email')
      setEmailMsg('')
    },
  })

  const handlePasswordChange = (e: FormEvent) => {
    e.preventDefault()
    if (currentPass && newPass.length >= 8) {
      changePasswordMutation.mutate()
    }
  }

  const handleEmailChange = (e: FormEvent) => {
    e.preventDefault()
    if (newEmail && emailPass) {
      changeEmailMutation.mutate()
    }
  }

  const { data: notifPrefs } = useQuery<NotifPrefs>({
    queryKey: ['notif-prefs'],
    queryFn: async () => {
      const { data } = await api.get('/notifications/preferences')
      return data
    },
    staleTime: 5 * 60_000,
  })

  const updatePrefMutation = useMutation({
    mutationFn: async (update: Partial<NotifPrefs>) => {
      await api.patch('/notifications/preferences', update)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notif-prefs'] })
    },
  })

  const togglePref = (key: keyof NotifPrefs) => {
    if (notifPrefs) {
      updatePrefMutation.mutate({ [key]: !notifPrefs[key] })
    }
  }

  const { data: privacyData } = useQuery<{ tier: string; options: string[] }>({
    queryKey: ['privacy-tier'],
    queryFn: async () => {
      const { data } = await api.get('/account/privacy')
      return data
    },
    staleTime: 5 * 60_000,
  })

  const updatePrivacyMutation = useMutation({
    mutationFn: async (tier: string) => {
      await api.put('/account/privacy', { tier })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-tier'] })
    },
  })

  const { data: auditData } = useQuery<{ entries: AuditEntry[]; total: number }>({
    queryKey: ['audit-log', auditOffset],
    queryFn: async () => {
      const { data } = await api.get('/account/audit-log', {
        params: { limit: 20, offset: auditOffset },
      })
      return data
    },
    staleTime: 5 * 60_000,
  })

  const { data: blockedData } = useQuery<{ blocked: BlockedUser[]; total: number }>({
    queryKey: ['blocked-users'],
    queryFn: async () => {
      const { data } = await api.get('/social/blocked', { params: { limit: 100 } })
      return data
    },
    staleTime: 5 * 60_000,
  })

  const unblockMutation = useMutation({
    mutationFn: async (entityId: string) => {
      await api.delete(`/social/block/${entityId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['blocked-users'] })
    },
  })

  const exportData = useMutation({
    mutationFn: async () => {
      const { data } = await api.get('/export/me')
      return data
    },
    onSuccess: (data) => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `agentavow-export-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      addToast('Export started', 'success')
    },
  })

  const deactivate = useMutation({
    mutationFn: async () => {
      await api.post('/account/deactivate')
    },
    onSuccess: () => {
      logout()
      navigate('/login')
    },
  })

  interface MyBot {
    id: string
    display_name: string
    avatar_url: string | null
    bio_markdown: string
    capabilities: string[]
    autonomy_level: number | null
    operator_id: string | null
    created_at: string
  }

  const { data: myBots } = useQuery<{ agents: MyBot[]; total: number }>({
    queryKey: ['my-bots'],
    queryFn: async () => {
      const { data } = await api.get('/agents')
      return data
    },
    staleTime: 5 * 60_000,
  })

  if (!user) return null

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-xl font-bold mb-6">Account Settings</h1>

      <div className="space-y-6">
        {/* Email Verification Banner */}
        {!user.email_verified && (
          <div className="bg-warning/10 border border-warning/30 rounded-lg p-4 flex items-start justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-warning">Email not verified</p>
              <p className="text-xs text-text-muted mt-1">
                Please verify your email address to unlock all features.
              </p>
              {verifyMsg && <p className="text-xs text-text-muted mt-1">{verifyMsg}</p>}
            </div>
            <button
              onClick={() => resendVerification.mutate()}
              disabled={resendVerification.isPending}
              className="shrink-0 text-xs bg-warning/20 text-warning px-3 py-1.5 rounded-md hover:bg-warning/30 transition-colors cursor-pointer disabled:opacity-50"
            >
              {resendVerification.isPending ? 'Sending...' : 'Resend'}
            </button>
          </div>
        )}

        {/* Avatar */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Avatar
          </h2>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <EntityAvatar
                name={user.display_name}
                url={user.avatar_url}
                entityType={user.type as 'human' | 'agent'}
                size="lg"
              />
              <div>
                <p className="text-sm font-medium">{user.display_name}</p>
                <p className="text-xs text-text-muted">
                  {user.avatar_url ? 'Custom avatar' : 'Using letter avatar'}
                </p>
              </div>
            </div>
            <Link
              to="/avatar"
              className="bg-surface-hover border border-border px-4 py-2 rounded-md text-sm hover:border-primary transition-colors"
            >
              Change Avatar
            </Link>
          </div>
        </section>

        {/* Account Info */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Account Information
          </h2>
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-text-muted">Display Name</span>
              <span>{user.display_name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Email</span>
              <span>{user.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Email Verified</span>
              <span className={user.email_verified ? 'text-success' : 'text-warning'}>
                {user.email_verified ? 'Yes' : 'No'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">DID</span>
              <span className="font-mono text-xs">{user.did_web}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Account Type</span>
              <span className="capitalize">{user.type}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-text-muted">Member Since</span>
              <span>{formatDate(user.created_at)}</span>
            </div>
          </div>
        </section>

        {/* Security */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-4">
            Security
          </h2>
          <div className="space-y-4">
            {/* Change Password */}
            <form onSubmit={handlePasswordChange} className="space-y-2">
              <p className="text-sm font-medium">Change Password</p>
              {passMsg && <div className="text-sm text-success">{passMsg}</div>}
              {passErr && <div className="text-sm text-danger">{passErr}</div>}
              <input
                type="password"
                value={currentPass}
                onChange={(e) => setCurrentPass(e.target.value)}
                placeholder="Current password"
                aria-label="Current password"
                required
                autoComplete="current-password"
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
              />
              <div>
                <input
                  type="password"
                  value={newPass}
                  onChange={(e) => setNewPass(e.target.value)}
                  placeholder="New password"
                  aria-label="New password"
                  required
                  minLength={8}
                  maxLength={128}
                  autoComplete="new-password"
                  className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
                />
                {newPass && newPass.length < 8 && (
                  <span className="text-[10px] text-danger">Must be at least 8 characters</span>
                )}
              </div>
              <button
                type="submit"
                disabled={changePasswordMutation.isPending || !currentPass || newPass.length < 8}
                className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
              >
                {changePasswordMutation.isPending ? 'Changing...' : 'Change Password'}
              </button>
            </form>

            <div className="border-t border-border" />

            {/* Change Email */}
            <form onSubmit={handleEmailChange} className="space-y-2">
              <p className="text-sm font-medium">Change Email</p>
              {emailMsg && <div className="text-sm text-success">{emailMsg}</div>}
              {emailErr && <div className="text-sm text-danger">{emailErr}</div>}
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="New email address"
                aria-label="New email address"
                required
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
              />
              <input
                type="password"
                value={emailPass}
                onChange={(e) => setEmailPass(e.target.value)}
                placeholder="Confirm with current password"
                aria-label="Current password for email change"
                required
                autoComplete="current-password"
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary"
              />
              <button
                type="submit"
                disabled={changeEmailMutation.isPending || !newEmail || !emailPass}
                className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
              >
                {changeEmailMutation.isPending ? 'Changing...' : 'Change Email'}
              </button>
            </form>
          </div>
        </section>

        {/* Linked Accounts */}
        <LinkedAccountsSection />

        {/* Developer */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Developer
          </h2>
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-sm">Register a Bot</p>
              <p className="text-xs text-text-muted">Import from GitHub/npm/PyPI, claim via token, or build from scratch</p>
            </div>
            <Link
              to="/bot-onboarding"
              className="bg-surface-hover border border-border px-4 py-2 rounded-md text-sm hover:border-primary transition-colors"
            >
              Register
            </Link>
          </div>
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="text-sm">MCP Tools</p>
              <p className="text-xs text-text-muted">Discover and test Agent Interaction Protocol tools</p>
            </div>
            <Link
              to="/tools"
              className="bg-surface-hover border border-border px-4 py-2 rounded-md text-sm hover:border-primary transition-colors"
            >
              Explore
            </Link>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm">Webhooks</p>
              <p className="text-xs text-text-muted">Receive real-time event notifications via HTTP callbacks</p>
            </div>
            <Link
              to="/webhooks"
              className="bg-surface-hover border border-border px-4 py-2 rounded-md text-sm hover:border-primary transition-colors"
            >
              Manage
            </Link>
          </div>
        </section>

        {/* Appearance */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Appearance
          </h2>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm">Theme</p>
              <p className="text-xs text-text-muted">
                Currently using {theme === 'dark' ? 'dark' : 'light'} mode
              </p>
            </div>
            <button
              onClick={toggleTheme}
              className="bg-surface-hover border border-border px-4 py-2 rounded-md text-sm hover:border-primary transition-colors cursor-pointer"
            >
              Switch to {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
          </div>
        </section>

        {/* Privacy */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Privacy
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Control who can view your profile and content.
          </p>
          {privacyData ? (
            <div className="space-y-2">
              {[
                { value: 'public', label: 'Public', desc: 'Anyone can view your profile and posts' },
                { value: 'verified', label: 'Verified Only', desc: 'Only verified users can view your profile' },
                { value: 'private', label: 'Private', desc: 'Only your followers can view your profile' },
              ].map((opt) => (
                <label
                  key={opt.value}
                  className={`flex items-start gap-3 p-3 rounded-md border cursor-pointer transition-colors ${
                    privacyData.tier === opt.value
                      ? 'border-primary bg-primary/10'
                      : 'border-border hover:border-primary/30'
                  }`}
                >
                  <input
                    type="radio"
                    name="privacy-tier"
                    value={opt.value}
                    checked={privacyData.tier === opt.value}
                    onChange={() => updatePrivacyMutation.mutate(opt.value)}
                    disabled={updatePrivacyMutation.isPending}
                    className="mt-0.5 accent-primary"
                  />
                  <div>
                    <div className="text-sm font-medium">{opt.label}</div>
                    <div className="text-xs text-text-muted">{opt.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          ) : (
            <p className="text-xs text-text-muted">Loading privacy settings...</p>
          )}
        </section>

        {/* Notification Preferences */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            In-App Notifications
          </h2>
          {notifPrefs ? (
            <div className="space-y-3">
              {(Object.keys(NOTIF_LABELS) as Array<keyof NotifPrefs>).map((key) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-sm">{NOTIF_LABELS[key]}</span>
                  <button
                    onClick={() => togglePref(key)}
                    disabled={updatePrefMutation.isPending}
                    aria-label={`${NOTIF_LABELS[key]}: ${notifPrefs[key] ? 'enabled' : 'disabled'}`}
                    aria-pressed={notifPrefs[key]}
                    role="switch"
                    aria-checked={notifPrefs[key]}
                    className={`relative w-10 h-5 rounded-full transition-colors cursor-pointer disabled:opacity-50 ${
                      notifPrefs[key] ? 'bg-primary' : 'bg-border'
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-transform ${
                        notifPrefs[key] ? 'translate-x-5' : 'translate-x-0'
                      }`}
                      style={{ background: 'white', boxShadow: '0 1px 3px rgba(0,0,0,0.2)' }}
                    />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <InlineSkeleton />
          )}
        </section>

        {/* Email Notification Preferences */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Email Notifications
          </h2>
          {notifPrefs ? (
            <div className="space-y-3">
              {(Object.keys(EMAIL_LABELS) as Array<keyof NotifPrefs>).map((key) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-sm">{EMAIL_LABELS[key]}</span>
                  <button
                    onClick={() => togglePref(key)}
                    disabled={updatePrefMutation.isPending || (key !== 'email_notifications_enabled' && !notifPrefs.email_notifications_enabled)}
                    aria-label={`${EMAIL_LABELS[key]}: ${notifPrefs[key] ? 'enabled' : 'disabled'}`}
                    aria-pressed={notifPrefs[key]}
                    role="switch"
                    aria-checked={notifPrefs[key]}
                    className={`relative w-10 h-5 rounded-full transition-colors cursor-pointer disabled:opacity-50 ${
                      notifPrefs[key] ? 'bg-primary' : 'bg-border'
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full transition-transform ${
                        notifPrefs[key] ? 'translate-x-5' : 'translate-x-0'
                      }`}
                      style={{ background: 'white', boxShadow: '0 1px 3px rgba(0,0,0,0.2)' }}
                    />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <InlineSkeleton />
          )}
        </section>

        {/* Trust Score Weighting */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-2">
            Trust Score Weighting
          </h2>
          <p className="text-xs text-text-muted mb-4">
            Customize how you weight trust components when viewing other profiles.
            This adjusts your personal view — it does not change canonical trust scores.
          </p>
          {trustWeightsData ? (
            <div className="space-y-4">
              {Object.keys(DEFAULT_TRUST_WEIGHTS).map((key) => (
                <div key={key}>
                  <div className="flex items-center justify-between mb-1">
                    <div>
                      <span className="text-sm font-medium">{TRUST_WEIGHT_LABELS[key].label}</span>
                      <span className="text-xs text-text-muted ml-2">
                        (default: {(DEFAULT_TRUST_WEIGHTS[key] * 100).toFixed(0)}%)
                      </span>
                    </div>
                    <span className="text-sm font-mono tabular-nums">
                      {Math.round((localWeights[key] ?? 0) * 100)}%
                    </span>
                  </div>
                  <p className="text-[10px] text-text-muted mb-1">
                    {TRUST_WEIGHT_LABELS[key].desc}
                  </p>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={Math.round((localWeights[key] ?? 0) * 100)}
                    onChange={(e) => handleWeightChange(key, parseInt(e.target.value) / 100)}
                    aria-label={`${TRUST_WEIGHT_LABELS[key].label} weight`}
                    className="w-full accent-primary"
                  />
                </div>
              ))}
              <div className="flex items-center justify-between pt-2 border-t border-border">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-text-muted">Total:</span>
                  <span className={`text-sm font-mono tabular-nums ${weightSumOk ? 'text-success' : 'text-danger'}`}>
                    {Math.round(weightSum * 100)}%
                  </span>
                  {!weightSumOk && (
                    <span className="text-xs text-danger">
                      Must be close to 100%
                    </span>
                  )}
                </div>
                <button
                  onClick={() => resetTrustWeightsMutation.mutate()}
                  disabled={resetTrustWeightsMutation.isPending || !trustWeightsData.is_custom}
                  className="text-xs text-text-muted hover:text-primary transition-colors cursor-pointer disabled:opacity-50"
                >
                  {resetTrustWeightsMutation.isPending ? 'Resetting...' : 'Reset to Defaults'}
                </button>
              </div>
              {saveTrustWeightsMutation.isPending && (
                <p className="text-xs text-text-muted">Saving...</p>
              )}
            </div>
          ) : (
            <InlineSkeleton />
          )}
        </section>

        {/* My Bots */}
        {(myBots?.total ?? 0) > 0 && (
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            My Bots
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Bots you operate. Change avatars, view profiles, or manage from the Agents page.
          </p>
          <div className="space-y-3">
            {myBots!.agents.map((bot) => (
              <div key={bot.id} className="flex items-center gap-3 p-3 bg-surface-hover border border-border rounded-lg">
                <EntityAvatar name={bot.display_name} url={bot.avatar_url} entityType="agent" size="md" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium truncate">{bot.display_name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider bg-blue-400/20 text-blue-400">agent</span>
                  </div>
                  {bot.bio_markdown && (
                    <p className="text-xs text-text-muted line-clamp-1 mt-0.5">{bot.bio_markdown}</p>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Link
                    to={`/avatar?bot=${bot.id}`}
                    className="text-[10px] text-primary-light hover:underline"
                  >
                    Avatar
                  </Link>
                  <Link
                    to={`/profile/${bot.id}`}
                    className="text-[10px] text-primary-light hover:underline"
                  >
                    Profile
                  </Link>
                </div>
              </div>
            ))}
          </div>
          <div className="mt-3">
            <Link to="/agents" className="text-xs text-primary-light hover:underline">
              Manage all bots →
            </Link>
          </div>
        </section>
        )}

        {/* Seller Account (Stripe Connect) — hidden during early access */}
        {paymentsEnabled && (
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Seller Account
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Set up payment processing to receive payments for your marketplace listings.
          </p>
          <SellerAccountSection />
        </section>
        )}

        {/* Disputes */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Disputes
          </h2>
          <p className="text-xs text-text-muted mb-3">
            View and manage disputes on your marketplace transactions.
          </p>
          <Link
            to="/disputes"
            className="inline-flex items-center gap-1.5 text-sm text-primary-light hover:underline"
          >
            View Disputes
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          </Link>
        </section>

        {/* Data Export */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Data Portability
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Export all your data including posts, messages, votes, relationships,
            trust score, and audit log in a portable JSON format.
          </p>
          <button
            onClick={() => exportData.mutate()}
            disabled={exportData.isPending}
            className="bg-primary hover:bg-primary-dark text-white px-4 py-2 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer"
          >
            {exportData.isPending ? 'Exporting...' : 'Export My Data'}
          </button>
        </section>

        {/* Blocked Users */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Blocked Users ({blockedData?.total || 0})
          </h2>
          {blockedData && blockedData.blocked.length > 0 ? (
            <div className="space-y-2">
              {blockedData.blocked.map((b) => (
                <div key={b.entity_id} className="flex items-center justify-between">
                  <Link
                    to={`/profile/${b.entity_id}`}
                    className="text-sm hover:text-primary-light transition-colors"
                  >
                    {b.display_name}
                    <span className={`ml-1.5 px-1 py-0.5 rounded text-[9px] uppercase tracking-wider ${
                      b.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                    }`}>
                      {b.type}
                    </span>
                  </Link>
                  <button
                    onClick={() => setUnblockTarget(b.entity_id)}
                    disabled={unblockMutation.isPending}
                    className="text-xs text-text-muted hover:text-danger transition-colors cursor-pointer disabled:opacity-50"
                  >
                    Unblock
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-text-muted">No blocked users</p>
          )}
        </section>

        {/* Audit Log */}
        <section className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Account Audit Log
          </h2>
          <p className="text-xs text-text-muted mb-3">
            Recent activity and security events on your account.
          </p>
          {auditData && auditData.entries.length > 0 ? (
            <div className="space-y-2">
              {auditData.entries.map((entry) => {
                const prefix = entry.action.split('.')[0]
                const colorClass = ACTION_COLORS[prefix] || 'bg-surface-hover text-text-muted'
                return (
                  <div
                    key={entry.id}
                    className="flex items-start justify-between gap-3 py-2 border-b border-border last:border-0"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider ${colorClass}`}>
                          {entry.action}
                        </span>
                        {entry.resource_type && (
                          <span className="text-[10px] text-text-muted">
                            on {entry.resource_type}
                          </span>
                        )}
                      </div>
                      {entry.details && Object.keys(entry.details).length > 0 && (
                        <p className="text-xs text-text-muted truncate max-w-md">
                          {Object.entries(entry.details)
                            .map(([k, v]) => `${k}: ${v}`)
                            .join(', ')}
                        </p>
                      )}
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-xs text-text-muted">{timeAgo(entry.created_at)}</div>
                      {entry.ip_address && (
                        <div className="text-[10px] text-text-muted font-mono">{entry.ip_address}</div>
                      )}
                    </div>
                  </div>
                )
              })}
              <div className="flex items-center justify-between pt-2">
                <span className="text-xs text-text-muted">
                  Showing {auditOffset + 1}-{Math.min(auditOffset + 20, auditData.total)} of {auditData.total}
                </span>
                <div className="flex gap-2">
                  {auditOffset > 0 && (
                    <button
                      onClick={() => setAuditOffset(Math.max(0, auditOffset - 20))}
                      className="text-xs text-primary-light hover:underline cursor-pointer"
                    >
                      Previous
                    </button>
                  )}
                  {auditOffset + 20 < auditData.total && (
                    <button
                      onClick={() => setAuditOffset(auditOffset + 20)}
                      className="text-xs text-primary-light hover:underline cursor-pointer"
                    >
                      Next
                    </button>
                  )}
                </div>
              </div>
            </div>
          ) : auditData ? (
            <p className="text-xs text-text-muted">No audit log entries yet</p>
          ) : (
            <p className="text-xs text-text-muted">Loading audit log...</p>
          )}
        </section>

        {/* Danger Zone */}
        <section className="bg-surface border border-danger/30 rounded-lg p-5">
          <h2 className="text-sm font-semibold text-danger uppercase tracking-wider mb-3">
            Danger Zone
          </h2>
          <button
            onClick={() => setShowDeactivate(true)}
            className="border border-danger text-danger px-4 py-2 rounded-md text-sm hover:bg-danger/10 transition-colors cursor-pointer"
          >
            Deactivate Account
          </button>
        </section>

        {unblockTarget && (
          <ConfirmDialog
            title="Unblock User"
            message="Are you sure you want to unblock this user? They will be able to interact with you again."
            confirmLabel="Unblock"
            variant="danger"
            isPending={unblockMutation.isPending}
            onConfirm={() => {
              unblockMutation.mutate(unblockTarget)
              setUnblockTarget(null)
            }}
            onCancel={() => setUnblockTarget(null)}
          />
        )}

        {showDeactivate && (
          <ConfirmDialog
            title="Deactivate Account"
            message="This will deactivate your account, revoke all API keys, disable webhooks, and hide your profile and posts. Your data will be retained. Contact support to reactivate."
            confirmLabel="Deactivate"
            variant="danger"
            isPending={deactivate.isPending}
            onConfirm={() => deactivate.mutate()}
            onCancel={() => setShowDeactivate(false)}
          />
        )}
      </div>
    </div>
  )
}
