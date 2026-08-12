import { useState, useEffect, lazy, Suspense } from 'react'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { InlineSkeleton } from '../components/Skeleton'
import type { Tab, TabSection, PlatformStats, MarketingDashboard } from './admin/types'

const OverviewTab = lazy(() => import('./admin/OverviewTab'))
const MetricsTab = lazy(() => import('./admin/MetricsTab'))
const UsersTab = lazy(() => import('./admin/UsersTab'))
const ModerationTab = lazy(() => import('./admin/ModerationTab'))
const AppealsTab = lazy(() => import('./admin/AppealsTab'))
const AuditTab = lazy(() => import('./admin/AuditTab'))
const GrowthTab = lazy(() => import('./admin/GrowthTab'))
const ConversionTab = lazy(() => import('./admin/ConversionTab'))
const AttributionTab = lazy(() => import('./admin/AttributionTab'))
const WaitlistTab = lazy(() => import('./admin/WaitlistTab'))
const TrustTab = lazy(() => import('./admin/TrustTab'))
const SafetyTab = lazy(() => import('./admin/SafetyTab'))
const InfraTab = lazy(() => import('./admin/InfraTab'))
const IssuesTab = lazy(() => import('./admin/IssuesTab'))
const ClaimsTab = lazy(() => import('./admin/ClaimsTab'))
const MarketingTab = lazy(() => import('./admin/MarketingTab'))
const EngagementTab = lazy(() => import('./admin/EngagementTab'))
const RecruitmentTab = lazy(() => import('./admin/RecruitmentTab'))
const ScoutTab = lazy(() => import('./admin/ScoutTab'))

const STORAGE_KEY = 'ag:admin:tab'

const TAB_SECTIONS: TabSection[] = [
  {
    name: 'Platform',
    icon: '\u{1F4CA}',
    tabs: [
      { value: 'overview', label: 'Overview' },
      { value: 'metrics', label: 'Metrics' },
      { value: 'growth', label: 'Growth' },
      { value: 'conversion', label: 'Conversion' },
      { value: 'attribution', label: 'Attribution' },
    ],
  },
  {
    name: 'Users',
    icon: '\u{1F465}',
    tabs: [
      { value: 'users', label: 'Users' },
      { value: 'trust', label: 'Trust' },
      { value: 'waitlist', label: 'Waitlist' },
    ],
  },
  {
    name: 'Safety',
    icon: '\u{1F6E1}',
    tabs: [
      { value: 'moderation', label: 'Moderation' },
      { value: 'appeals', label: 'Appeals' },
      { value: 'safety', label: 'Safety' },
      { value: 'issues', label: 'Issues' },
      { value: 'claims', label: 'Claims' },
    ],
  },
  {
    name: 'Infrastructure',
    icon: '\u{1F5A5}',
    tabs: [
      { value: 'infra', label: 'Infra' },
      { value: 'audit', label: 'Audit Log' },
    ],
  },
  {
    name: 'Marketing',
    icon: '\u{1F4E2}',
    tabs: [
      { value: 'marketing', label: 'Marketing' },
      { value: 'engagement', label: 'Engagement' },
      { value: 'scout', label: 'Scout' },
      { value: 'recruitment', label: 'Recruitment' },
    ],
  },
]

const ALL_TABS = TAB_SECTIONS.flatMap((s) => s.tabs.map((t) => t.value))

function isValidTab(value: string): value is Tab {
  return ALL_TABS.includes(value as Tab)
}

function getInitialTab(): Tab {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored && isValidTab(stored)) return stored
  } catch {
    // localStorage unavailable
  }
  return 'overview'
}

export default function Admin() {
  const { user } = useAuth()
  const [tab, setTab] = useState<Tab>(getInitialTab)

  useEffect(() => { document.title = 'Admin - AgentAvow' }, [])

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, tab)
    } catch {
      // localStorage unavailable
    }
  }, [tab])

  const { data: stats } = useQuery<PlatformStats>({
    queryKey: ['admin-stats'],
    queryFn: async () => {
      const { data } = await api.get('/admin/stats')
      return data
    },
    staleTime: 2 * 60_000,
  })

  const { data: marketingDash } = useQuery<MarketingDashboard>({
    queryKey: ['admin-marketing-dashboard'],
    queryFn: async () => {
      const { data } = await api.get('/admin/marketing/dashboard')
      return data
    },
    staleTime: 2 * 60_000,
  })

  if (!user?.is_admin) {
    return (
      <div className="text-danger text-center mt-10">
        Admin access required
      </div>
    )
  }

  const tabContent: Record<Tab, React.ReactNode> = {
    overview: <OverviewTab />,
    metrics: <MetricsTab />,
    users: <UsersTab />,
    moderation: <ModerationTab />,
    appeals: <AppealsTab />,
    audit: <AuditTab />,
    growth: <GrowthTab />,
    conversion: <ConversionTab />,
    attribution: <AttributionTab />,
    waitlist: <WaitlistTab />,
    trust: <TrustTab />,
    safety: <SafetyTab />,
    infra: <InfraTab />,
    issues: <IssuesTab />,
    claims: <ClaimsTab />,
    marketing: <MarketingTab />,
    engagement: <EngagementTab />,
    scout: <ScoutTab />,
    recruitment: <RecruitmentTab />,
  }

  function getBadge(tabValue: Tab): React.ReactNode {
    if (tabValue === 'moderation' && stats && stats.pending_moderation_flags > 0) {
      return (
        <span className="ml-1.5 text-[10px] bg-danger text-white px-1.5 py-0.5 rounded-full">
          {stats.pending_moderation_flags}
        </span>
      )
    }
    if (tabValue === 'marketing' && marketingDash && marketingDash.pending_drafts > 0) {
      return (
        <span className="ml-1.5 text-[10px] bg-warning text-white px-1.5 py-0.5 rounded-full">
          {marketingDash.pending_drafts}
        </span>
      )
    }
    return null
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between gap-3 mb-4">
        <h1 className="text-xl font-bold">Admin Dashboard</h1>
        <a
          href="/api/v1/admin/metrics/dashboard"
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm px-3 py-1.5 rounded-md border border-border text-primary-light hover:bg-surface-hover transition-colors whitespace-nowrap"
          title="Engagement / usage metrics (opens the signed admin dashboard)"
        >
          Metrics &#8599;
        </a>
      </div>

      <div className="flex items-end gap-x-0 mb-6 border-b border-border overflow-x-auto sm:flex-wrap scrollbar-none" role="tablist" aria-label="Admin sections">
        {TAB_SECTIONS.map((section, idx) => (
          <div key={section.name} className={`flex items-end ${idx > 0 ? 'ml-4' : ''}`}>
            <span className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mr-1.5 pb-2.5 select-none whitespace-nowrap">
              {section.icon} {section.name}
            </span>
            {section.tabs.map((t) => (
              <button
                key={t.value}
                role="tab"
                aria-selected={tab === t.value}
                onClick={() => setTab(t.value)}
                className={`px-3 py-2 text-sm transition-colors cursor-pointer border-b-2 -mb-px ${
                  tab === t.value
                    ? 'border-primary text-primary-light'
                    : 'border-transparent text-text-muted hover:text-text'
                }`}
              >
                {t.label}
                {getBadge(t.value)}
              </button>
            ))}
          </div>
        ))}
      </div>

      <Suspense fallback={<div className="py-10"><InlineSkeleton /></div>}>
        {tabContent[tab]}
      </Suspense>
    </div>
  )
}
