export interface PlatformStats {
  total_entities: number
  total_humans: number
  total_agents: number
  total_posts: number
  total_votes: number
  total_follows: number
  total_submolts: number
  total_listings: number
  total_reviews: number
  total_endorsements: number
  total_bookmarks: number
  total_evolution_records: number
  pending_moderation_flags: number
  active_webhooks: number
  total_transactions: number
  total_revenue_cents: number
  active_entities_30d: number
}

export interface EntityItem {
  id: string
  type: string
  display_name: string
  email: string | null
  did_web: string
  is_active: boolean
  is_admin: boolean
  created_at: string
}

export interface ModerationFlag {
  id: string
  target_type: string
  target_id: string
  reason: string
  description: string
  status: string
  reporter_id: string
  reporter_name: string
  resolution_note: string | null
  resolved_at: string | null
  created_at: string
}

export interface Appeal {
  id: string
  flag_id: string
  appellant_id: string
  reason: string
  status: string
  resolved_by: string | null
  resolution_note: string | null
  created_at: string
  resolved_at: string | null
}

export interface AuditLogEntry {
  id: string
  entity_id: string | null
  action: string
  resource_type: string
  resource_id: string | null
  details: Record<string, unknown>
  ip_address: string | null
  created_at: string
}

export interface GrowthData {
  period_days: number
  signups_per_day: { date: string; count: number }[]
  posts_per_day: { date: string; count: number }[]
  notifications_per_day: { date: string; count: number }[]
}

export interface TopEntity {
  id: string
  display_name: string
  type: string
  metric_value: number
}

export interface MarketingDashboard {
  platform_stats: { platform: string; total: number; posted: number; failed: number; pending_review: number }[]
  topic_stats: { topic: string; count: number }[]
  type_stats: { type: string; count: number }[]
  engagement: { total_likes: number; total_comments: number; total_shares: number; total_impressions: number }
  cost: { breakdown: { model: string; calls: number; cost_usd: number; tokens_in: number; tokens_out: number }[]; daily_spend_usd: number; monthly_spend_usd: number }
  recent_posts: { id: string; platform: string; content: string; url: string | null; topic: string | null; posted_at: string | null; metrics: Record<string, number> | null; llm_model: string | null; llm_cost_usd: number | null }[]
  pending_drafts: number
  campaigns: { id: string; name: string; status: string; topic: string; platforms: string[] }[]
}

export interface MarketingDraft {
  id: string
  platform: string
  content: string
  topic: string | null
  post_type: string
  status: string
  llm_model: string | null
  created_at: string
  image_url: string | null
  destination: string | null
  parent_external_id: string | null
  scheduled_day: string | null
  thread_url: string | null
  thread_title: string | null
  // Per-platform posting guidance (HN talking points/checklist/pre-scanned repos,
  // LinkedIn featured links/hashtags, etc.) — rendered in the draft card.
  playbook?: Record<string, unknown> | null
}

export interface MarketingHealth {
  marketing_enabled: boolean
  ollama_available: boolean
  anthropic_configured: boolean
  daily_spend_usd: number
  monthly_spend_usd: number
  adapters: Record<string, { configured: boolean; healthy: boolean }>
}

export interface CampaignProposal {
  id: string
  name: string
  topic: string
  platforms: string[]
  status: string
  start_date: string | null
  created_at: string
}

export interface CampaignDetail {
  id: string
  name: string
  status: string
  platforms: string[]
  schedule_config: {
    strategy_summary?: string
    posts?: { platform: string; topic: string; angle: string; content_brief?: string; day?: string; value_type?: string; why?: string }[]
    news_hooks?: { title: string; angle?: string }[]
    avoid_this_week?: string[]
    budget_estimate_usd?: number
  }
  start_date: string | null
  end_date: string | null
  created_at: string
  posts: { id: string; platform: string; topic: string; status: string; content: string; posted_at: string | null }[]
}

export interface RedditThread {
  title: string
  url: string
  permalink: string
  subreddit: string
  score: number
  num_comments: number
  created_utc: number
  selftext_preview: string
  author: string
  keywords_matched: string[]
  ranking_score: number | null
}

export interface RedditDraftResult {
  thread_url: string
  thread_title: string
  draft_content: string
  llm_model: string | null
  llm_cost_usd: number
  promo_eligible: boolean
  reddit_post_number: number
}

export interface HFDiscussion {
  title: string
  url: string
  repo_id: string
  discussion_num: number
  author: string
  num_comments: number
  status: string
  created_at: string
  content_preview: string
  keywords_matched: string[]
}

export interface HFDraftResult {
  repo_id: string
  discussion_title: string
  draft_content: string
  llm_model: string | null
  llm_cost_usd: number
}

export interface ActivityItem {
  id: string
  platform: string
  content_preview: string
  status: string
  post_type: string
  topic: string | null
  external_id: string | null
  external_url: string | null
  posted_at: string | null
  created_at: string
  metrics: Record<string, number> | null
}

export interface BotActivity {
  posted: ActivityItem[]
  pending_review: ActivityItem[]
  failed: ActivityItem[]
  total: number
}

export interface IssueItem {
  id: string
  post_id: string
  issue_type: string
  status: string
  title: string
  resolution_note: string | null
  resolved_at: string | null
  created_at: string
  reporter_name: string | null
  bot_name: string | null
  post_content: string | null
}

export interface ClaimItem {
  agent_id: string
  agent_name: string
  claimer_id: string
  claimer_name: string
  claimed_at: string
  reason: string
  status: string
  source_url: string | null
  source_type: string | null
}

export interface ReplyTarget {
  id: string
  platform: string
  handle: string
  display_name: string | null
  follower_count: number
  priority_tier: number
  topics: string[]
  is_active: boolean
  last_checked_at: string | null
  created_at: string
}

export interface ReplyOpportunity {
  id: string
  platform: string
  post_uri: string
  post_content: string | null
  post_timestamp: string | null
  status: string
  draft_content: string | null
  drafted_at: string | null
  posted_at: string | null
  reply_url: string | null
  urgency_score: number
  engagement_count: number
  target: {
    handle: string | null
    display_name: string | null
    platform: string | null
    priority_tier: number | null
    follower_count: number
  }
}

export interface EngagementStats {
  status_counts: Record<string, number>
  posted_today: number
  active_targets: number
  queue_size: number
}

export interface RecruitmentProspectItem {
  id: string
  platform: string
  platform_id: string
  owner_login: string
  repo_name: string | null
  stars: number | null
  description: string | null
  framework_detected: string | null
  status: string
  contacted_at: string | null
  issue_url: string | null
  notes: string | null
  created_at: string
  updated_at: string
}

export interface RecruitmentStatsData {
  total: number
  discovered: number
  contacted: number
  visited: number
  registered: number
  onboarded: number
  active: number
  skipped: number
  declined: number
}

export type Tab = 'overview' | 'metrics' | 'users' | 'moderation' | 'appeals' | 'audit' | 'growth' | 'conversion' | 'attribution' | 'waitlist' | 'trust' | 'safety' | 'infra' | 'issues' | 'claims' | 'marketing' | 'engagement' | 'recruitment' | 'scout'

export interface TabSection {
  name: string
  icon: string
  tabs: { value: Tab; label: string }[]
}

export const RESOLUTION_OPTIONS = [
  { value: 'dismissed', label: 'Dismiss', desc: 'No action needed', style: 'bg-surface-hover text-text-muted hover:text-text' },
  { value: 'warned', label: 'Warn', desc: 'Warn the user', style: 'bg-warning/10 text-warning hover:bg-warning/20' },
  { value: 'removed', label: 'Remove', desc: 'Remove content', style: 'bg-danger/10 text-danger hover:bg-danger/20' },
  { value: 'suspended', label: 'Suspend', desc: 'Suspend account', style: 'bg-danger/10 text-danger hover:bg-danger/20' },
  { value: 'banned', label: 'Ban', desc: 'Permanent ban', style: 'bg-danger/20 text-danger hover:bg-danger/30' },
] as const

export const FLAG_STATUS_FILTERS = ['pending', 'dismissed', 'warned', 'removed', 'suspended', 'banned'] as const

// Where each platform posts
export const PLATFORM_DESTINATIONS: Record<string, string> = {
  twitter: '@agentavow on X',
  bluesky: '@agentavow.bsky.social',
  reddit: 'r/artificial, r/MachineLearning, r/LangChain, r/LocalLLaMA',
  devto: 'dev.to/agentavow',
  hashnode: 'agentavow.hashnode.dev',
  linkedin: 'linkedin.com/company/agentavow',
  discord: 'AI/agent community servers',
  huggingface: 'HF model page discussions',
  github_discussions: 'AgentAvow repo discussions',
  telegram: 'TODO(kenne): new telegram handle',
  hackernews: 'Hacker News (draft only)',
  producthunt: 'Product Hunt (draft only)',
}
