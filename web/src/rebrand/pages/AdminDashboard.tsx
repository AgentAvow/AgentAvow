/**
 * AgentAvow admin dashboard — Kenne's day-to-day ops tool, rebrand-styled.
 *
 * Tabs: Metrics (product/adoption + traffic funnel, under ONE page-level time window
 * of 7 / 30 / 90 complete UTC days), Marketing (health, weekly campaign planner,
 * interactive draft queue, reply-guy, cost, recent posts), Posts (review and track
 * hand-posted drafts) and Radar. Consumes the SAME existing admin endpoints as the
 * legacy admin, which is left fully intact (footer Community → /feed → /admin, and a
 * link here).
 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'

import api from '../../lib/api'
import { DECISIONS, TRUST_TIERS } from '../../components/trust/gradeSystem'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'
import StartHerePanel from './AdminStartHere'
import CampaignPanel from './AdminCampaignPanel'
import PostStudioTab from './AdminPostStudio'
import { AdminAccessPanel, useAdminAccess, ViewOnlyNotice } from './adminAccess'
import { BarList, Section, Stat, TrendChart, WindowBar } from './adminMetricsKit'
import type { TrendLine } from './adminMetricsKit'
import {
  completeDays, dayLabel, DashWindowContext, fmt, fmtOrDash, metricsWindow, pctOf, rangeLabel,
  usd, useDashWindow, useMetricsScope, useWindowLabel, utcDay,
} from './adminMetricsUtil'
import type { PageWin } from './adminMetricsUtil'

// ── shared types (loose — endpoints already validated server-side) ──────────
interface Metrics {
  include_today?: boolean
  headline?: Record<string, number>
  series?: Record<string, number[]>
  days?: string[]
  scans?: { grade_distribution?: Record<string, number>; decision_distribution?: Record<string, number>; unique_repos_total?: number; scans_total_alltime?: number }
  watches?: { active?: number; total?: number }
  claims?: { verified_total?: number; public?: number; private?: number }
  attestations?: { issued_total?: number; verification_badges_active?: number }
  badges?: { readme_renders_window?: number; leaderboard?: { repo: string; renders: number }[] }
  catalog?: { by_surface?: Record<string, number>; by_category?: Record<string, number>; size_total?: number }
  x402?: { listings?: number; scored?: number; testnet_hidden?: number; answers?: Record<string, number> }
  scan_kinds?: { checks?: Record<string, number>; renders?: Record<string, number>; other?: Record<string, number> }
  watch_alerts?: Record<string, { public?: number; private?: number }>
  funnel?: { scanned?: number; watched?: number; claimed?: number; installs?: number }
  installs_by_client?: Record<string, number>
  mcp?: { calls_window?: number; callers_window?: number; ok_window?: number; errors_window?: number; safe_window?: number; needs_review_window?: number; answers_window?: Record<string, number>; checks_window?: number; by_tool?: Record<string, number>; by_surface?: Record<string, { calls?: number; callers?: number; errors?: number; safe?: number; needs_review?: number; checks?: number; answer_safe?: number; answer_review?: number; answer_do_not_connect?: number }> }
  hook?: { scans_window?: number; machines_window?: number }
  private_repos?: { app_scans?: number; published_to_search?: number; app_installs_active?: number; onetime_scans_window?: number }
  alert_webhooks?: { active?: number }
  traffic_quality?: Record<string, { total?: number; human?: number; agent?: number; agentavow?: number; automated?: number }>
  baseline?: { rules_changed_on?: string; rules?: string[] }
}
interface Draft { id: string; platform: string; content: string; topic: string | null; status: string; created_at: string; post_type?: string; llm_model?: string | null }
interface Health { marketing_enabled?: boolean; anthropic_configured?: boolean; ollama_available?: boolean; daily_spend_usd?: number; monthly_spend_usd?: number; adapters?: Record<string, { configured: boolean; healthy: boolean }> }
interface MktDash {
  engagement?: { total_likes: number; total_comments: number; total_shares: number; total_impressions: number }
  cost?: { daily_spend_usd: number; monthly_spend_usd: number; breakdown: { model: string; calls: number; cost_usd: number }[] }
  recent_posts?: { id: string; platform: string; content: string; url: string | null; posted_at: string | null; metrics: Record<string, number> | null; llm_model: string | null; llm_cost_usd: number | null }[]
  pending_drafts?: number
  platform_stats?: { platform: string; total: number; posted: number; failed: number; pending_review: number }[]
}
interface Campaign { id: string; name: string; topic: string; platforms: string[]; status: string; start_date?: string }
interface ReplyStats { status_counts?: Record<string, number>; posted_today?: number; active_targets?: number; queue_size?: number }
interface Eval { engagement_per_post_7d?: number; engagement_per_post_30d?: number; trend_pct?: number | null; slop_pass_rate_7d?: number | null; reply_engagement_per_post_7d?: number; posts_7d?: number; by_platform?: { platform: string; eng_per_post: number; posts: number; total: number }[]; alerts?: { level: string; message: string; action?: string }[] }
interface TargetPerf { targets?: { handle: string; platform: string; replies: number; avg_engagement: number; total_engagement: number }[] }
interface ReplyRow { id: string; platform: string; post_uri?: string; reply_url?: string | null; draft_content?: string; drafted_at?: string | null; posted_at?: string | null; engagement_count?: number; urgency_score?: number; target?: { handle?: string | null; follower_count?: number } }
const REPLY_TTL_H = 48

// ── helpers ─────────────────────────────────────────────────────────────────
const ago = (iso?: string | null) => {
  if (!iso) return '—'
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

/** The day each newer counter started, for the plain "counted from" notes. */
const COUNTED_FROM = {
  answers: 'Nov 11', ourClients: 'Nov 11', kinds: 'Nov 11', alerts: 'Nov 11', installTimeHook: 'Nov 11',
  installSplit: 'Nov 12', pageActions: '2026-11-12', growthRows: 'Nov 11',
}

const INSTALL_CLIENT_LABEL: Record<string, string> = { cursor: 'Cursor', vscode: 'VS Code', goose: 'Goose' }
/** "Cursor 3 · VS Code 1 · Goose 0": one-click installs by app (split from Nov 12; older clicks are in the total only). */
const installSplit = (by?: Record<string, number>) =>
  by ? Object.entries(INSTALL_CLIENT_LABEL).map(([k, label]) => `${label} ${fmt(by[k])}`).join(' · ') : undefined

/** /admin/metrics for the page window (complete days), plus today's partial day when
 *  the page asks to show it. */
function useMetricsData() {
  const w = useDashWindow()
  const m = metricsWindow(w.days)
  const main = useQuery<Metrics>({
    queryKey: ['admin-dash-metrics', m.param, 'complete'],
    queryFn: async () => (await api.get('/admin/metrics', { params: { window: m.param, include_today: false } })).data,
  })
  const today = useQuery<Metrics>({
    queryKey: ['admin-dash-metrics', 'today'],
    queryFn: async () => (await api.get('/admin/metrics', { params: { window: 'today' } })).data,
    enabled: w.includeToday,
  })
  return { data: main.data, today: w.includeToday ? today.data : undefined }
}


// ── Behavioral sandbox panel (GET /admin/metrics/behavioral) ────────────────
interface Behavioral {
  days?: string[]
  runs?: number; exercised?: number; with_findings?: number; canary_leaks?: number
  slot_rejected?: number; killed?: number; cache_hits?: number; cache_misses?: number
  cache_hit_rate?: number | null; avg_duration_s?: number | null; max_duration_s?: number | null
  start_reasons?: Record<string, number>; findings_by_rule?: Record<string, number>
  series?: { runs?: number[]; exercised?: number[]; slot_rejected?: number[] }
  concurrency_limit?: number; scaling_hint?: string
  last_eval?: EvalReport | null
  corpus?: CorpusEntry[]
}
interface EvalFp { surface: string; name: string; rules: string[] }
interface EvalReport {
  ran_at?: string; reason?: string; duration_s?: number; running?: boolean
  fixtures?: { total?: number; passed?: number; failed?: string[] }
  known_good?: { total?: number; ran?: number; exercised?: number; false_positives?: EvalFp[]; expected_findings?: number; not_started?: { name: string; start_reason: string }[] }
  diff?: {
    first_run?: boolean; previous_ran_at?: string | null; regression?: boolean; exercised_delta?: number
    fixture_failures?: string[]; fixture_regressions?: string[]; fixture_fixed?: string[]
    new_false_positives?: EvalFp[]; cleared_false_positives?: string[]
    newly_not_exercised?: string[]; newly_exercised?: string[]
  }
  alert?: { notified?: number; webhooks?: number }
}
interface CorpusEntry { key: string; surface: string; name: string; expect_rules?: string[]; note?: string; source: 'file' | 'admin'; removed?: boolean }
const START_LABEL: Record<string, string> = {
  started: 'Started', needs_credentials: 'Needs credentials', needs_arguments: 'Needs arguments',
  missing_binary: 'Missing program', install_failed: 'Install failed', resource_limit: 'Hit a resource limit',
  no_entrypoint: 'Nothing to start', timeout: 'Timed out', crashed: 'Crashed', unknown: 'Unknown',
  not_applicable: 'Nothing to run (install-only package)',
}
const RULE_LABEL: Record<string, string> = {
  behavioral_undeclared_egress: 'Network call it didn\'t declare', annotation_readonly_violated: 'Wrote data though marked read-only',
  annotation_open_world_violated: 'Reached outside though marked closed', credential_canary_exfiltrated: 'Sent a fake credential out (canary leak)',
  canary_echoed_in_result: 'Repeated a fake credential in its reply', tool_call_crashed_server: 'A tool call crashed the server',
  cloud_metadata_probe: 'Probed cloud metadata',
}
const evalDate = (iso?: string | null) => (iso ? new Date(iso).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '—')

// ── Scheduled eval tile (weekly corpus run; POST /admin/metrics/behavioral/eval) ──
function EvalTile({ report, corpus, queryKey }: { report?: EvalReport | null; corpus: CorpusEntry[]; queryKey: unknown[] }) {
  const { isAdmin } = useAdminAccess() // a viewer reads the report; no run / corpus edits
  const qc = useQueryClient()
  const [msg, setMsg] = useState<string | null>(null)
  const [showCorpus, setShowCorpus] = useState(false)
  const [addSurface, setAddSurface] = useState<'npm' | 'pypi' | 'skill'>('npm')
  const [addName, setAddName] = useState('')
  const [addRules, setAddRules] = useState('')
  const invalidate = () => qc.invalidateQueries({ queryKey })
  const run = useMutation({
    mutationFn: async () => (await api.post('/admin/metrics/behavioral/eval')).data,
    onSuccess: () => { setMsg('queued — the report lands here when the run finishes'); invalidate() },
    onError: (e: unknown) => {
      const status = (e as { response?: { status?: number } })?.response?.status
      setMsg(status === 409 ? 'a run is already in progress' : 'could not start the run')
    },
  })
  const edit = useMutation({
    mutationFn: async (body: { action: 'add' | 'remove'; surface: string; name: string; expect_rules?: string[] }) =>
      (await api.post('/admin/metrics/behavioral/corpus', body)).data,
    onSuccess: () => { setAddName(''); setAddRules(''); invalidate() },
  })
  const r = report || null
  const fx = r?.fixtures || {}
  const kg = r?.known_good || {}
  const d = r?.diff || {}
  const fpCount = (kg.false_positives || []).length
  const regressed = !!d.regression
  const finished = !!r?.ran_at
  const diffLines: { tone: 'bad' | 'good' | 'muted'; text: string }[] = []
  for (const l of d.fixture_regressions || []) diffLines.push({ tone: 'bad', text: `fixture now failing: ${l}` })
  for (const f of d.new_false_positives || []) diffLines.push({ tone: 'bad', text: `new false positive: ${f.surface}:${f.name} (${f.rules.join(', ')})` })
  for (const n of d.newly_not_exercised || []) diffLines.push({ tone: 'bad', text: `no longer exercised: ${n}` })
  for (const l of d.fixture_fixed || []) diffLines.push({ tone: 'good', text: `fixture fixed: ${l}` })
  for (const n of d.cleared_false_positives || []) diffLines.push({ tone: 'good', text: `false positive cleared: ${n}` })
  for (const n of d.newly_exercised || []) diffLines.push({ tone: 'good', text: `newly exercised: ${n}` })
  const toneCls = { bad: 'text-danger', good: 'text-success', muted: 'text-text-muted/70' }
  const active = corpus.filter((c) => !c.removed)
  const removed = corpus.filter((c) => c.removed)
  return (
    <div className="glass rounded-2xl p-5 mt-3">
      <div className="flex items-baseline justify-between gap-3 flex-wrap">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted">
          Eval — known-good corpus run <span className="normal-case tracking-normal">· runs weekly on a schedule, or by hand</span>
          {finished
            ? <span className="normal-case tracking-normal"> · last finished run: {evalDate(r!.ran_at)} ({ago(r!.ran_at)} ago, {r!.reason === 'admin' ? 'started by hand' : r!.reason || 'scheduled'}{r!.duration_s != null ? `, took ${Math.round(r!.duration_s / 60)} min` : ''})</span>
            : <span className="normal-case tracking-normal"> · never finished a run</span>}
        </div>
        <div className="flex items-center gap-2">
          {msg && <span className="text-[11.5px] text-text-muted">{msg}</span>}
          {isAdmin ? (
            <button
              onClick={() => { setMsg(null); run.mutate() }}
              disabled={run.isPending || !!r?.running}
              className="px-2.5 py-1 rounded-lg text-[12px] font-mono bg-primary/15 text-primary-light hover:bg-primary/25 disabled:opacity-50 transition-colors"
            >
              {r?.running ? 'new run in progress…' : 'Run eval now'}
            </button>
          ) : r?.running ? <span className="text-[12px] font-mono text-text-muted">new run in progress…</span> : null}
        </div>
      </div>
      {r?.running && finished && <p className="mt-2 text-[12px] text-text-muted">A new run is in progress. Everything below is from the run that finished {evalDate(r.ran_at)}; it updates when the new run ends.</p>}
      {finished ? (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3">
            <div>
              <div className={`text-[20px] font-extrabold tabular-nums ${(fx.failed || []).length ? 'text-danger' : 'gradient-text'}`}>{fmt(fx.passed)}/{fmt(fx.total)}</div>
              <div className="text-[11px] font-mono uppercase tracking-wide text-text-muted">test fixtures passed</div>
            </div>
            <div>
              <div className="text-[20px] font-extrabold tabular-nums gradient-text">{fmt(kg.exercised)}/{fmt(kg.total)}</div>
              <div className="text-[11px] font-mono uppercase tracking-wide text-text-muted">known-good tools exercised{d.exercised_delta ? ` (${d.exercised_delta > 0 ? '+' : ''}${d.exercised_delta})` : ''}</div>
            </div>
            <div>
              <div className={`text-[20px] font-extrabold tabular-nums ${fpCount > 0 ? 'text-danger' : 'gradient-text'}`}>{fmt(fpCount)}</div>
              <div className="text-[11px] font-mono uppercase tracking-wide text-text-muted">false alarms</div>
            </div>
            <div>
              <div className={`text-[20px] font-extrabold tabular-nums ${regressed ? 'text-danger' : 'text-success'}`}>{d.first_run ? 'first run' : regressed ? 'got worse' : 'no worse'}</div>
              <div className="text-[11px] font-mono uppercase tracking-wide text-text-muted">vs the run before{d.previous_ran_at ? ` (${evalDate(d.previous_ran_at)})` : ''}</div>
            </div>
          </div>
          {(fx.failed || []).length > 0 && <p className="mt-2 text-[12px] text-danger">Failing fixtures: {(fx.failed || []).join(', ')}</p>}
          {fpCount > 0 && (
            <ul className="mt-2 text-[12px] text-danger space-y-0.5">
              {(kg.false_positives || []).map((f) => <li key={`${f.surface}:${f.name}`}>{f.surface}:{f.name} — {f.rules.join(', ')}</li>)}
            </ul>
          )}
          <div className="mt-3">
            <div className="text-[11px] font-mono uppercase tracking-wide text-text-muted mb-1">What changed since the run before</div>
            {diffLines.length ? (
              <ul className="text-[12px] space-y-0.5">{diffLines.map((l, i) => <li key={i} className={toneCls[l.tone]}>{l.text}</li>)}</ul>
            ) : (
              <p className="text-[12px] text-text-muted/70">{d.first_run ? 'No earlier run to compare against.' : 'Nothing changed.'}</p>
            )}
          </div>
          {(kg.not_started || []).length > 0 && (
            <p className="mt-2 text-[11px] text-text-muted/70">Not started: {(kg.not_started || []).map((n) => `${n.name} (${START_LABEL[n.start_reason] || n.start_reason})`).join(' · ')}</p>
          )}
        </>
      ) : (
        <p className="mt-2 text-[12.5px] text-text-muted/70">No eval report yet. The job runs weekly (first run an hour after startup) when the sandbox tier is enabled; or start one now.</p>
      )}
      <div className="mt-3 border-t border-border/40 pt-3">
        <button onClick={() => setShowCorpus(!showCorpus)} className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted hover:text-text transition-colors">
          Known-good corpus · {active.length} entries {showCorpus ? '▾' : '▸'}
        </button>
        {showCorpus && (
          <div className="mt-2">
            <ul className="text-[12px] space-y-1">
              {active.map((c) => (
                <li key={c.key} className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono">{c.surface}:{c.name}</span>
                  {c.source === 'admin' && <span className="text-[10.5px] px-1.5 rounded bg-primary/15 text-primary-light">admin</span>}
                  {(c.expect_rules || []).length > 0 && <span className="text-[11px] text-text-muted/70">expects {c.expect_rules!.join(', ')}</span>}
                  {isAdmin && <button onClick={() => edit.mutate({ action: 'remove', surface: c.surface, name: c.name })} className="text-[11px] text-text-muted hover:text-danger">remove</button>}
                </li>
              ))}
              {removed.map((c) => (
                <li key={c.key} className="flex items-center gap-2 flex-wrap opacity-60">
                  <span className="font-mono line-through">{c.surface}:{c.name}</span>
                  {isAdmin && <button onClick={() => edit.mutate({ action: 'add', surface: c.surface, name: c.name, expect_rules: c.expect_rules || [] })} className="text-[11px] text-text-muted hover:text-success">restore</button>}
                </li>
              ))}
            </ul>
            {isAdmin && <form
              className="mt-2 flex items-center gap-2 flex-wrap text-[12px]"
              onSubmit={(e) => { e.preventDefault(); if (addName.trim()) edit.mutate({ action: 'add', surface: addSurface, name: addName.trim(), expect_rules: addRules.split(',').map((x) => x.trim()).filter(Boolean) }) }}
            >
              <select value={addSurface} onChange={(e) => setAddSurface(e.target.value as 'npm' | 'pypi' | 'skill')} className="bg-surface rounded-lg px-2 py-1 font-mono">
                <option value="npm">npm</option><option value="pypi">pypi</option><option value="skill">skill</option>
              </select>
              <input value={addName} onChange={(e) => setAddName(e.target.value)} placeholder={addSurface === 'skill' ? 'owner/repo' : 'package name'} className="bg-surface rounded-lg px-2 py-1 font-mono min-w-[14rem]" />
              <input value={addRules} onChange={(e) => setAddRules(e.target.value)} placeholder="expect_rules (comma-separated, optional)" className="bg-surface rounded-lg px-2 py-1 font-mono min-w-[16rem]" />
              <button type="submit" disabled={edit.isPending || !addName.trim()} className="px-2.5 py-1 rounded-lg font-mono bg-primary/15 text-primary-light hover:bg-primary/25 disabled:opacity-50">add</button>
              {edit.isError && <span className="text-danger">could not save</span>}
            </form>}
          </div>
        )}
      </div>
    </div>
  )
}

function BehavioralPanel() {
  const w = useDashWindow()
  const scope = useMetricsScope()
  const queryKey = ['admin-dash-behavioral', scope.param, 'complete']
  const { data } = useQuery<Behavioral>({
    queryKey,
    queryFn: async () => (await api.get('/admin/metrics/behavioral', { params: { window: scope.param, include_today: false } })).data,
  })
  const todayQ = useQuery<Behavioral>({
    queryKey: ['admin-dash-behavioral', 'today'],
    queryFn: async () => (await api.get('/admin/metrics/behavioral', { params: { window: 'today' } })).data,
    enabled: w.includeToday,
  })
  const b = data || {}
  const s = b.series || {}
  const runs = b.runs ?? 0
  const attempts = runs + (b.slot_rejected ?? 0)
  const hint = b.scaling_hint || 'ok'
  const hintCls = hint === 'ok' ? 'text-success border-success/40' : 'text-warning border-warning/40'
  const ts = w.includeToday ? todayQ.data?.series : undefined
  const perDay = [
    ...(b.days || []).map((d, i) => ({ d, label: d.slice(5), today: false, r: s.runs?.[i] ?? 0, e: s.exercised?.[i] ?? 0, rj: s.slot_rejected?.[i] ?? 0 })),
    ...(ts ? [{ d: w.today, label: 'today*', today: true, r: ts.runs?.[0] ?? 0, e: ts.exercised?.[0] ?? 0, rj: ts.slot_rejected?.[0] ?? 0 }] : []),
  ]
  const smax = Math.max(...perDay.map((p) => p.r + p.rj), 1)
  return (
    <Section
      title="Behavioral sandbox"
      scope={scope.label}
      note="Sandbox runs from the public scan path: each server is started in an isolated sandbox (gVisor), every tool is called with made-up arguments, and fake 'canary' credentials are planted to see if it sends them anywhere. Day counters are kept 45 days; nothing is backfilled."
      right={<span className={`font-mono text-[11.5px] px-2.5 py-1 rounded-lg border ${hintCls}`} title="'add capacity' when more than 5% of attempts were turned away; 'watch memory' when more than 10% of runs were killed">capacity: {hint} · {fmt(b.concurrency_limit)} runs at once</span>}
    >
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        <Stat label="Sandbox runs" value={fmt(runs)} series={s.runs} />
        <Stat label="Servers actually exercised" value={fmt(b.exercised)} sub={runs ? `${pctOf(b.exercised ?? 0, runs)} of runs: it started and its tools were called` : undefined} series={s.exercised} />
        <Stat label="Runs with findings" value={fmt(b.with_findings)} />
        <Stat label="Canary leaks" value={fmt(b.canary_leaks)} sub="a fake credential was sent out over the network" />
        <Stat label="Turned away (all slots busy)" value={fmt(b.slot_rejected)} sub={attempts ? `${pctOf(b.slot_rejected ?? 0, attempts)} of attempts` : undefined} series={s.slot_rejected} />
        <Stat label="Killed (out of time or memory)" value={fmt(b.killed)} sub={runs ? `${pctOf(b.killed ?? 0, runs)} of runs` : undefined} />
        <Stat label="Re-used a recent result" value={b.cache_hit_rate != null ? `${Math.round(b.cache_hit_rate * 100)}%` : '—'} sub={`${fmt(b.cache_hits)} re-used · ${fmt(b.cache_misses)} ran fresh`} />
        <Stat label="Run time avg / max" value={b.avg_duration_s != null ? `${b.avg_duration_s}s` : '—'} sub={b.max_duration_s != null ? `max ${b.max_duration_s}s` : undefined} />
      </div>
      <p className="mt-3 text-[12px] text-text-muted max-w-[80ch]"><span className="font-semibold">Canary leaks vs “repeated a fake credential in its reply”:</span> a leak means the server sent one of the planted fake credentials out over the network, the serious case. Repeating it in its own reply (in Findings by rule) is milder: it is flagged, but nothing left the sandbox. That is why leaks can be 0 while repeats are not.</p>
      <div className="grid md:grid-cols-2 gap-3 mt-3">
        <BarList title="Why a run did or didn't start" rows={b.start_reasons || {}} labels={START_LABEL} empty="No sandbox runs recorded in this window." gradient="linear-gradient(90deg,#2dd4bf,#818cf8)" />
        <BarList title="Findings by rule" rows={b.findings_by_rule || {}} labels={RULE_LABEL} empty="No sandbox findings in this window." gradient="linear-gradient(90deg,#f59e0b,#e879f9)" />
      </div>
      {perDay.length > 1 && (
        <div className="glass rounded-2xl p-5 mt-3">
          <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-1">Per UTC day — runs · of which exercised · turned away</div>
          <div className="mb-3 flex flex-wrap gap-x-4 text-[11.5px] text-text-muted">
            <span className="inline-flex items-center gap-1.5"><span className="inline-block w-3 h-2 rounded-sm" style={{ background: '#2dd4bf' }} />runs</span>
            <span className="inline-flex items-center gap-1.5"><span className="inline-block w-3 h-2 rounded-sm" style={{ background: '#6366f1' }} />of which exercised (inside the runs bar)</span>
            <span className="inline-flex items-center gap-1.5"><span className="inline-block w-3 h-2 rounded-sm bg-warning/70" />turned away</span>
          </div>
          <div className="space-y-1">
            {perDay.map((p) => (
              <div key={p.d} className={`flex items-center gap-3 text-[12px]${p.today ? ' opacity-60' : ''}`}>
                <span className="font-mono text-text-muted/70 w-[5.5rem] shrink-0">{p.label}</span>
                <div className={`flex-1 h-2.5 rounded-full bg-surface overflow-hidden flex${p.today ? ' border border-dashed border-text-muted/50' : ''}`}>
                  <div className="h-full relative" style={{ width: `${(p.r / smax) * 100}%`, background: '#2dd4bf' }}>
                    <div className="absolute inset-y-0 left-0" style={{ width: p.r ? `${(Math.min(p.e, p.r) / p.r) * 100}%` : 0, background: '#6366f1' }} />
                  </div>
                  <div className="h-full bg-warning/70" style={{ width: `${(p.rj / smax) * 100}%` }} />
                </div>
                <span className="tabular-nums text-text-muted/70 w-28 text-right shrink-0">{fmt(p.r)} · {fmt(p.e)} · {fmt(p.rj)}</span>
              </div>
            ))}
          </div>
          <p className="mt-2 text-[11px] text-text-muted/60">Bars are scaled to the busiest day.{ts ? ' today* = today so far (partial).' : ''}</p>
        </div>
      )}
      <EvalTile report={b.last_eval} corpus={b.corpus || []} queryKey={queryKey} />
    </Section>
  )
}

// ── CLAUDE TRAFFIC (durable series from the daily snapshot cron) ─────────────
interface TrafficRow {
  day: string; cc_machines?: number | null; cc_new_machines_30d?: number | null; cc_sessions?: number | null
  claudeai_reqs?: number | null; hook_machines_nginx?: number | null; hook_reqs?: number | null
  calls_claude_code?: number | null; callers_claude_code?: number | null; calls_claude?: number | null
  callers_claude?: number | null; calls_chatgpt?: number | null; hook_top_version?: string
  cc_machines_excl_owner?: number | null; hook_machines_excl_owner?: number | null; log_complete?: number | null
  checked_machines?: number | null; checked_machines_excl_owner?: number | null
  preinstall_machines?: number | null; preinstall_reqs?: number | null
  gate_machines?: number | null; tool_gate_machines?: number | null; tool_gate_reqs?: number | null
  a2a_card_fetches?: number | null; a2a_card_fetchers?: number | null
  [col: string]: number | string | null | undefined
}
interface Traffic { days?: string[]; rows?: TrafficRow[]; latest?: TrafficRow | null; covered_days?: number; notes?: string[] }

/** The nightly traffic snapshot for the page window: one row per complete UTC day that
 *  has a snapshot (today never does; the cron writes each day after it ends). */
function useTraffic() {
  const w = useDashWindow()
  const q = useQuery<Traffic>({
    queryKey: ['admin-dash-claude-traffic', w.days + 1],
    queryFn: async () => { try { return (await api.get('/admin/metrics/traffic', { params: { days: w.days + 1 } })).data } catch { return {} } },
  })
  const inWindow = new Set(w.complete)
  const rows = (q.data?.rows || []).filter((r) => inWindow.has(r.day))
  const byDay = Object.fromEntries(rows.map((r) => [r.day, r]))
  /** A column aligned to the window's days; null where there is no snapshot or no value. */
  const col = (name: string) => w.complete.map((d) => { const v = byDay[d]?.[name]; return typeof v === 'number' ? v : null })
  return { rows, byDay, col, latest: rows[rows.length - 1] }
}

// ── Scan requests by kind (GET /admin/metrics → scan_kinds) ─────────────────
const KIND_LABEL: Record<string, string> = {
  repo: 'GitHub repo', package: 'Package (npm, PyPI, …)', mcp: 'MCP server', skill: 'Skill', a2a: 'A2A agent card',
  erc8004: 'ERC-8004 agent', wallet: 'Wallet', submit: 'Submit a tool', x402: 'x402 (catalog lookups)',
  badge: 'Badge image', card: 'Card image', og: 'Link preview image', verdict_json: 'verdict.json',
  preflight: 'Preflight runs', drift_feed: 'Drift feed reads', registry_snippet: 'Registry snippet', catalog: 'Catalog / Browse', read: 'History, checks, adoption', beacon: 'Beacons',
}

function ScanKindsPanel({ data }: { data?: Metrics }) {
  const scope = useMetricsScope()
  const k = data?.scan_kinds || {}
  return (
    <Section title="Scan requests by kind" scope={scope.label} note={`Answered public scan-API requests, by what was asked: checks per kind, with README badge / card / link-preview images and other reads split out. Preflight runs and drift-feed reads are counted here too. Counted from ${COUNTED_FROM.kinds}; the "Public scan requests by caller type" chart above still mixes all of them.`}>
      <div className="grid md:grid-cols-3 gap-3">
        <BarList title="Checks" rows={k.checks || {}} labels={KIND_LABEL} empty="No checks counted yet." gradient="linear-gradient(90deg,#2dd4bf,#818cf8)" />
        <BarList title="Images (badges, cards, previews)" rows={k.renders || {}} labels={KIND_LABEL} empty="No images counted yet." gradient="linear-gradient(90deg,#fbbf24,#f59e0b)" />
        <BarList title="Other (Preflight, feeds, catalog)" rows={k.other || {}} labels={KIND_LABEL} empty="Nothing counted yet." gradient="linear-gradient(90deg,#64748b,#94a3b8)" />
      </div>
    </Section>
  )
}

// ── Watch alerts by trigger (GET /admin/metrics → watch_alerts) ─────────────
const ALERT_LABEL: Record<string, string> = {
  answer_worse: 'Answer got worse', certified_lost: 'Certified lost', score_drop: 'Score dropped', definition_change: 'Signed definition changed',
  sandbox_change: 'Sandbox behavior changed', icon_change: 'Icons changed', good_news: 'Good news', held: 'Held (alerts paused for a planned re-score)',
}
const ALERT_COLOR: Record<string, string> = {
  answer_worse: '#f87171', certified_lost: '#fb923c', score_drop: '#fbbf24', definition_change: '#e879f9',
  sandbox_change: '#818cf8', icon_change: '#94a3b8', good_news: '#22c55e', held: '#64748b',
}

function WatchAlertsPanel({ data, today }: { data?: Metrics; today?: Metrics }) {
  const scope = useMetricsScope()
  const a = data?.watch_alerts || {}
  const s = data?.series || {}
  const codes = Object.keys(ALERT_LABEL)
  const lines: TrendLine[] = codes.map((c) => ({ key: c, label: ALERT_LABEL[c], color: ALERT_COLOR[c], kind: 'flow', data: s[`watch_alert:${c}`], today: today?.series?.[`watch_alert:${c}`]?.[0] }))
  return (
    <Section title="Watch alerts by trigger" scope={scope.label} note={`One count per trigger per alert (one alert can carry several), for public watches and for private repos connected through the GitHub App. Counted from ${COUNTED_FROM.alerts}: the first re-check after every stored answer was re-set ran silently on purpose, so nothing before it is counted.`}>
      <div className="glass rounded-2xl p-5 overflow-x-auto">
        <table className="w-full text-[12.5px]">
          <thead><tr className="text-left font-mono text-[11px] uppercase tracking-wide text-text-muted/70"><th className="py-1 pr-3">Trigger</th><th className="py-1 pr-3 text-right">Public</th><th className="py-1 pr-3 text-right">Private</th><th className="py-1 text-right">Total</th></tr></thead>
          <tbody>
            {codes.map((c) => {
              const pub = a[c]?.public ?? 0, priv = a[c]?.private ?? 0
              return (
                <tr key={c} className={`border-t border-border/40${pub + priv === 0 ? ' opacity-50' : ''}`}>
                  <td className="py-1.5 pr-3"><span className="inline-block w-2 h-2 rounded-full mr-2" style={{ background: ALERT_COLOR[c] }} />{ALERT_LABEL[c]}</td>
                  <td className="py-1.5 pr-3 tabular-nums text-right">{fmt(pub)}</td>
                  <td className="py-1.5 pr-3 tabular-nums text-right">{fmt(priv)}</td>
                  <td className="py-1.5 tabular-nums text-right font-semibold">{fmt(pub + priv)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <div className="glass rounded-2xl p-5 mt-3">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Alerts per day, stacked by trigger</div>
        <TrendChart bars days={data?.days} lines={lines} yLabel="Alerts per day" empty="No watch alerts counted in this window yet." />
      </div>
    </Section>
  )
}

// ── Growth: Certified + answer mix, activation by entrypoint, downloads, referrals ──
interface Growth {
  days?: string[]
  catalog_daily?: Record<string, Record<string, number>>
  catalog_now?: Record<string, number> | null
  downloads_daily?: Record<string, Record<string, number>>
  downloads_latest?: Record<string, number> | null
  referrals?: { search?: Record<string, number>; ai?: Record<string, number>; other_top?: Record<string, number>; search_total?: number; ai_total?: number; other_total?: number }
  indexnow_runs?: { at: string; outcome: string; submitted: number; status: number | null }[]
}
const INDEXNOW_OUTCOME: Record<string, string> = {
  sent: 'sent', not_confirmed: 'not confirmed', nothing_changed: 'nothing changed', http_error: 'HTTP error', skipped: 'skipped (error)',
}
const EP_LABEL: Record<string, string> = { desktop: 'Desktop app', cli: 'CLI + IDE extensions', sdk: 'Agent SDK', cloud: 'Anthropic cloud (remote)', other: 'Other / unknown' }

/** The newest day in `days` (oldest first) that has a row in `byDay`. */
const newestWithRow = (days: string[], byDay: Record<string, unknown>) => [...days].reverse().find((d) => byDay[d])

function GrowthPanel() {
  const w = useDashWindow()
  const label = useWindowLabel()
  const { data } = useQuery<Growth>({
    queryKey: ['admin-dash-growth', w.days + 1],
    queryFn: async () => { try { return (await api.get('/admin/metrics/growth', { params: { days: w.days + 1 } })).data } catch { return {} } },
  })
  // Referrals are a rolling count up to now; ask for exactly the window's length.
  const refQ = useQuery<Growth>({
    queryKey: ['admin-dash-growth', w.days],
    queryFn: async () => { try { return (await api.get('/admin/metrics/growth', { params: { days: w.days } })).data } catch { return {} } },
  })
  const traffic = useTraffic()
  const g = data || {}
  const dayList = w.complete
  const cat = g.catalog_daily || {}
  const catToday = cat[w.today]
  const catLines: TrendLine[] = [
    { key: 'certified', label: 'Certified', color: '#22c55e', kind: 'stock', data: dayList.map((d) => cat[d]?.certified ?? null), today: catToday?.certified },
    ...DECISIONS.map((d) => ({ key: d.value, label: d.phrase, color: d.color, dashed: true, kind: 'stock' as const, data: dayList.map((day) => cat[day]?.[d.value] ?? null), today: catToday?.[d.value] })),
  ]
  const dl = g.downloads_daily || {}
  const dlLines: TrendLine[] = [
    { key: 'npm', label: 'npm · last 7 days', color: '#f87171', kind: 'rolling', data: dayList.map((d) => dl[d]?.npm_week ?? null), today: dl[w.today]?.npm_week },
    { key: 'pypi', label: 'PyPI · last 7 days', color: '#818cf8', kind: 'rolling', data: dayList.map((d) => dl[d]?.pypi_week ?? null), today: dl[w.today]?.pypi_week },
  ]
  const firstRow = dayList.find((d) => cat[d])
  const snapDay = newestWithRow(dayList, cat)
  const snap = snapDay ? cat[snapDay] : undefined
  const dlDay = newestWithRow(dayList, dl)
  const dlRow = dlDay ? dl[dlDay] : undefined
  const tsum = (c: string) => traffic.col(c).reduce<number>((a, v) => a + (v ?? 0), 0)
  const hasEp = traffic.rows.some((r) => r.cc_machines_cli != null)
  const newSeen = tsum('cc_new_machines_30d')
  const newChecked = tsum('new_checked_same_day')
  const d7Cohort = tsum('d7_cohort'), d7Checked = tsum('d7_cohort_checked')
  const now = g.catalog_now
  const ref = refQ.data?.referrals || {}
  const pypiMonthBad = dlRow?.pypi_month != null && dlRow?.pypi_week != null && dlRow.pypi_month < dlRow.pypi_week
  return (
    <Section title="Growth — Certified, activation, downloads, search" scope={`${label}${firstRow && firstRow > dayList[0] ? ` · daily rows exist from ${dayLabel(firstRow)} (days before are blank, not zero)` : ''}`} note="Daily rows written by the 6-hour job from Nov 11 on. x402 is left out of the catalog mix, as on the site.">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Stat label={`Certified · ${dayLabel(snapDay)}`} value={snap ? fmt(snap.certified) : '—'} sub={<>{snap ? `of ${fmt(snap.total)} tools` : 'no daily row yet'}{now ? ` · right now: ${fmt(now.certified)}` : ''}</>} tip="The card and the chart legend read the same daily row (the last complete day). 'Right now' is the live count, which can be a few tools apart." />
        {DECISIONS.map((d) => <Stat key={d.value} label={`${d.phrase} · ${dayLabel(snapDay)}`} value={snap ? fmt(snap[d.value]) : '—'} sub={<>{snap && snap.total ? pctOf(snap[d.value] ?? 0, snap.total) : ''}{now ? ` · right now: ${fmt(now[d.value])}` : ''}</>} />)}
        <Stat label={`npm downloads · 7 days to ${dayLabel(dlDay)}`} value={fmtOrDash(dlRow?.npm_week)} sub={<>agentavow-trust{g.downloads_latest?.npm_week != null ? ` · newest fetch: ${fmt(g.downloads_latest.npm_week)}` : ''}</>} />
        <Stat
          label={`PyPI downloads · 7 days to ${dayLabel(dlDay)}`}
          value={fmtOrDash(dlRow?.pypi_week)}
          sub={pypiMonthBad
            ? `last 30 days: ${fmt(dlRow?.pypi_month)} (wrong: pypistats' 30-day figure lagged; fixed for days from Nov 13)`
            : dlRow?.pypi_month != null ? `last 30 days: ${fmt(dlRow.pypi_month)}` : 'agentavow-trust'}
          tip={g.downloads_latest?.pypi_week != null ? `Newest fetch: ${fmt(g.downloads_latest.pypi_week)} in 7 days${g.downloads_latest.pypi_month != null ? `, ${fmt(g.downloads_latest.pypi_month)} in 30` : ''}.` : undefined}
        />
      </div>
      <div className="grid md:grid-cols-2 gap-3 mt-3">
        <div className="glass rounded-2xl p-5">
          <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Certified and the answer mix · tools on each day (x402 left out)</div>
          <TrendChart days={dayList} lines={catLines} yLabel="Tools" empty="No daily catalog rows yet. The 6-hour job writes the first one after deploy." />
        </div>
        <div className="glass rounded-2xl p-5">
          <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Registry downloads · 7-day total, read once a day</div>
          <TrendChart days={dayList} lines={dlLines} yLabel="Downloads in the 7 days before" empty="No download counts yet. The 6-hour job fetches them from npm and pypistats." />
        </div>
      </div>
      <div className="grid md:grid-cols-2 gap-3 mt-3">
        <div className="glass rounded-2xl p-5">
          <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Claude Code activation by entrypoint · {rangeLabel(dayList)}</div>
          {hasEp ? (
            <table className="w-full text-[12.5px]">
              <thead><tr className="text-left font-mono text-[11px] uppercase tracking-wide text-text-muted/70"><th className="py-1 pr-3">Entrypoint</th><th className="py-1 pr-3 text-right">Connecting (days of use)</th><th className="py-1 pr-3 text-right">Checked (days of use)</th><th className="py-1 text-right">Share</th></tr></thead>
              <tbody>
                {Object.keys(EP_LABEL).map((ep) => {
                  const c = tsum(`cc_machines_${ep}`), k = tsum(`checked_machines_${ep}`)
                  return (
                    <tr key={ep} className={`border-t border-border/40${c === 0 ? ' opacity-50' : ''}`}>
                      <td className="py-1.5 pr-3">{EP_LABEL[ep]}</td>
                      <td className="py-1.5 pr-3 tabular-nums text-right">{fmt(c)}</td>
                      <td className="py-1.5 pr-3 tabular-nums text-right">{fmt(k)}</td>
                      <td className="py-1.5 tabular-nums text-right">{c ? pctOf(k, c) : '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          ) : <p className="text-[12.5px] text-text-muted/70">No entrypoint columns yet: the nightly snapshot adds them from Nov 11.</p>}
          <p className="mt-3 text-[12.5px]">
            New machines that got a verdict on their first day: <span className="font-semibold tabular-nums">{newSeen ? pctOf(newChecked, newSeen) : '—'}</span> <span className="text-text-muted">({fmt(newChecked)} of {fmt(newSeen)})</span>
            {' · '}within their first week: <span className="font-semibold tabular-nums">{d7Cohort && traffic.rows.some((r) => r.d7_cohort_checked != null) ? pctOf(d7Checked, d7Cohort) : '—'}</span> <span className="text-text-muted">(machines first seen a week earlier; counted from Nov 11, so the first full week ends Nov 18)</span>
          </p>
          <p className="mt-1 text-[11px] text-text-muted/60">A day of use is one machine on one day: a machine seen on two days counts twice, and on two entrypoints, in both. Owner machines excluded.</p>
        </div>
        <div className="glass rounded-2xl p-5">
          <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Landing visits by referrer · last {w.days} × 24 hours up to now</div>
          <div className="grid grid-cols-3 gap-3 mb-3">
            <Stat label="Search" value={fmt(ref.search_total)} />
            <Stat label="AI assistants" value={fmt(ref.ai_total)} />
            <Stat label="Other sites" value={fmt(ref.other_total)} />
          </div>
          <BarList title="Search engines" rows={ref.search || {}} labels={{}} empty="No search referrals yet (counted from Nov 11)." gradient="linear-gradient(90deg,#2dd4bf,#818cf8)" />
          {Object.keys(ref.ai || {}).length > 0 && <div className="mt-3"><BarList title="AI assistants" rows={ref.ai || {}} labels={{}} empty="" gradient="linear-gradient(90deg,#818cf8,#e879f9)" /></div>}
          {Object.keys(ref.other_top || {}).length > 0 && <div className="mt-3"><BarList title="Top other sites" rows={ref.other_top || {}} labels={{}} empty="" gradient="linear-gradient(90deg,#64748b,#94a3b8)" /></div>}
          <p className="mt-2 text-[11px] text-text-muted/60">Only the referring site's name is stored, never its page or search terms. Direct visits and visits from our own pages carry no referrer. Search Console and Bing Webmaster stay manual.</p>
          <div className="mt-3 pt-3 border-t border-border/40 text-[12.5px]">
            <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-1">Search-engine pings (IndexNow) · after each deploy, newest first</div>
            {(g.indexnow_runs || []).length ? (
              <ul className="space-y-0.5 tabular-nums">
                {(g.indexnow_runs || []).map((r) => (
                  <li key={r.at}><span className="font-mono text-text-muted">{r.at.slice(0, 16).replace('T', ' ')} UTC</span> · {INDEXNOW_OUTCOME[r.outcome] ?? r.outcome} · {fmt(r.submitted)} URL{r.submitted === 1 ? '' : 's'}{r.status != null ? ` · HTTP ${r.status}` : ''}</li>
                ))}
              </ul>
            ) : <p className="text-text-muted/70">No ping recorded yet. The next production deploy stores one.</p>}
          </div>
        </div>
      </div>
    </Section>
  )
}

function ClaudeTrafficPanel() {
  const w = useDashWindow()
  const label = useWindowLabel()
  const [mode, setMode] = useState<'machines' | 'calls'>('machines')
  const { rows, col, latest } = useTraffic()
  const lines: TrendLine[] = mode === 'machines'
    ? [
        { key: 'checked', label: 'Machines AgentAvow checked something for · owner excluded', color: '#22c55e', kind: 'distinct', data: col('checked_machines_excl_owner') },
        { key: 'cc', label: 'Claude Code machines connecting', color: '#2dd4bf', kind: 'distinct', data: col('cc_machines') },
        { key: 'new', label: 'New machines (not seen in 30 days)', color: '#fbbf24', kind: 'flow', data: col('cc_new_machines_30d') },
        { key: 'hook', label: 'Plugin hook machines', color: '#94a3b8', dashed: true, kind: 'distinct', data: col('hook_machines_nginx') },
        { key: 'ccx', label: 'Claude Code machines · owner excluded', color: '#818cf8', dashed: true, kind: 'distinct', data: col('cc_machines_excl_owner') },
      ]
    : [
        { key: 'cai', label: 'claude.ai connector requests (every HTTP request)', color: '#818cf8', kind: 'flow', data: col('claudeai_reqs') },
        { key: 'cc-calls', label: 'Claude Code tool calls', color: '#2dd4bf', kind: 'flow', data: col('calls_claude_code') },
        { key: 'claude-calls', label: 'claude.ai tool calls', color: '#e879f9', kind: 'flow', data: col('calls_claude') },
        { key: 'hook-scans', label: 'Plugin hook scans', color: '#94a3b8', dashed: true, kind: 'flow', data: col('hook_reqs') },
      ]
  const covered = rows.length
  const day = dayLabel(latest?.day)
  const toggle = (
    <div className="flex gap-1 font-mono text-[12px]">
      {(['machines', 'calls'] as const).map((m) => (
        <button key={m} onClick={() => setMode(m)} className={`px-2.5 py-1 rounded-lg transition-colors ${mode === m ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>
          {m === 'machines' ? 'Machines' : 'Requests & calls'}
        </button>
      ))}
    </div>
  )
  return (
    <Section title="Claude traffic — day by day" scope={`${label} · snapshot rows for ${covered} of the ${w.days} days`} note="Traffic that starts in Anthropic's apps, one row per UTC day, written by the nightly snapshot at 00:40 UTC for the day before and kept for good (the server log itself only holds four days). Today never appears: its row is written after it ends. 'Machines checked' is the headline usage number: distinct machines where the plugin checked something on its own that day, at session start or when a tool was being installed, leaving out the owner's test machines. 'Machines connecting' is distinct addresses that opened the plugin's MCP server from Claude Code (installs, not use). Both come from the server log, NOT the tool-call counters in the panels above. A row marked partial did not cover all 24 hours." right={toggle}>
      <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Latest complete day with a snapshot: {day}{latest?.log_complete === 0 ? ' (partial)' : ''}</div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-3">
        <Stat label={`Machines checked · ${day}`} value={fmt(latest?.checked_machines_excl_owner)} sub={`${fmt(latest?.preinstall_machines)} at install time · owner excluded`} series={col('checked_machines_excl_owner')} />
        <Stat label={`Machines connecting · ${day}`} value={fmt(latest?.cc_machines)} sub={`${fmt(latest?.cc_new_machines_30d)} new`} series={col('cc_machines')} />
        <Stat label={`claude.ai connector requests · ${day}`} value={fmt(latest?.claudeai_reqs)} sub="every HTTP request through Anthropic's proxy: handshakes, tool lists and calls" series={col('claudeai_reqs')} />
        <Stat label={`Hook machines · ${day}`} value={fmt(latest?.hook_machines_nginx)} sub={`${fmt(latest?.hook_reqs)} scans · most common plugin version ${latest?.hook_top_version ?? '—'}`} series={col('hook_machines_nginx')} />
        <Stat label={`Claude Code tool calls · ${day}`} value={fmt(latest?.calls_claude_code)} sub={`${fmt(latest?.callers_claude_code)} distinct machines`} series={col('calls_claude_code')} />
        <Stat label="Days with a snapshot" value={fmt(covered)} sub={`of the ${w.days} complete days in the window`} />
        <Stat label={`Plugin gate machines · ${day}`} value={fmt(latest?.gate_machines)} sub="the plugin's gate (agentavow-gate)" series={col('gate_machines')} />
        <Stat label={`npm tool gate machines · ${day}`} value={fmt(latest?.tool_gate_machines)} sub={`${fmt(latest?.tool_gate_reqs)} requests · the npm SDK's tool gate, counted from Nov 12`} series={col('tool_gate_machines')} />
        <Stat label={`A2A card fetches · ${day}`} value={fmt(latest?.a2a_card_fetches)} sub={`${fmt(latest?.a2a_card_fetchers)} distinct addresses · our agent card, counted from Nov 12`} series={col('a2a_card_fetches')} />
      </div>
      <div className="glass rounded-2xl p-5">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">{mode === 'machines' ? 'Machines per day' : 'Requests and tool calls per day'}</div>
        <TrendChart days={w.complete} lines={lines} yLabel={mode === 'machines' ? 'Machines per day (distinct)' : 'Requests or tool calls per day'} empty="No snapshot rows yet. The nightly cron writes the first row at 00:40 UTC." />
      </div>
      <div className="glass rounded-2xl p-5 mt-3 overflow-x-auto max-h-[28rem] overflow-y-auto">
        <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Day by day · {rangeLabel(w.complete)} (UTC), newest first</div>
        <table className="w-full text-[12.5px] tabular-nums">
          <thead>
            <tr className="text-[11px] font-mono uppercase tracking-wide text-text-muted/60">
              <th className="text-left py-1">Day</th><th className="text-right">Machines connecting</th><th className="text-right">New</th><th className="text-right">Sessions</th>
              <th className="text-right" title="Every HTTP request from claude.ai: handshakes, tool lists and tool calls">claude.ai requests (all)</th><th className="text-right">Hook machines</th><th className="text-right">Hook scans</th>
              <th className="text-right">Claude Code tool calls / machines</th><th className="text-right" title="Only actual tool calls (checks) from claude.ai">claude.ai tool calls</th><th className="text-right">ChatGPT tool calls</th>
            </tr>
          </thead>
          <tbody>
            {[...w.complete].reverse().map((d) => {
              const r = rows.find((x) => x.day === d)
              if (!r) return <tr key={d} className="border-t border-border/40 opacity-50"><td className="py-1 font-mono text-text-muted">{d}</td><td colSpan={9} className="text-text-muted/70 text-right">no snapshot</td></tr>
              return (
                <tr key={d} className={`border-t border-border/40${r.log_complete === 0 ? ' opacity-70' : ''}`}>
                  <td className="py-1 font-mono text-text-muted">{r.day}{r.log_complete === 0 ? ' *' : ''}</td>
                  <td className="text-right text-text">{fmt(r.cc_machines)}</td><td className="text-right">{fmt(r.cc_new_machines_30d)}</td><td className="text-right">{fmt(r.cc_sessions)}</td>
                  <td className="text-right">{fmt(r.claudeai_reqs)}</td><td className="text-right">{fmt(r.hook_machines_nginx)}</td><td className="text-right">{fmt(r.hook_reqs)}</td>
                  <td className="text-right">{fmt(r.calls_claude_code)} / {fmt(r.callers_claude_code)}</td><td className="text-right">{fmt(r.calls_claude)}</td><td className="text-right">{fmt(r.calls_chatgpt)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        <p className="text-[11px] text-text-muted/60 mt-2">* partial day (the log did not cover all 24 hours). claude.ai requests count every request the connector makes; claude.ai tool calls count only the checks it actually ran, so a day can have thousands of requests and no tool calls.</p>
      </div>
    </Section>
  )
}

// ── Landing trend: landings and install-command copies per day, ads vs organic ──
interface LandingDay { date: string; lp_view: number; lp_view_paid: number; copy_plugin_cmd: number; copy_plugin_cmd_paid: number }

function LandingTrendPanel() {
  const w = useDashWindow()
  const label = useWindowLabel()
  const { data } = useQuery<{ landing?: LandingDay[] }>({
    queryKey: ['admin-dash-landing-daily', w.days + 1],
    queryFn: async () => { try { return (await api.get('/analytics/conversion/daily', { params: { days: w.days + 1 } })).data } catch { return {} } },
  })
  const byDay = Object.fromEntries((data?.landing || []).map((d) => [d.date, d]))
  // Every complete UTC day in the window: a day with no landings really is zero here.
  const dayList = w.complete
  const get = (d: string, k: keyof Omit<LandingDay, 'date'>) => byDay[d]?.[k] ?? 0
  const organic = (d: string, k: 'lp_view' | 'copy_plugin_cmd') => get(d, k) - get(d, `${k}_paid`)
  const t = w.today
  const lines: TrendLine[] = [
    { key: 'lp', label: 'Landed · organic', color: '#2dd4bf', data: dayList.map((d) => organic(d, 'lp_view')), today: organic(t, 'lp_view') },
    { key: 'lp-paid', label: 'Landed · from ads', color: '#818cf8', data: dayList.map((d) => get(d, 'lp_view_paid')), today: get(t, 'lp_view_paid') },
    { key: 'copy', label: 'Copied install command · organic', color: '#22c55e', dashed: true, data: dayList.map((d) => organic(d, 'copy_plugin_cmd')), today: organic(t, 'copy_plugin_cmd') },
    { key: 'copy-paid', label: 'Copied install command · from ads', color: '#f59e0b', dashed: true, data: dayList.map((d) => get(d, 'copy_plugin_cmd_paid')), today: get(t, 'copy_plugin_cmd_paid') },
  ]
  return (
    <Section title="Landings and install-command copies — day by day" scope={label} note="Visits per UTC day that landed on a landing page, and that copied the /plugin install command, split by whether the visit first arrived from an ad (its link tags say paid / cpc / ppc / display / paid-social, or it came from reddit, meta, facebook or instagram). Bots left out. Read it next to machines protected.">
      <div className="glass rounded-2xl p-5">
        <TrendChart days={dayList} lines={lines} yLabel="Visits per day" empty="No landings in this window yet." />
      </div>
    </Section>
  )
}

const ACTION_AREAS: [string, string][] = [['browse', 'Browse'], ['trust_index', 'Trust Index'], ['certified', 'Certified'], ['preflight', 'Preflight'], ['dev', 'For developers']]

function PageActionsPanel() {
  const w = useDashWindow()
  const { data } = useQuery<{ views?: Record<string, number>; actions?: Record<string, number> }>({
    queryKey: ['admin-dash-page-actions', w.days],
    queryFn: async () => { try { return (await api.get('/analytics/page-actions', { params: { days: w.days } })).data } catch { return {} } },
  })
  const actions = data?.actions || {}
  // Counting started on COUNTED_FROM.pageActions; say how much of the window it covers.
  const sinceStart = Math.round((Date.parse(w.today) - Date.parse(COUNTED_FROM.pageActions)) / 86_400_000)
  const covered = Math.min(w.days, Math.max(0, sinceStart))
  const scope = `Last ${w.days} × 24 hours up to now (this section can't be split by UTC day) · counting started ${dayLabel(COUNTED_FROM.pageActions)}${covered < w.days ? `, so it covers ${covered === 0 ? 'only today so far' : `${covered} full day${covered === 1 ? '' : 's'} plus today so far`}` : ''}`
  return (
    <Section title="Catalog and developer pages — views and actions" scope={scope} note="Visits that viewed each page and that took each main action on it (searches and filters, opening a tool, copies, claim / private-scan starts, gate checks, Preflight runs). What someone typed is never sent. Bots left out.">
      <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {ACTION_AREAS.map(([area, areaLabel]) => {
          const rows = Object.fromEntries(Object.entries(actions).filter(([k]) => k.startsWith(`${area}:`)).map(([k, n]) => [k.slice(area.length + 1).replace(/_/g, ' '), n]))
          return (
            <div key={area} className="min-w-0">
              <Stat label={areaLabel} value={fmt(data?.views?.[area])} sub="visits viewing" />
              <div className="mt-2"><BarList title="Actions" rows={rows} labels={{}} empty="No actions yet." gradient="linear-gradient(90deg,#2dd4bf,#818cf8)" /></div>
            </div>
          )
        })}
      </div>
    </Section>
  )
}

// ── METRICS TAB ──────────────────────────────────────────────────────────────
function MetricsTab() {
  const [days, setDays] = useState<PageWin>(7)
  const [includeToday, setIncludeToday] = useState(false)
  const [now] = useState(() => Date.now())
  const win = { days, includeToday, complete: completeDays(days, now), today: utcDay(0, now) }
  return (
    <DashWindowContext.Provider value={win}>
      <WindowBar days={days} setDays={setDays} includeToday={includeToday} setIncludeToday={setIncludeToday} />
      <MetricsBody />
    </DashWindowContext.Provider>
  )
}

function MetricsBody() {
  const { isAdmin } = useAdminAccess()
  const scope = useMetricsScope()
  const [trend, setTrend] = useState<'callers' | 'calls'>('callers')
  const { data, today } = useMetricsData()
  const flagged = useQuery<{ pct: number | null; flagged: number; scanned: number }>({
    queryKey: ['admin-dash-flagged'],
    queryFn: async () => { try { return (await api.get('/public/scan-catalog/flagged-stat')).data } catch { return { pct: null, flagged: 0, scanned: 0 } } },
  })
  const h = data?.headline || {}
  const s = data?.series || {}
  const f = data?.funnel || {}
  const th = today?.headline
  const ts = today?.series
  /** " · today so far N" on a windowed tile when the page shows today. */
  const tsf = (key: string) => (th && th[key] != null ? ` · today so far ${fmt(th[key])}` : '')
  const board = data?.badges?.leaderboard || []
  const grades = data?.scans?.grade_distribution || {}
  const decisions = data?.scans?.decision_distribution || {}
  const surfaces = data?.catalog?.by_surface || {}
  const funnelSteps: [string, number][] = [['Scanned (repos checked)', f.scanned ?? 0], ['Watched (watches created)', f.watched ?? 0], ['Claimed (ownership claims)', f.claimed ?? 0]]
  const fmax = Math.max(...funnelSteps.map(([, n]) => n), 1)
  const bySurface = data?.mcp?.by_surface || {}
  const crawlerCallers = bySurface.other?.callers ?? 0
  const realCallers = Object.entries(bySurface).filter(([k]) => k !== 'other').reduce((a, [, v]) => a + (v.callers ?? 0), 0)
  const communityTotal = Object.values(decisions).reduce((a, b) => a + b, 0)

  return (
    <>
      <StartHerePanel />
      <CampaignPanel />
      <LandingTrendPanel />
      <Section title="Product & adoption" scope={scope.label} note="Everything the product counts: the full set, not a slice. Tiles marked 'right now' or 'all time' are not limited to the window.">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          <Stat label="Repos scanned" value={fmt(h.repos_scanned)} sub={`${fmt(h.new_repos)} scanned for the first time${tsf('repos_scanned')}`} series={s.repos_scanned} />
          <Stat label="Badge fetches" value={fmt(h.badge_fetches)} sub={`${fmt(h.readme_renders)} in READMEs${tsf('badge_fetches')}`} series={s.badge_fetches} />
          <Stat label="Watches created" value={fmt(h.watches_created)} sub={tsf('watches_created').replace(/^ · /, '') || undefined} series={s.watches_created} />
          <Stat label="Unique checkers" value={fmt(h.unique_checkers)} sub={`distinct people and agents who ran a check, each counted once over the window${tsf('unique_checkers')}`} />
          <Stat label="Browser visits (one per person per day)" value={fmt(h.unique_humans)} sub={`not unique people: a person on 3 days counts 3 times. Counted privately, nothing identifying stored${tsf('unique_humans')}`} />
          <Stat label="Adoption score lookups" value={fmt(h.adoption_hits)} sub={tsf('adoption_hits').replace(/^ · /, '') || undefined} series={s.adoption_hits} />
          <Stat label="One-click install clicks" value={fmt(h.install_clicks)} sub={`${installSplit(data?.installs_by_client) ?? ''} · split by app from ${COUNTED_FROM.installSplit}; earlier clicks are in the total only${tsf('install_clicks')}`} series={s.install_clicks} />
          <Stat label="Forced re-scans" value={fmt(h.force_rescans)} sub={`someone asked for a fresh result instead of the 1-hour cache${tsf('force_rescans')}`} series={s.force_rescans} />
          <Stat label="API-key requests" value={fmt(h.api_calls)} sub="requests signed in with an API key. The public scan API needs no key, so scans don't count here" series={s.api_calls} />
          <Stat label="Formal attestations stored" value={fmt(h.attestations_issued)} sub="agent-to-agent attestations. Every scan's signed result is made per request and not stored, so scans don't count here" />
          <Stat label="Active watches" value={fmt(data?.watches?.active)} sub={`right now · ${fmt(data?.watches?.total)} ever created`} />
          <Stat label="Verified claims" value={fmt(data?.claims?.verified_total)} sub={`all time · ${fmt(data?.claims?.public)} public · ${fmt(data?.claims?.private)} private`} />
          <Stat label="Active verification badges" value={fmt(data?.attestations?.verification_badges_active)} sub="right now" />
          <Stat label="MCP connector calls" value={fmt(h.mcp_calls)} sub={`${fmt(data?.mcp?.checks_window)} hand-run checks · ${fmt(data?.mcp?.errors_window)} errors${tsf('mcp_calls')}`} series={s.mcp_calls} />
          <Stat label="MCP callers · days of use" value={fmt(h.mcp_callers)} sub={`${fmt(realCallers)} people and agents · ${fmt(crawlerCallers)} crawlers and monitors. Each machine counts once per day it called`} series={s.mcp_callers} />
          <Stat label="Plugin hook scans" value={fmt(h.hook_scans)} sub={`${fmt(h.hook_machines)} days of use · session-start and install-time hooks (install-time counted from ${COUNTED_FROM.installTimeHook})${tsf('hook_scans')}`} series={s.hook_scans} />
          <Stat label="Private repo scans (GitHub App)" value={fmt(data?.private_repos?.app_scans)} sub={`all time · ${fmt(data?.private_repos?.app_installs_active)} installs · ${fmt(data?.private_repos?.published_to_search)} published`} />
          <Stat label="One-time private scans" value={fmt(data?.private_repos?.onetime_scans_window)} sub="scans with a token supplied once, in the window" />
          <Stat label="Alert webhooks" value={fmt(data?.alert_webhooks?.active)} sub="active right now" />
          <Stat label="Redirects (not usage)" value={fmt(h.requests_redirected)} sub="301/302/308 and old-domain requests, kept out of every count above" series={s.requests_redirected} />
        </div>
      </Section>

      {(() => {
        const mcp = data?.mcp || {}
        const calls = mcp.calls_window ?? 0
        const ok = mcp.ok_window ?? 0
        const err = mcp.errors_window ?? 0
        const answers = mcp.answers_window || {}
        const answered = DECISIONS.reduce((a, d) => a + (answers[d.value] ?? 0), 0)
        // "unlisted" = calls to a tool name we do not serve; shown only when non-zero so
        // the rows always add up to Total calls.
        const toolLabel = (t: string) => (t === 'unlisted' ? 'Unknown tool name (not one we serve)' : t)
        const tools = Object.entries(mcp.by_tool || {}).filter(([t, n]) => t !== 'unlisted' || n > 0).sort((a, b) => b[1] - a[1])
        const anyTool = tools.some(([, n]) => n > 0)
        // "other" is what the User-Agent bucketer could not place: in practice the MCP
        // crawlers and uptime monitors (mcpbeat, SentinelOracle, …), not people. Name it
        // so, and list it last so the real surfaces read first.
        const surfaceLabels: Record<string, string> = {
          claude: 'Claude Directory', chatgpt: 'ChatGPT', 'claude-code': 'Claude Code',
          cursor: 'Cursor', vscode: 'VS Code', codex: 'Codex', other: 'Crawlers / unknown',
        }
        const rowsBySurface = Object.entries(bySurface)
          .map(([k, d]) => ({ s: k, label: surfaceLabels[k] || k, ...d, calls: d.calls ?? 0 }))
          .sort((a, b) => (a.s === 'other' ? 1 : b.s === 'other' ? -1 : b.calls - a.calls))
        const anySurface = rowsBySurface.some((r) => r.calls > 0)
        return (
          <Section title="MCP connector — usage by surface" scope={scope.label} note={`Use of the remote MCP server at agentavow.com/mcp from every place it's installed (Claude Directory, ChatGPT, the Claude Code plugin, Cursor, VS Code, Codex). The surface comes from the request's User-Agent and the rows add up to the total. Every surface is listed, so a zero means that channel has sent nothing yet. 'Crawlers / unknown' is MCP directory crawlers and uptime monitors, not users. The three answers are counted from ${COUNTED_FROM.answers}.`}>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <Stat label="Total calls" value={fmt(calls)} sub={`${fmt(ok)} ok · ${pctOf(err, calls)} errors`} />
              <Stat label="Errors" value={fmt(err)} />
              {DECISIONS.map((d) => {
                const n = answers[d.value] ?? 0
                return <Stat key={d.value} label={d.phrase} value={fmt(n)} sub={answered ? `${pctOf(n, answered)} of answers` : undefined} />
              })}
              <Stat label="Hand-run checks" value={fmt(mcp.checks_window)} sub="calls minus about_agentavow overviews and owner machines" />
            </div>
            <div className="glass rounded-2xl p-5 mt-3">
              <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Calls by tool</div>
              {anyTool ? (
                <div className="space-y-1">
                  {tools.map(([t, n]) => (
                    <div key={t} className="flex justify-between text-[12.5px] py-0.5">
                      <span className="font-mono text-text-muted truncate">{toolLabel(t)}</span>
                      <span className="tabular-nums text-text-muted/70 ml-3">{fmt(n)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[12.5px] text-text-muted/70">No connector calls recorded yet. Counts start once the connector is live and used in Claude.</p>
              )}
            </div>
            <div className="glass rounded-2xl p-5 mt-3">
              <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Calls by surface</div>
              {anySurface ? (
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px] font-mono uppercase tracking-wide text-text-muted/60 pb-1">
                    <span>Surface</span>
                    <span className="flex gap-4"><span className="w-16 text-right">Calls</span><span className="w-20 text-right" title="Distinct callers per day, added up over the window">Callers (days of use)</span><span className="w-16 text-right">Errors</span><span className="w-28 text-right">Safe/Review/No</span></span>
                  </div>
                  {rowsBySurface.map((r) => (
                    <div key={r.s} className={`flex justify-between text-[12.5px] py-0.5${r.calls === 0 ? ' opacity-50' : ''}`}>
                      <span className="text-text-muted truncate">{r.label}</span>
                      <span className="flex gap-4 tabular-nums text-text-muted/70">
                        <span className="w-16 text-right">{fmt(r.calls)}</span>
                        <span className="w-20 text-right">{fmt(r.callers ?? 0)}</span>
                        <span className="w-16 text-right">{fmt(r.errors ?? 0)}</span>
                        <span className="w-28 text-right">{fmt(r.answer_safe ?? 0)}/{fmt(r.answer_review ?? 0)}/{fmt(r.answer_do_not_connect ?? 0)}</span>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-[12.5px] text-text-muted/70">No per-surface traffic yet. Once the connector is used from Claude, ChatGPT, or the plugin, each surface shows here.</p>
              )}
            </div>
          </Section>
        )
      })()}

      {(() => {
        const key = (sfc: string) => `mcp_${trend}:${sfc}`
        const kind = trend === 'callers' ? 'distinct' as const : 'flow' as const
        const line = (k: string, label: string, color: string): TrendLine => ({ key: k, label, color, kind, data: s[key(k)], today: ts?.[key(k)]?.[0] })
        const surfaceLines: TrendLine[] = [
          line('claude-code', 'Claude Code', '#2dd4bf'),
          line('claude', 'Claude Directory', '#818cf8'),
          line('chatgpt', 'ChatGPT', '#e879f9'),
          line('cursor', 'Cursor', '#fbbf24'),
          line('vscode', 'VS Code', '#f87171'),
          line('codex', 'Codex', '#a3e635'),
          { key: 'hook', label: trend === 'callers' ? 'Plugin hook (machines)' : 'Plugin hook (scans)', color: '#94a3b8', dashed: true, kind, data: trend === 'callers' ? s.hook_machines : s.hook_scans, today: (trend === 'callers' ? ts?.hook_machines : ts?.hook_scans)?.[0] },
        ]
        const cl = (k: string, label: string, color: string, dashed?: boolean): TrendLine => ({ key: k, label, color, dashed, kind: 'flow', data: s[`scan_requests:${k}`], today: ts?.[`scan_requests:${k}`]?.[0] })
        const callerLines: TrendLine[] = [
          cl('human', 'People (browser)', '#2dd4bf'),
          cl('agent', 'Agents (Claude, ChatGPT, Cursor)', '#818cf8'),
          cl('agentavow', 'AgentAvow clients (hooks, gates, SDKs)', '#e879f9'),
          cl('automated', 'Automated (crawlers, scripts)', '#94a3b8', true),
          { key: 'badge', label: 'Badge fetches', color: '#fbbf24', kind: 'flow', data: s.badge_fetches, today: ts?.badge_fetches?.[0] },
        ]
        const toggle = (
          <div className="flex gap-1 font-mono text-[12px]">
            {(['callers', 'calls'] as const).map((m) => (
              <button key={m} onClick={() => setTrend(m)} className={`px-2.5 py-1 rounded-lg transition-colors ${trend === m ? 'bg-primary/15 text-primary-light' : 'text-text-muted hover:text-text'}`}>
                {m === 'callers' ? 'Machines' : 'Calls'}
              </button>
            ))}
          </div>
        )
        return (
          <Section title="Adoption trend — day by day" scope={scope.label} note={`Who is actually using the connector, per UTC day. "Machines" is distinct callers each day (counted privately, nothing identifying stored): the honest adoption number. "Calls" is raw tool calls. Claude Directory traffic arrives through Anthropic's proxy, so its machine count is a floor. The plugin hook is the session-start auto-check: it never touches the MCP counters, so it is drawn on its own (dashed). Crawlers are left out.`} right={toggle}>
            <div className="glass rounded-2xl p-5">
              <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Connector use by surface · {trend === 'callers' ? 'distinct machines' : 'tool calls'} per day</div>
              <TrendChart days={data?.days} lines={surfaceLines} yLabel={trend === 'callers' ? 'Machines per day (distinct)' : 'Tool calls per day'} empty="No connector use in this window yet. Lines appear once a surface calls a tool." />
            </div>
            <div className="glass rounded-2xl p-5 mt-3">
              <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">Public scan requests by caller type · per day</div>
              <TrendChart days={data?.days} lines={callerLines} yLabel="Requests per day" empty="No scan requests recorded in this window." />
            </div>
          </Section>
        )
      })()}

      <ClaudeTrafficPanel />

      <PageActionsPanel />

      <ScanKindsPanel data={data} />

      <WatchAlertsPanel data={data} today={today} />

      <GrowthPanel />

      <BehavioralPanel />

      <Section title="Who is calling — people, agents, our clients, automation" scope={scope.label} note={`Public scan requests and badge fetches split by the caller's User-Agent. 'AgentAvow clients' is our own plugin hooks, npm/Python gates and SDK adapters (their own row from ${COUNTED_FROM.ourClients}; before that the plugin hook counted as an agent and the rest as automated). The GitHub Action sends a bare curl User-Agent, so it still lands in 'automated'. 'Automated' is crawlers, uptime monitors and scripts and is not usage. Honest usage = people + agents + our clients.`}>
        <div className="grid md:grid-cols-2 gap-4">
          {([['scan_requests', 'Scan requests'], ['badge_fetches', 'Badge fetches']] as const).map(([key, title]) => {
            const q = data?.traffic_quality?.[key] || {}
            const total = q.total ?? 0
            const rows: [string, number, string][] = [
              ['People (browser)', q.human ?? 0, 'linear-gradient(90deg,#2dd4bf,#818cf8)'],
              ['Agents (Claude, ChatGPT, Cursor, README badges)', q.agent ?? 0, 'linear-gradient(90deg,#818cf8,#e879f9)'],
              ['AgentAvow clients (hooks, gates, SDKs)', q.agentavow ?? 0, 'linear-gradient(90deg,#e879f9,#f59e0b)'],
              ['Automated (crawlers, monitors, scripts)', q.automated ?? 0, 'linear-gradient(90deg,#64748b,#94a3b8)'],
            ]
            const real = (q.human ?? 0) + (q.agent ?? 0) + (q.agentavow ?? 0)
            return (
              <div key={key} className="glass rounded-2xl p-5">
                <div className="flex justify-between items-baseline mb-3">
                  <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted">{title}</div>
                  <div className="text-[12.5px] tabular-nums text-text-muted">{fmt(real)} real <span className="text-text-muted/60">of {fmt(total)}</span></div>
                </div>
                {total > 0 ? rows.map(([rowLabel, n, bg]) => (
                  <div key={rowLabel} className="mb-2">
                    <div className="flex justify-between text-[12.5px] mb-1"><span className="text-text-muted">{rowLabel}</span><span className="tabular-nums text-text-muted/70">{fmt(n)} <span className="text-[11px]">({pctOf(n, total)})</span></span></div>
                    <div className="h-2 rounded-full bg-surface overflow-hidden"><div className="h-full rounded-full" style={{ width: `${(n / total) * 100}%`, background: bg }} /></div>
                  </div>
                )) : (
                  <p className="text-[12.5px] text-text-muted/70">No classified requests in this window yet.</p>
                )}
              </div>
            )
          })}
        </div>
        {/* The counting rules and the date they changed — so the step down in every
            usage line on that date reads as a rule change, not a drop. */}
        {data?.baseline?.rules?.length ? (
          <div className="glass rounded-2xl p-5 mt-4">
            <div className="text-[11.5px] font-mono uppercase tracking-wide text-text-muted mb-2">
              Counting rules · since {data.baseline.rules_changed_on ?? '—'}
            </div>
            <ul className="space-y-1">
              {data.baseline.rules.map((rule) => (
                <li key={rule} className="text-[12.5px] text-text-muted/80 pl-3 border-l border-primary/30">{rule}</li>
              ))}
            </ul>
            <p className="text-[11px] text-text-muted/60 mt-2">Every usage number above steps down on that date. That is the rules changing, not usage.</p>
          </div>
        ) : null}
      </Section>

      <Section title="Product funnel — where users drop off" scope={scope.label} note="Repos scanned → watches created → ownership claims, with the share that made it from each step to the next.">
        <div className="glass rounded-2xl p-6 flex flex-col gap-3">
          {funnelSteps.map(([stepLabel, n], i) => {
            const prev = i === 0 ? n : funnelSteps[i - 1][1]
            return (
              <div key={stepLabel}>
                <div className="flex justify-between text-[12.5px] mb-1"><span className="font-mono">{stepLabel}</span><span className="tabular-nums text-text-muted">{fmt(n)}{i > 0 && <span className="ml-2 text-[11px]">({pctOf(n, prev)} of the step before)</span>}</span></div>
                <div className="h-2.5 rounded-full bg-surface overflow-hidden"><div className="h-full rounded-full" style={{ width: `${(n / fmax) * 100}%`, background: 'linear-gradient(90deg,#2dd4bf,#818cf8)' }} /></div>
              </div>
            )
          })}
          <p className="text-[12.5px] mt-1 pt-3 border-t border-border/40">
            <span className="font-mono">One-click install clicks</span> <span className="tabular-nums font-semibold">{fmt(f.installs)}</span>
            <span className="text-text-muted"> — shown on its own, not as a step: an install click doesn't come after a claim (people install without claiming anything).</span>
          </p>
        </div>
      </Section>

      <div className="grid md:grid-cols-2 gap-4">
        <Section title="Answers for community-scanned repos" scope={`Right now · the ${fmt(communityTotal)} repos people have scanned on demand`} note="Not the whole catalog: the full catalog's answer mix is in Growth. The three-phrase answer each tool leads with, then the trust tiers underneath as detail.">
          <div className="glass rounded-2xl p-5 flex flex-col gap-2">
            {/* The headline: Safe to connect / Review before you connect / Do not connect
                (metrics_dashboard_router._DECISION_CASE, from the stored critical/high counts + score). */}
            {DECISIONS.map((d) => {
              const n = decisions[d.value] ?? 0
              const tot = communityTotal || 1
              return <div key={d.value} className="flex items-center gap-3 text-[13px]"><span className="w-[12rem] shrink-0 flex items-center gap-2"><span className="inline-block w-2 h-2 rounded-full" style={{ background: d.color }} /><span className="font-semibold">{d.phrase}</span></span><div className="flex-1 h-2 rounded-full bg-surface overflow-hidden"><div className="h-full" style={{ width: `${(n / tot) * 100}%`, background: d.color }} /></div><span className="tabular-nums text-text-muted w-16 text-right">{fmt(n)}</span></div>
            })}
            <div className="mt-2 font-mono text-[10.5px] uppercase tracking-wide text-text-muted">Trust tiers (detail)</div>
            {/* One bucket per tier, keyed by the API's trust_tier value — the same six floors
                as getTrustTier / src/trust_tiers.py (metrics_dashboard_router._TIER_CASE). */}
            {TRUST_TIERS.map((t, i) => {
              const top = i === 0 ? 100 : TRUST_TIERS[i - 1].min - 1
              const n = grades[t.value] ?? 0
              const tot = Object.values(grades).reduce((a, b) => a + b, 0) || 1
              return <div key={t.value} className="flex items-center gap-3 text-[13px]"><span className="w-[7.5rem] shrink-0 flex items-center gap-2"><span className="inline-block w-2 h-2 rounded-full" style={{ background: t.color }} /><span className="font-semibold">{t.name}</span><span className="font-mono tabular-nums text-text-muted text-[11.5px]">{t.min}–{top}</span></span><div className="flex-1 h-2 rounded-full bg-surface overflow-hidden"><div className="h-full" style={{ width: `${(n / tot) * 100}%`, background: t.color }} /></div><span className="tabular-nums text-text-muted w-16 text-right">{fmt(n)}</span></div>
            })}
          </div>
        </Section>
        <Section title="Badges in READMEs" scope="All time" note="Proof of adoption, and the warmest list for re-outreach. Count = times the badge was shown.">
          <div className="glass rounded-2xl p-5">
            {board.length ? <div className="flex flex-col divide-y divide-border/40">{board.slice(0, 10).map((r) => (<div key={r.repo} className="flex justify-between py-1.5 text-[12.5px]"><a href={`https://github.com/${r.repo}`} target="_blank" rel="noopener" className="font-mono text-text hover:text-primary-light truncate">{r.repo}</a><span className="font-mono tabular-nums text-text-muted ml-3">{fmt(r.renders)}</span></div>))}</div> : <p className="text-text-muted text-[13px]">No README renders yet.</p>}
          </div>
        </Section>
      </div>

      <Section title="Catalog risk" scope="Right now" note="Share of scanned tools carrying a high or critical finding: the headline safety signal (and content angle).">
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <Stat label="Flagged (high/critical)" value={flagged.data?.pct != null ? `${flagged.data.pct}%` : '—'} sub={`${fmt(flagged.data?.flagged)} of ${fmt(flagged.data?.scanned)}`} />
        </div>
        <p className="mt-2 text-[11.5px] text-text-muted/70">A breakdown by finding category (which kinds are most common) needs category tallies stored on each scan: not built yet.</p>
      </Section>

      <Section title="Catalog by surface" scope="Right now" note="Launch catalog plus community scans. x402 listings are left out, as on the site; they have their own panel below.">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Object.entries(surfaces).filter(([k]) => k !== 'x402').sort((a, b) => b[1] - a[1]).map(([k, v]) => <Stat key={k} label={k} value={fmt(v)} />)}
        </div>
      </Section>

      <Section title="x402 listings" scope="Right now" note="Paid x402 endpoints, scored from their public Bazaar listing alone (never the code). Kept out of every catalog total. The answer mix covers listings the site shows; testnet-only listings can't take real payment and are hidden from default views.">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <Stat label="Listings" value={fmt(data?.x402?.listings)} />
          <Stat label="Scored" value={fmt(data?.x402?.scored)} />
          {DECISIONS.map((d) => <Stat key={d.value} label={d.phrase} value={fmt(data?.x402?.answers?.[d.value])} />)}
          <Stat label="Testnet (hidden)" value={fmt(data?.x402?.testnet_hidden)} />
        </div>
      </Section>

      {isAdmin && <AdminAccessPanel />}
    </>
  )
}

// ── MARKETING TAB ──────────────────────────────────────────────────────────
function DraftCard({ d, onDone }: { d: Draft; onDone: () => void }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(d.content)
  const [postedUrl, setPostedUrl] = useState('')
  const [showPosted, setShowPosted] = useState(false)
  const manual = ['reddit', 'hackernews', 'producthunt', 'linkedin'].includes(d.platform)
  const act = useMutation({
    mutationFn: (body: { action: string; content?: string; posted_url?: string }) => api.post(`/admin/marketing/drafts/${d.id}`, body),
    onSuccess: onDone,
  })
  const slopCheck = useMutation<{ passed: boolean; reasons: string[]; hint: string }>({
    mutationFn: async () => (await api.post('/admin/marketing/check-slop', { content: text, platform: d.platform })).data,
  })
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted mb-2">
        <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{d.platform}</span>
        {d.post_type === 'reactive' && <span className="px-1.5 py-0.5 rounded bg-warning/15 text-warning">reply</span>}
        {d.topic && <span>{d.topic}</span>}
        <span className="ml-auto">{ago(d.created_at)} ago · {d.status}</span>
      </div>
      {editing
        ? <textarea value={text} onChange={(e) => setText(e.target.value)} rows={5} className="w-full text-[13px] rounded-lg bg-surface border border-border p-2 font-mono" />
        : <p className="text-[13px] text-text whitespace-pre-wrap">{d.content}</p>}
      {showPosted && <input value={postedUrl} onChange={(e) => setPostedUrl(e.target.value)} placeholder="URL where you posted it (optional)" className="mt-2 w-full text-[12.5px] rounded-lg bg-surface border border-border px-2 py-1.5" />}
      <div className="mt-3 flex gap-2 flex-wrap text-[12.5px] font-semibold">
        {editing ? (
          <>
            <button onClick={() => act.mutate({ action: 'edit_approve', content: text })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Save &amp; {manual ? 'keep' : 'post'}</button>
            <button onClick={() => slopCheck.mutate()} disabled={slopCheck.isPending} className="px-3 py-1.5 rounded-lg border border-primary/50 text-primary-light disabled:opacity-60">{slopCheck.isPending ? 'Checking…' : 'Check for slop'}</button>
            <button onClick={() => setEditing(false)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Cancel</button>
          </>
        ) : manual ? (
          <>
            {showPosted
              ? <button onClick={() => act.mutate({ action: 'mark_posted', posted_url: postedUrl || undefined })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-success to-primary disabled:opacity-60">Confirm posted</button>
              : <button onClick={() => setShowPosted(true)} className="px-3 py-1.5 rounded-lg border border-primary/50 text-primary-light">I posted this</button>}
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Edit</button>
            <button onClick={() => act.mutate({ action: 'reject' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-danger">Reject</button>
          </>
        ) : (
          <>
            <button onClick={() => act.mutate({ action: 'approve' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Approve &amp; post</button>
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Edit</button>
            <button onClick={() => act.mutate({ action: 'reject' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-danger">Reject</button>
          </>
        )}
      </div>
      {slopCheck.data && (
        slopCheck.data.passed
          ? <p className="mt-2 text-[12.5px] text-success">✓ No-slop check passed — reads clean.</p>
          : <p className="mt-2 text-[12.5px] text-warning">⚠ Slop detected: {slopCheck.data.hint || slopCheck.data.reasons.join(', ')}</p>
      )}
      {act.isError && <p className="mt-2 text-[12px] text-danger">Action failed — try again.</p>}
    </div>
  )
}

function PlannedCard({ d, onDone }: { d: Draft; onDone: () => void }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(d.content)
  const day = (d as Draft & { scheduled_day?: string }).scheduled_day
  const act = useMutation({
    mutationFn: () => api.post(`/admin/marketing/drafts/${d.id}`, { action: 'edit', content: text }),
    onSuccess: () => { setEditing(false); onDone() },
  })
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted">
        <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{d.platform}</span>
        {day && <span>📅 {day}</span>}
        {d.topic && <span>{d.topic}</span>}
        {!editing && <button onClick={() => setEditing(true)} className="ml-auto text-primary-light hover:text-primary font-semibold">edit</button>}
      </div>
      {editing ? (
        <>
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={5} className="mt-2 w-full text-[13px] rounded-lg bg-surface border border-border p-2 font-mono" />
          <div className="mt-2 flex gap-2 text-[12.5px] font-semibold">
            <button onClick={() => act.mutate()} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Save</button>
            <button onClick={() => { setEditing(false); setText(d.content) }} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Cancel</button>
          </div>
        </>
      ) : <p className="mt-2 text-[12.5px] text-text-muted whitespace-pre-wrap">{d.content.slice(0, 220)}{d.content.length > 220 ? '…' : ''}</p>}
    </div>
  )
}

function MarketingTab() {
  const qc = useQueryClient()
  const invalidate = () => { ['admin-mkt-drafts', 'admin-mkt-planned', 'admin-mkt-dash', 'admin-mkt-reply-considering', 'admin-mkt-reply-sent'].forEach((k) => qc.invalidateQueries({ queryKey: [k] })) }
  const health = useQuery<Health>({ queryKey: ['admin-mkt-health'], queryFn: async () => (await api.get('/admin/marketing/health')).data })
  const dash = useQuery<MktDash>({ queryKey: ['admin-mkt-dash'], queryFn: async () => (await api.get('/admin/marketing/dashboard')).data })
  // Queue 1: things I must post by hand (human_review). Queue 2: scheduled campaign posts (planned).
  const manual = useQuery<Draft[]>({ queryKey: ['admin-mkt-drafts'], queryFn: async () => (await api.get('/admin/marketing/drafts', { params: { status: 'human_review,draft', limit: 40 } })).data })
  const planned = useQuery<Draft[]>({ queryKey: ['admin-mkt-planned'], queryFn: async () => (await api.get('/admin/marketing/drafts', { params: { status: 'planned', limit: 60 } })).data })
  const campaigns = useQuery<Campaign[]>({ queryKey: ['admin-mkt-campaigns'], queryFn: async () => { try { return (await api.get('/admin/marketing/campaigns/proposed')).data } catch { return [] } } })
  const reply = useQuery<ReplyStats>({ queryKey: ['admin-mkt-reply'], queryFn: async () => (await api.get('/admin/engagement/stats')).data })
  const evalQ = useQuery<Eval>({ queryKey: ['admin-mkt-eval'], queryFn: async () => (await api.get('/admin/marketing/eval')).data })
  const slop = useQuery<{ proposals: { phrase: string; reason: string }[] }>({ queryKey: ['admin-mkt-slop'], queryFn: async () => (await api.get('/admin/marketing/slop-proposals')).data })
  const targetPerf = useQuery<TargetPerf>({ queryKey: ['admin-mkt-target-perf'], queryFn: async () => { try { return (await api.get('/admin/engagement/target-performance')).data } catch { return {} } } })
  const slopAct = useMutation({ mutationFn: (b: { phrase: string; action: string }) => api.post('/admin/marketing/slop-proposals/action', b), onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-mkt-slop'] }) })
  // Queue 3: replies it's considering next (drafted). Feed: replies already sent.
  // Sorted by urgency (default) — the ones it'll try to post first.
  const considering = useQuery<{ items: ReplyRow[] }>({ queryKey: ['admin-mkt-reply-considering'], queryFn: async () => (await api.get('/admin/engagement/queue', { params: { status: 'drafted', limit: 20 } })).data })
  const replySent = useQuery<{ items: ReplyRow[] }>({ queryKey: ['admin-mkt-reply-sent'], queryFn: async () => (await api.get('/admin/engagement/queue', { params: { status: 'posted', sort: 'recent', limit: 20 } })).data })
  const [replyView, setReplyView] = useState<'considering' | 'sent'>('considering')
  const byDate = <T extends { created_at?: string; posted_at?: string | null; drafted_at?: string | null }>(a: T[]) => [...a].sort((x, y) => new Date(y.posted_at || y.drafted_at || y.created_at || 0).getTime() - new Date(x.posted_at || x.drafted_at || x.created_at || 0).getTime())

  const genCampaign = useMutation({ mutationFn: () => api.post('/admin/marketing/campaigns/generate', {}, { timeout: 120_000 }), onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-mkt-campaigns'] }) })
  const trigger = useMutation({ mutationFn: () => api.post('/admin/marketing/trigger', {}), onSuccess: invalidate })

  const h = health.data
  const eng = dash.data?.engagement
  const cost = dash.data?.cost
  const rc = reply.data?.status_counts || {}

  return (
    <>
      <Section title="Health & spend" right={<button onClick={() => trigger.mutate()} disabled={trigger.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg border border-primary/50 text-primary-light disabled:opacity-60">{trigger.isPending ? 'Running…' : 'Trigger marketing tick'}</button>}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Stat label="Engine" value={h?.marketing_enabled ? 'On' : 'Off'} sub={h?.anthropic_configured ? 'Anthropic ✓' : 'no key'} />
          <Stat label="Spend today" value={usd(cost?.daily_spend_usd ?? h?.daily_spend_usd)} />
          <Stat label="Spend this month" value={usd(cost?.monthly_spend_usd ?? h?.monthly_spend_usd)} sub="all LLM usage" />
          <Stat label="Engagement (7d)" value={fmt((eng?.total_likes ?? 0) + (eng?.total_comments ?? 0) + (eng?.total_shares ?? 0))} sub={`${fmt(eng?.total_impressions)} impressions`} />
        </div>
        {cost?.breakdown?.length ? (
          <div className="glass rounded-2xl p-4 mt-3 overflow-x-auto">
            <div className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-1">LLM cost by model (attributed)</div>
            <table className="w-full text-[12.5px]"><tbody>{cost.breakdown.map((b) => <tr key={b.model} className="border-t border-border/40"><td className="py-1 font-mono">{b.model}</td><td className="py-1 tabular-nums text-right text-text-muted">{fmt(b.calls)} calls</td><td className="py-1 tabular-nums text-right">{usd(b.cost_usd)}</td></tr>)}</tbody></table>
            <p className="text-[11px] text-text-muted/60 mt-1">Note: the monthly figure counts all LLM usage (incl. reply-guy drafts); this table is only spend attributed to stored posts — the two differ until cost tracking is unified.</p>
          </div>
        ) : null}
      </Section>

      <Section title="Learning-loop eval" note="Is the self-tuning actually working? Engagement trend, no-slop first-pass rate, reply engagement — plus alerts.">
        {!!evalQ.data?.alerts?.length && (
          <div className="flex flex-col gap-2 mb-3">
            {evalQ.data.alerts.map((a, i) => (
              <div key={i} className={`glass rounded-xl p-3 text-[13px] border-l-4 ${a.level === 'warn' ? 'border-warning/70' : 'border-primary/50'}`}>
                <div className={a.level === 'warn' ? 'text-warning' : 'text-text-muted'}>{a.level === 'warn' ? '⚠ ' : 'ℹ '}{a.message}</div>
                {a.action && <div className="mt-1 text-[12.5px] text-text">→ {a.action}</div>}
              </div>
            ))}
          </div>
        )}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Stat label="Engagement / post (7d)" value={fmt(evalQ.data?.engagement_per_post_7d)} sub={evalQ.data?.trend_pct != null ? `${evalQ.data.trend_pct > 0 ? '▲' : '▼'} ${Math.abs(evalQ.data.trend_pct)}% vs 30d` : `${fmt(evalQ.data?.engagement_per_post_30d)}/post (30d)`} />
          <Stat label="No-slop first-pass" value={evalQ.data?.slop_pass_rate_7d != null ? `${Math.round(evalQ.data.slop_pass_rate_7d * 100)}%` : '—'} sub="clean on first draft" />
          <Stat label="Reply engagement (7d)" value={fmt(evalQ.data?.reply_engagement_per_post_7d)} sub="per reply" />
          <Stat label="Posts measured (7d)" value={fmt(evalQ.data?.posts_7d)} />
        </div>
      </Section>

      <Section title="Engagement by platform" note="Average engagement per post, by channel (30d) — which platforms earn their keep.">
        {evalQ.data?.by_platform?.length ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {evalQ.data.by_platform.map((b) => <Stat key={b.platform} label={b.platform} value={b.eng_per_post} sub={`${fmt(b.posts)} posts · ${fmt(b.total)} total`} />)}
          </div>
        ) : <p className="text-text-muted text-[13px]">Not enough posts with engagement data yet.</p>}
      </Section>

      {!!slop.data?.proposals?.length && (
        <Section title="No-slop — phrases to review" note="Learned from your edits + model proposals. Approve to add to the blocklist (bans it from future copy), or reject.">
          <div className="flex flex-col gap-2">
            {slop.data.proposals.map((p) => (
              <div key={p.phrase} className="glass rounded-xl p-3 flex items-center gap-3 flex-wrap">
                <span className="font-mono text-[13px] text-text">"{p.phrase}"</span>
                <span className="text-[11.5px] text-text-muted/70">{p.reason}</span>
                <div className="ml-auto flex gap-2 text-[12.5px] font-semibold">
                  <button onClick={() => slopAct.mutate({ phrase: p.phrase, action: 'approve' })} className="px-3 py-1 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark">Ban it</button>
                  <button onClick={() => slopAct.mutate({ phrase: p.phrase, action: 'reject' })} className="px-3 py-1 rounded-lg border border-border text-text-muted">Keep allowed</button>
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      <RecentPostsCard posts={dash.data?.recent_posts || []} />

      {(() => {
        const posts = dash.data?.recent_posts || []
        const scored = posts.map((p) => ({ p, e: (p.metrics?.likes || 0) + (p.metrics?.comments || 0) + (p.metrics?.shares || 0) })).filter((x) => x.e > 0).sort((a, b) => b.e - a.e)
        if (!scored.length) return null
        const top = scored[0]
        return (
          <Reveal><div className="mt-6 glass rounded-2xl p-5 border-l-4 border-success/60">
            <div className="text-[12px] font-mono uppercase tracking-wide text-text-muted">What's working 💡</div>
            <p className="mt-1.5 text-[13.5px]">Best-performing recent post ({top.e} engagements) on <span className="font-mono">{top.p.platform}</span>{top.p.url && <> — <a href={top.p.url} target="_blank" rel="noopener" className="text-primary-light hover:text-primary">open ↗</a></>}: <span className="text-text-muted">"{top.p.content.slice(0, 120)}…"</span></p>
            <p className="mt-1 text-[11.5px] text-text-muted/70">The engine can weight future posts toward what earns engagement — closed-loop self-tuning is the next step (staged).</p>
          </div></Reveal>
        )
      })()}

      <Section title="Weekly campaign planner" note="Generate a week of posts, review, approve or reject. Approved posts land in the draft queue below." right={<button onClick={() => genCampaign.mutate()} disabled={genCampaign.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{genCampaign.isPending ? 'Generating…' : 'Generate weekly plan'}</button>}>
        {campaigns.data?.length ? (
          <div className="flex flex-col gap-2">
            {campaigns.data.map((c) => (
              <div key={c.id} className="glass rounded-xl p-4 flex items-center justify-between gap-3 flex-wrap">
                <div><div className="font-semibold text-[14px]">{c.name}</div><div className="text-[12px] text-text-muted font-mono">{c.platforms?.join(' · ')} · {c.status}{c.start_date ? ` · starts ${c.start_date}` : ''}</div></div>
                <div className="flex gap-2 text-[12.5px] font-semibold">
                  <CampaignActions id={c.id} onDone={() => qc.invalidateQueries({ queryKey: ['admin-mkt-campaigns'] })} />
                </div>
              </div>
            ))}
          </div>
        ) : <p className="text-text-muted text-[13px]">No proposed campaigns. Generate a weekly plan to review one.</p>}
      </Section>

      <Section title="Queue 1 · To post by hand" note="Drafts on manual-post platforms (LinkedIn/Reddit/HN/Product Hunt) awaiting you — edit, mark posted, or reject. Newest first.">
        {(() => { const q = byDate((manual.data || []).filter((d) => ['linkedin', 'reddit', 'hackernews', 'producthunt'].includes(d.platform))); return q.length ? <div className="flex flex-col gap-2">{q.map((d) => <DraftCard key={d.id} d={d} onDone={invalidate} />)}</div> : <p className="text-text-muted text-[13px]">Nothing to post by hand right now.</p> })()}
      </Section>

      <Section title="Queue 2 · Scheduled this week" note="What the weekly campaign will auto-post, and when. You'll likely never touch it — but you can edit any post here.">
        {byDate(planned.data || []).length ? (
          <div className="flex flex-col gap-2">
            {byDate(planned.data || []).map((d) => <PlannedCard key={d.id} d={d} onDone={invalidate} />)}
          </div>
        ) : <p className="text-text-muted text-[13px]">No scheduled campaign posts. Generate a weekly plan above.</p>}
      </Section>

      <Section title="Reply-guy" note="Your best engagement channel — replies average far more traction than broadcasts.">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
          <Stat label="Posted today" value={fmt(reply.data?.posted_today)} />
          <Stat label="Active targets" value={fmt(reply.data?.active_targets)} />
          <Stat label="Considering" value={fmt(reply.data?.queue_size)} sub="drafted+new" />
          <Stat label="Sent (all-time)" value={fmt(rc.posted)} sub={`${fmt(rc.posting_error)} errors`} />
        </div>
        {!!targetPerf.data?.targets?.length && (
          <div className="glass rounded-2xl p-4 mb-3 overflow-x-auto">
            <div className="text-[12px] font-mono uppercase tracking-wide text-text-muted mb-2">Top targets by reply engagement — double down on these</div>
            <table className="w-full text-[12.5px]">
              <thead><tr className="text-text-muted/70 text-left font-mono"><th className="py-1 pr-3">target</th><th className="py-1 pr-3 text-right">replies</th><th className="py-1 pr-3 text-right">avg ♥</th><th className="py-1 text-right">total ♥</th></tr></thead>
              <tbody>
                {targetPerf.data.targets.slice(0, 8).map((t) => (
                  <tr key={`${t.platform}:${t.handle}`} className="border-t border-border/40">
                    <td className="py-1.5 pr-3 font-mono">{t.platform} @{t.handle}</td>
                    <td className="py-1.5 pr-3 tabular-nums text-right">{fmt(t.replies)}</td>
                    <td className="py-1.5 pr-3 tabular-nums text-right">{t.avg_engagement}</td>
                    <td className="py-1.5 tabular-nums text-right text-text-muted">{fmt(t.total_engagement)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex gap-1 border-b border-border/60 mb-3">
          {([['considering', 'Considering next'], ['sent', 'Sent']] as const).map(([k, lbl]) => (
            <button key={k} onClick={() => setReplyView(k)} className={`px-3.5 py-1.5 text-[13px] font-semibold border-b-2 -mb-px transition-colors ${replyView === k ? 'border-primary text-text' : 'border-transparent text-text-muted hover:text-text'}`}>{lbl}</button>
          ))}
        </div>
        {replyView === 'considering' ? (
          <>
            <p className="text-[12.5px] text-text-muted mb-2">Most-urgent first (what it'll try next). Each fades after 48h — edit, or post now.</p>
            {considering.data?.items?.length ? <div className="flex flex-col gap-2">{considering.data.items.map((r) => <ReplyConsideringCard key={r.id} r={r} onDone={invalidate} />)}</div> : <p className="text-text-muted text-[13px]">Nothing queued to reply to right now.</p>}
          </>
        ) : (
          <>
            {replySent.data?.items?.length ? (
              <div className="glass rounded-2xl p-4 overflow-x-auto">
                <table className="w-full text-[12.5px]">
                  <thead><tr className="text-text-muted/70 text-left font-mono"><th className="py-1 pr-3">when</th><th className="py-1 pr-3">platform</th><th className="py-1 pr-3">reply</th><th className="py-1 pr-2 text-right">♥</th><th className="py-1 text-right">link</th></tr></thead>
                  <tbody>{replySent.data.items.map((r) => (
                    <tr key={r.id} className="border-t border-border/40">
                      <td className="py-1.5 pr-3 text-text-muted whitespace-nowrap">{ago(r.posted_at)}</td>
                      <td className="py-1.5 pr-3 font-mono">{r.platform}{r.target?.handle && <span className="text-text-muted/60"> @{r.target.handle}</span>}</td>
                      <td className="py-1.5 pr-3 text-text-muted max-w-[360px] truncate">{r.draft_content || r.post_uri}</td>
                      <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(r.engagement_count)}</td>
                      <td className="py-1.5 text-right">{(r.reply_url || r.post_uri) ? <a href={r.reply_url || r.post_uri} target="_blank" rel="noopener" className="text-primary-light hover:text-primary">{r.reply_url ? 'reply ↗' : 'thread ↗'}</a> : '—'}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ) : <p className="text-text-muted text-[13px]">No replies sent yet.</p>}
            <div className="mt-2 text-[12.5px]"><Link to={rp('/rebrand/admin-replies')} className="text-primary-light hover:text-primary font-semibold">View all replies — sort & search →</Link></div>
          </>
        )}
      </Section>

    </>
  )
}

function RecentPostsCard({ posts }: { posts: NonNullable<MktDash['recent_posts']> }) {
  return (
    <Section title="Recent posts" note="Your manual + weekly-campaign posts, newest first — click any to open, with engagement.">
      {posts.length ? (
        <>
          <div className="glass rounded-2xl p-4 overflow-x-auto">
            <table className="w-full text-[12.5px]">
              <thead><tr className="text-text-muted/70 text-left font-mono"><th className="py-1 pr-3">when</th><th className="py-1 pr-3">platform</th><th className="py-1 pr-3">post</th><th className="py-1 pr-2 text-right">♥</th><th className="py-1 pr-2 text-right">💬</th><th className="py-1 pr-2 text-right">🔁</th><th className="py-1 pr-2 text-right">👁</th><th className="py-1 text-right">cost</th></tr></thead>
              <tbody>{[...posts].sort((a, b) => new Date(b.posted_at || 0).getTime() - new Date(a.posted_at || 0).getTime()).slice(0, 15).map((p) => (
                <tr key={p.id} className="border-t border-border/40">
                  <td className="py-1.5 pr-3 text-text-muted whitespace-nowrap">{ago(p.posted_at)}</td>
                  <td className="py-1.5 pr-3 font-mono">{p.platform}</td>
                  <td className="py-1.5 pr-3 text-text-muted max-w-[360px] truncate">{p.url ? <a href={p.url} target="_blank" rel="noopener" className="hover:text-primary-light">{p.content.slice(0, 90)} ↗</a> : p.content.slice(0, 90)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(p.metrics?.likes)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(p.metrics?.comments)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right">{fmt(p.metrics?.shares)}</td>
                  <td className="py-1.5 pr-2 tabular-nums text-right text-text-muted">{fmt(p.metrics?.impressions)}</td>
                  <td className="py-1.5 tabular-nums text-right text-text-muted">{usd(p.llm_cost_usd)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="mt-2 text-[12.5px]"><Link to={rp('/rebrand/admin-posts')} className="text-primary-light hover:text-primary font-semibold">View all posts — sort & search →</Link></div>
        </>
      ) : <p className="text-text-muted text-[13px]">No recent posts.</p>}
    </Section>
  )
}

function ReplyConsideringCard({ r, onDone }: { r: ReplyRow; onDone: () => void }) {
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(r.draft_content || '')
  const act = useMutation({
    mutationFn: (body: { action: string; draft_content?: string }) => api.post(`/admin/engagement/queue/${r.id}/action`, body),
    onSuccess: onDone,
  })
  const ageH = r.drafted_at ? (Date.now() - new Date(r.drafted_at).getTime()) / 3.6e6 : 0
  const leftH = Math.max(0, REPLY_TTL_H - ageH)
  return (
    <div className="glass rounded-xl p-4">
      <div className="flex items-center gap-2 text-[11.5px] font-mono text-text-muted mb-2">
        <span className="px-1.5 py-0.5 rounded bg-primary/15 text-primary-light">{r.platform}</span>
        {r.target?.handle && <span>@{r.target.handle}</span>}
        {!!r.target?.follower_count && <span>{fmt(r.target.follower_count)} followers</span>}
        {!!r.engagement_count && <span title="likes on the thread being replied to">🧵 ♥ {fmt(r.engagement_count)}</span>}
        {typeof r.urgency_score === 'number' && <span title="thread heat: recency × audience × engagement">🔥 {r.urgency_score.toFixed(1)}</span>}
        {r.post_uri && <a href={r.post_uri} target="_blank" rel="noopener" className="hover:text-primary-light">the thread ↗</a>}
        <span className={`ml-auto ${leftH < 6 ? 'text-warning' : ''}`}>fades in {Math.round(leftH)}h · posts next 14:00-UTC window</span>
      </div>
      {editing
        ? <textarea value={text} onChange={(e) => setText(e.target.value)} rows={3} className="w-full text-[13px] rounded-lg bg-surface border border-border p-2 font-mono" />
        : <p className="text-[13px] text-text whitespace-pre-wrap">{r.draft_content}</p>}
      <div className="mt-3 flex gap-2 flex-wrap text-[12.5px] font-semibold">
        {editing ? (
          <>
            <button onClick={() => { act.mutate({ action: 'edit', draft_content: text }); setEditing(false) }} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark">Save</button>
            <button onClick={() => setEditing(false)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Cancel</button>
          </>
        ) : (
          <>
            <button onClick={() => act.mutate({ action: 'approve' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-success to-primary disabled:opacity-60">Post it now</button>
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Edit</button>
            <button onClick={() => act.mutate({ action: 'skip' })} disabled={act.isPending} className="px-3 py-1.5 rounded-lg border border-border text-text-muted hover:text-danger">Skip</button>
          </>
        )}
      </div>
    </div>
  )
}

function CampaignActions({ id, onDone }: { id: string; onDone: () => void }) {
  const [rejecting, setRejecting] = useState(false)
  const [fb, setFb] = useState('')
  const approve = useMutation({ mutationFn: () => api.post(`/admin/marketing/campaigns/${id}/approve`, {}), onSuccess: onDone })
  const reject = useMutation({ mutationFn: () => api.post(`/admin/marketing/campaigns/${id}/reject`, { feedback: fb }), onSuccess: onDone })
  if (rejecting) return (
    <div className="flex gap-2 items-center">
      <input value={fb} onChange={(e) => setFb(e.target.value)} placeholder="why?" className="text-[12px] rounded-lg bg-surface border border-border px-2 py-1" />
      <button onClick={() => reject.mutate()} disabled={reject.isPending} className="px-3 py-1.5 rounded-lg border border-border text-danger">Confirm</button>
    </div>
  )
  return (
    <>
      <button onClick={() => approve.mutate()} disabled={approve.isPending} className="px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">Approve</button>
      <button onClick={() => setRejecting(true)} className="px-3 py-1.5 rounded-lg border border-border text-text-muted">Reject</button>
    </>
  )
}

// ── SHELL ────────────────────────────────────────────────────────────────
interface RadarItem {
  full_name: string; owner: string; repo: string; stars?: number; framework?: string
  trust_score?: number; certified?: boolean; critical?: number; high?: number
  has_shields?: boolean; priority?: number; channel?: string; angle?: string
  badge_ask?: boolean; score_url?: string; draft?: string; top_finding?: string
}

// Curator targets — one relationship → many placements. Static (from dev-first-adopter-list.md).
const CURATORS: [string, string, string][] = [
  ['Puliczek/awesome-mcp-security', '729★', 'tightest fit — an MCP *security* list; approach first'],
  ['rohitg00/awesome-devops-mcp-servers', '1k★', 'niche/reachable — PR under tooling/security'],
  ['wong2/awesome-mcp-servers', '4.3k★', 'reachable — same PR play'],
  ['appcypher/awesome-mcp-servers', '5.7k★', 'reachable — same'],
  ['punkpeye/awesome-mcp-servers', '92k★', 'canonical, hardest — approach LAST, after a win or two'],
]

function RadarRow({ it }: { it: RadarItem }) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const copy = () => { if (it.draft && navigator.clipboard) { navigator.clipboard.writeText(it.draft); setCopied(true); setTimeout(() => setCopied(false), 1400) } }
  return (
    <div className="glass rounded-xl px-4 py-3">
      <div className="flex items-center gap-2.5 flex-wrap">
        <span className="font-mono text-[10.5px] font-bold tabular-nums w-9 text-primary-light">{it.priority ?? '—'}</span>
        <a href={it.score_url || `https://agentavow.com/check/${it.full_name}`} target="_blank" rel="noopener noreferrer" className="font-mono text-[13.5px] font-semibold text-text hover:text-primary-light truncate">{it.full_name}</a>
        {it.certified
          ? <span className="font-mono text-[10px] font-extrabold px-1.5 py-0.5 rounded-full" style={{ background: 'linear-gradient(120deg,#2dd4bf,#e879f9)', color: '#06231f' }}>✓ CERT {it.trust_score}</span>
          : <span className="font-mono text-[10.5px] px-1.5 py-0.5 rounded bg-surface border border-border/60 text-text-muted">{it.trust_score ?? '—'}/100</span>}
        {it.badge_ask
          ? <span className="text-[10px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded bg-success/10 text-success">badge ask</span>
          : <span className="text-[10px] font-mono uppercase tracking-wide px-1.5 py-0.5 rounded bg-warning/10 text-warning">fix-first</span>}
        {it.has_shields && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-border/60 text-text-muted">shields ✓</span>}
        <span className="text-[11px] text-text-muted/70 ml-auto">★{it.stars ?? 0}{it.framework ? ` · ${it.framework}` : ''}</span>
      </div>
      {it.channel && <p className="text-[12.5px] text-text-muted mt-1.5">{it.channel}</p>}
      {it.draft && (
        <div className="mt-1.5">
          <button onClick={() => setOpen(!open)} className="text-[12px] font-semibold text-primary-light hover:text-primary">{open ? 'Hide draft' : 'Show draft'} →</button>
          {open && (
            <div className="mt-2 relative">
              <p className="text-[12.5px] text-text bg-surface border border-border rounded-lg p-3 pr-16 whitespace-pre-wrap leading-relaxed">{it.draft}</p>
              <button onClick={copy} className="absolute top-2 right-2 font-mono text-[11px] px-2 py-1 rounded-md bg-surface-hover border border-border text-text-muted hover:text-primary-light">{copied ? 'copied ✓' : 'copy'}</button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function RadarTab() {
  const qc = useQueryClient()
  const queue = useQuery<{ queue: RadarItem[]; total: number }>({
    queryKey: ['radar-queue'],
    queryFn: async () => (await api.get('/admin/recruitment/radar/queue', { params: { limit: 100 } })).data,
  })
  const run = useMutation({
    mutationFn: () => api.post('/admin/recruitment/radar/run', null, { params: { limit: 25 } }),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['radar-queue'] }), 4000),
  })
  const items = queue.data?.queue ?? []
  return (
    <div className="mt-6">
      <Section
        title="Developer radar — outreach queue"
        note="Discovers MCP/agent repos, scans + ranks them into a personal outreach list. Human-gated — it never contacts anyone. Send the top ones yourself, a few a day."
        right={<button onClick={() => run.mutate()} disabled={run.isPending} className="text-[12.5px] font-semibold px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">{run.isPending ? 'Started…' : 'Run radar'}</button>}
      >
        {run.isSuccess && <p className="text-[12.5px] text-text-muted mb-3">Radar running in the background — the queue refreshes in a few seconds (a full cycle scans ~25 repos, ~2–4 min).</p>}
        {queue.isLoading && <p className="text-text-muted text-[13px]">Loading queue…</p>}
        {!queue.isLoading && !items.length && <p className="text-text-muted text-[13px]">Queue empty — hit “Run radar” to discover + rank candidates.</p>}
        <div className="flex flex-col gap-2">
          {items.map((it) => <RadarRow key={it.full_name} it={it} />)}
        </div>
      </Section>

      <Section title="Curator targets" note="One relationship → many placements. Awesome-list PRs, ordered by reachability (not size).">
        <div className="flex flex-col gap-2">
          {CURATORS.map(([repo, stars, why]) => (
            <div key={repo} className="glass rounded-xl px-4 py-2.5 flex items-center gap-3 flex-wrap">
              <a href={`https://github.com/${repo}`} target="_blank" rel="noopener noreferrer" className="font-mono text-[13px] font-semibold text-text hover:text-primary-light">{repo}</a>
              <span className="font-mono text-[11px] text-text-muted">{stars}</span>
              <span className="text-[12.5px] text-text-muted ml-auto">{why}</span>
            </div>
          ))}
        </div>
      </Section>
    </div>
  )
}

export default function AdminDashboard() {
  const { isLoading, isAdmin, canView } = useAdminAccess()
  // Tab lives in the URL so browser back/forward restores it.
  const [sp, setSp] = useSearchParams()
  const _t = sp.get('tab')
  const tab: 'metrics' | 'marketing' | 'posts' | 'radar' = _t === 'marketing' ? 'marketing' : _t === 'posts' ? 'posts' : _t === 'radar' ? 'radar' : 'metrics'
  const setTab = (t: 'metrics' | 'marketing' | 'posts' | 'radar') => setSp(t === 'metrics' ? {} : { tab: t })
  // A read-only viewer gets the Metrics tab only (the server 403s everything else).
  const tabs = isAdmin ? (['metrics', 'marketing', 'posts', 'radar'] as const) : (['metrics'] as const)

  if (isLoading) return <div className="max-w-[1080px] mx-auto px-6 py-24 text-center text-text-muted">Loading…</div>
  if (!canView) return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      <h1 className="text-2xl font-extrabold tracking-tight">Admins only</h1>
      <p className="mt-3 text-text-muted text-[14px]">This dashboard is restricted. <Link to={rp('/rebrand')} className="text-primary-light hover:text-primary font-semibold">← Back home</Link></p>
    </div>
  )

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <Reveal>
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <div>
            <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Operations</span>
            <h1 className="mt-2 text-3xl md:text-4xl font-extrabold tracking-tight">Admin dashboard</h1>
          </div>
          {isAdmin
            ? <a href="/admin" className="text-[12.5px] text-text-muted hover:text-text font-semibold">Legacy admin ↗</a>
            : <span className="text-[12.5px] font-mono px-2.5 py-1 rounded-lg border border-border/60 text-text-muted">View-only access</span>}
        </div>
        <div className="mt-6 flex gap-1 border-b border-border/60">
          {tabs.map((t) => (
            <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 text-[14px] font-semibold capitalize border-b-2 -mb-px transition-colors ${tab === t ? 'border-primary text-text' : 'border-transparent text-text-muted hover:text-text'}`}>{t === 'radar' ? 'Dev radar' : t}</button>
          ))}
        </div>
      </Reveal>
      {tab === 'metrics' ? <MetricsTab /> : !isAdmin ? <ViewOnlyNotice /> : tab === 'marketing' ? <MarketingTab /> : tab === 'posts' ? <PostStudioTab /> : <RadarTab />}
    </div>
  )
}
