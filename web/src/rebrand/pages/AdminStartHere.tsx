/** The five numbers to read first on the admin dashboard, in plain English. Everything
 * else on the Metrics tab stays below this panel. */
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'

import api from '../../lib/api'
import { liveListings, pendingListings } from './adminListings'

interface Row {
  day: string
  cc_machines_7d?: number | null; checked_machines_7d?: number | null
  cc_new_machines_30d?: number | null
  d1_cohort?: number | null; d1_returned?: number | null
  d7_cohort?: number | null; d7_returned?: number | null
  calls_claude_code?: number | null; calls_claude?: number | null; calls_chatgpt?: number | null
  checks_total?: number | null; checks_claude_code?: number | null; checks_claude?: number | null
  checks_chatgpt?: number | null; checks_cursor?: number | null; checks_vscode?: number | null
  checks_codex?: number | null
}

const sum = (rows: Row[], pick: (r: Row) => number | null | undefined) =>
  rows.reduce((total, r) => total + (pick(r) ?? 0), 0)

const pct = (num: number, den: number) => (den ? `${Math.round((num / den) * 100)}%` : 'Not ready')

/** Hand-run checks for one day. From the day the checks counter exists (checks_total is
 *  set) it is every real surface minus about_agentavow and owner machines; before that,
 *  the raw tool calls from the three surfaces the snapshot used to keep. */
function handRunChecks(r: Row): number {
  if (r.checks_total != null) {
    return (r.checks_claude_code ?? 0) + (r.checks_claude ?? 0) + (r.checks_chatgpt ?? 0)
      + (r.checks_cursor ?? 0) + (r.checks_vscode ?? 0) + (r.checks_codex ?? 0)
  }
  return (r.calls_claude_code ?? 0) + (r.calls_claude ?? 0) + (r.calls_chatgpt ?? 0)
}

function Card({ label, value, meaning, tip, children }: { label: string; value: string; meaning: string; tip?: string; children?: ReactNode }) {
  return (
    <div className="glass rounded-xl p-4" title={tip}>
      <div className="text-[12.5px] font-semibold text-text-muted">
        {label}{tip && <span className="ml-1 cursor-help text-text-muted/60" aria-label={tip}>ⓘ</span>}
      </div>
      <div className="mt-1 text-2xl font-extrabold tabular-nums">{value}</div>
      <p className="mt-1 text-[12px] text-text-muted">{meaning}</p>
      {children}
    </div>
  )
}

export default function StartHerePanel() {
  const { data } = useQuery<{ rows?: Row[] }>({
    queryKey: ['admin-start-here'],
    queryFn: async () => (await api.get('/admin/metrics/traffic', { params: { days: 14 } })).data,
  })
  const week = (data?.rows || []).slice(-7)
  const latest = week[week.length - 1]
  const protectedMachines = latest?.checked_machines_7d
  const connected = latest?.cc_machines_7d
  const share = protectedMachines != null && connected ? ` of ${connected.toLocaleString()} (${Math.round((protectedMachines / connected) * 100)}%)` : ''
  const d7 = pct(sum(week, (r) => r.d7_returned), sum(week, (r) => r.d7_cohort))
  const d1 = pct(sum(week, (r) => r.d1_returned), sum(week, (r) => r.d1_cohort))
  const calls = sum(week, handRunChecks)
  const firstChecksDay = week.find((r) => r.checks_total != null)?.day
  const live = liveListings()
  const pending = pendingListings()

  return (
    <section className="mt-8">
      <h2 className="text-lg font-bold">Start here</h2>
      <p className="mt-1 text-text-muted text-[13px]">
        The five numbers that matter, for the last 7 days. Higher is better on all of them.
        {latest && <> Latest snapshot: {latest.day}{week.length < 7 ? ` (${week.length} of 7 days on file)` : ''}.</>}
      </p>
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <Card
          label="Claude Code machines protected (7 days)"
          value={protectedMachines != null ? `${protectedMachines.toLocaleString()}${share}` : 'Not ready'}
          meaning="Machines where the Claude Code plugin's session-start or install-time hook checked at least one thing in the last 7 days, out of machines connecting. Full count from Nov 14."
          tip="Owner machines (data/owner-ips.txt on the host) are excluded. Not counted: hand-run checks in claude.ai, ChatGPT, Cursor, VS Code or Codex; the npm and Python gates; CI. Anthropic cloud egress IPs (remote Claude Code sessions) are NOT excluded: no list of them exists yet, so they inflate both the count and the share."
        />
        <Card
          label="New machines"
          value={sum(week, (r) => r.cc_new_machines_30d).toLocaleString()}
          meaning="Claude Code machines connecting for the first time in 30 days. Shows whether people are finding us."
          tip="A machine is an IP address, so an address change reads as a new machine. Owner machines are not excluded here."
        />
        <Card
          label="Came back on day 7"
          value={`${d7} · D1 ${d1}`}
          meaning="Day 7: machines first seen 8–14 days ago that connected again exactly 7 days later. D1: the same for the next day (first seen 2–8 days ago)."
          tip="Connecting, not being protected. Exact-day retention is noisy for a tool used a few times a week, and IP changes lower it. Owner machines excluded."
        />
        <Card
          label="Hand-run checks"
          value={calls.toLocaleString()}
          meaning="Tool calls people asked for in Claude Code, claude.ai, ChatGPT, Cursor, VS Code and Codex. Shows people asking on purpose."
          tip={`Leaves out about_agentavow (an overview, not a check) and calls from owner machines (METRICS_OWNER_IPS)${firstChecksDay ? `, from ${firstChecksDay}` : ' once the new counter has a day on file'}; earlier days are raw tool calls from Claude Code, claude.ai and ChatGPT. Owner calls through claude.ai and ChatGPT arrive from the vendor's proxy, so they cannot be excluded. Codex has its own surface only if its User-Agent says "codex" (not yet confirmed); otherwise its calls stay under ChatGPT or "unknown", which is not counted.`}
        />
        <Card
          label="Listings live"
          value={`${live.length} live · ${pending.length} pending`}
          meaning={live.map((l) => l.name).join(', ')}
          tip="From web/src/rebrand/pages/adminListings.ts. VS Code is not a listing of its own: it reads the official MCP registry."
        >
          <details className="mt-1 text-[11.5px] text-text-muted">
            <summary className="cursor-pointer">Pending</summary>
            <ul className="mt-1 space-y-0.5">
              {pending.map((l) => (
                <li key={l.name}>
                  {l.url ? <a href={l.url} target="_blank" rel="noopener" className="hover:text-primary-light">{l.name}</a> : l.name}
                  {l.note ? ` · ${l.note}` : ''}{l.since ? ` · since ${l.since}` : ''}
                </li>
              ))}
            </ul>
          </details>
        </Card>
      </div>
    </section>
  )
}
