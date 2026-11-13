/** The five numbers to read first on the admin dashboard, in plain English. Everything
 * else on the Metrics tab stays below this panel. Uses the page's time window; the two
 * machine counts are 7-day counts by nature and say so. */
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'

import api from '../../lib/api'
import { liveListings, pendingListings } from './adminListings'
import { Info } from './AdminGlossary'
import type { GlossaryKey } from './adminGlossaryTerms'
import { dayLabel, pctOf, rangeLabel, useDashWindow, useWindowLabel } from './adminMetricsUtil'

interface Row {
  day: string
  cc_machines_7d?: number | null; checked_machines_7d?: number | null
  cc_machines_7d_excl_cloud?: number | null; checked_machines_7d_excl_cloud?: number | null
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

const pct = (num: number, den: number) => (den ? pctOf(num, den) : 'Not ready')

/** The 7-day machine counts are complete from this snapshot day (they need 7 days). */
const SEVEN_DAY_COMPLETE_FROM = '2026-11-14'

/** Hand-run checks for one day, from the checks counter: every real surface minus
 *  about_agentavow and owner machines. Only days where checks_total is set. */
const handRunChecks = (r: Row) =>
  (r.checks_claude_code ?? 0) + (r.checks_claude ?? 0) + (r.checks_chatgpt ?? 0)
  + (r.checks_cursor ?? 0) + (r.checks_vscode ?? 0) + (r.checks_codex ?? 0)

/** Raw tool calls for a day before the checks counter existed (three surfaces only). */
const rawCalls = (r: Row) => (r.calls_claude_code ?? 0) + (r.calls_claude ?? 0) + (r.calls_chatgpt ?? 0)

function Card({ label, k, value, meaning, tip, children }: { label: string; k?: GlossaryKey; value: string; meaning: ReactNode; tip?: string; children?: ReactNode }) {
  return (
    <div className="glass rounded-xl p-4" title={tip}>
      <div className="text-[12.5px] font-semibold text-text-muted">
        {label}{k ? <Info k={k} extra={tip} /> : tip && <span className="ml-1 cursor-help text-text-muted/60" aria-label={tip}>ⓘ</span>}
      </div>
      <div className="mt-1 text-2xl font-extrabold tabular-nums">{value}</div>
      <p className="mt-1 text-[12px] text-text-muted">{meaning}</p>
      {children}
    </div>
  )
}

export default function StartHerePanel() {
  const w = useDashWindow()
  const label = useWindowLabel()
  const { data } = useQuery<{ rows?: Row[] }>({
    queryKey: ['admin-dash-claude-traffic', w.days + 1],
    queryFn: async () => (await api.get('/admin/metrics/traffic', { params: { days: w.days + 1 } })).data,
  })
  const inWindow = new Set(w.complete)
  const rows = (data?.rows || []).filter((r) => inWindow.has(r.day))
  const latest = rows[rows.length - 1]
  const yesterday = w.complete[w.complete.length - 1]
  // The 7 days the latest snapshot's rolling counts cover.
  const sevenDays = latest ? Array.from({ length: 7 }, (_, i) => new Date(Date.parse(`${latest.day}T00:00:00Z`) - (6 - i) * 86_400_000).toISOString().slice(0, 10)) : []
  // From the Nov 11 snapshot on, machines seen on an Anthropic cloud entrypoint are left
  // out (their egress IPs are shared); older rows only have the raw 7-day counts.
  const cloudExcluded = latest?.checked_machines_7d_excl_cloud != null
  const protectedMachines = cloudExcluded ? latest?.checked_machines_7d_excl_cloud : latest?.checked_machines_7d
  const connected = cloudExcluded ? latest?.cc_machines_7d_excl_cloud : latest?.cc_machines_7d
  const share = protectedMachines != null && connected ? ` of ${connected.toLocaleString()} (${pctOf(protectedMachines, connected)})` : ''
  const sevenDayPartial = latest && latest.day < SEVEN_DAY_COMPLETE_FROM
  const d7 = pct(sum(rows, (r) => r.d7_returned), sum(rows, (r) => r.d7_cohort))
  const d1 = pct(sum(rows, (r) => r.d1_returned), sum(rows, (r) => r.d1_cohort))
  // Hand-run checks: only the days the checks counter covers, so this matches the MCP
  // panel's "Hand-run checks". Earlier days' raw tool calls are shown apart, not added.
  const checkDays = rows.filter((r) => r.checks_total != null)
  const preDays = rows.filter((r) => r.checks_total == null)
  const checks = sum(checkDays, handRunChecks)
  const live = liveListings()
  const pending = pendingListings()

  return (
    <section className="mt-8">
      <h2 className="text-lg font-bold">Start here</h2>
      <p className="mt-0.5 font-mono text-[11.5px] text-primary-light/90">{label}</p>
      <p className="mt-1 text-text-muted text-[13px]">
        The five numbers that matter. Higher is better on all of them.
        {latest
          ? <> The two machine counts are 7-day counts from the {dayLabel(latest.day)} snapshot ({rangeLabel(sevenDays)}); the rest cover the whole window ({rows.length} of {w.days} days have a snapshot).{latest.day !== yesterday ? ` The ${dayLabel(yesterday)} snapshot isn't written yet (it lands at 00:40 UTC).` : ''}</>
          : ' No snapshot on file for this window yet.'}
      </p>
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <Card
          label={`Claude Code machines protected · unique, 7 days to ${dayLabel(latest?.day)}`}
          k="protected"
          value={protectedMachines != null ? `${protectedMachines.toLocaleString()}${share}` : 'Not ready'}
          meaning={<>Machines where the Claude Code plugin's session-start or install-time check ran at least once in those 7 days, out of machines connecting.{sevenDayPartial ? ` Partial: this count is complete from ${dayLabel(SEVEN_DAY_COMPLETE_FROM)} (it needs 7 days of data).` : ''}</>}
          tip={`Each machine counts once in the 7 days. Owner machines (data/owner-ips.txt on the host) are excluded. Not counted: hand-run checks in claude.ai, ChatGPT, Cursor, VS Code or Codex; the npm and Python gates; CI. ${cloudExcluded ? 'Machines seen on an Anthropic cloud (remote) entrypoint in the last 30 days are excluded too.' : 'Anthropic cloud addresses (remote Claude Code sessions) are NOT excluded on this row: the snapshot did not split by entrypoint yet, so they inflate both the count and the share.'}`}
        />
        <Card
          label={`New machines · ${rangeLabel(w.complete)}`}
          k="machine"
          value={sum(rows, (r) => r.cc_new_machines_30d).toLocaleString()}
          meaning="Claude Code machines connecting for the first time in 30 days. Shows whether people are finding us."
          tip="A machine is an IP address, so an address change reads as a new machine. Owner machines are not excluded here. Each machine is new on one day only, so the days add up."
        />
        <Card
          label="Came back a week later"
          value={`${d7} · next day ${d1}`}
          meaning="For each day in the window: of the machines first seen exactly 7 days earlier, how many connected again that day. 'Next day' is the same for machines first seen the day before."
          tip="Connecting, not being protected. Exact-day return is noisy for a tool used a few times a week, and IP changes lower it. Owner machines excluded."
        />
        <Card
          label={`Hand-run checks · ${checkDays.length ? rangeLabel(checkDays.map((r) => r.day)) : 'none yet'}`}
          k="hand_run"
          value={checks.toLocaleString()}
          meaning={<>Checks people asked for by hand in Claude Code, claude.ai, ChatGPT, Cursor, VS Code and Codex. Shows people asking on purpose.{preDays.length > 0 && checkDays.length > 0 ? ` Counted from ${dayLabel(checkDays[0].day)}, when this count started; the ${preDays.length} earlier day${preDays.length === 1 ? '' : 's'} in the window had ${sum(preDays, rawCalls).toLocaleString()} raw tool calls, not included.` : ''}</>}
          tip={`Leaves out about_agentavow (an overview, not a check) and calls from owner machines (METRICS_OWNER_IPS). Owner calls through claude.ai and ChatGPT arrive from the vendor's proxy, so they cannot be excluded. Codex has its own surface only if its User-Agent says "codex" (not yet confirmed); otherwise its calls stay under ChatGPT or "unknown", which is not counted. Same counter as "Hand-run checks" in the MCP panel.`}
        />
        <Card
          label="Listings live · right now"
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
