/**
 * The score page's pure logic, shared by every result type (rebrand/components/
 * ResultPage.tsx renders it): the checked time, the top findings and their fix lines,
 * the Certified checklist rows and status line, and the one-line sandbox summary.
 * Plain TypeScript with `.ts` imports so tests can run it under node type stripping
 * (tests/test_result_page.py). Nothing here decides the answer or moves the score: the
 * answer is the API's decision read through gradeSystem.decisionOf.
 */
import {
  coverageGapNotes, decisionOf, isCertified, certifiedMarkNote, cheapCoverageGap,
  CERTIFIED_MARK_MIN_SCORE, type Decision,
} from '../../components/trust/gradeSystem.ts'

type Obj = Record<string, unknown>
const asObj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {})

export type ResultKind = 'repo' | 'package' | 'mcp' | 'skill' | 'a2a'


/** "7 min ago" from an ISO time; '' when unknown. */
export function checkedAgo(iso?: unknown, now = Date.now()): string {
  if (typeof iso !== 'string' || !iso) return ''
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return ''
  const s = Math.max(0, Math.round((now - t) / 1000))
  if (s < 60) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h} h ago`
  return `${Math.round(h / 24)} days ago`
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3, info: 4 }
export type TopFinding = {
  category?: string; name?: string; severity?: string; file_path?: string; line_number?: number
  remediation?: string; shipped?: boolean; kind?: string; installed?: boolean
}

/** The findings that lead the page: worst first, shipped code before tests, defects
 * before capabilities. A view only; the score and the answer come from the API. */
export function topFindings(scan: unknown, n = 3): TopFinding[] {
  const items = (asObj(asObj(scan).findings).items as TopFinding[] | undefined) ?? []
  return items
    .filter((i) => i && i.installed !== false)
    .map((i, idx) => ({ i, idx }))
    .sort((a, b) => (SEV_RANK[(a.i.severity || 'info').toLowerCase()] ?? 5) - (SEV_RANK[(b.i.severity || 'info').toLowerCase()] ?? 5)
      || Number(a.i.shipped === false) - Number(b.i.shipped === false)
      || Number(a.i.kind === 'capability') - Number(b.i.kind === 'capability')
      || a.idx - b.idx)
    .slice(0, n)
    .map(({ i }) => i)
}

/** The fix line for a finding. A capability is what the tool does, not a defect, and its
 * `remediation` only repeats the capability, so it says so instead. Remediation text
 * written "what it is — what to do" keeps the part after the dash. */
export function fixText(it: TopFinding): string {
  if (it.kind === 'capability') return 'No fix needed: this is what the tool does. It is listed so you know.'
  const r = (it.remediation || '').trim()
  if (!r) return ''
  const parts = r.split(' — ')
  const fix = (parts.length > 1 ? parts[parts.length - 1] : r).trim()
  return fix ? fix[0].toUpperCase() + fix.slice(1) : ''
}

const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s)

// ── the Certified checklist ─────────────────────────────────────────────────────

export type CheckRowState = 'pass' | 'fail' | 'wait' | 'na'
export interface CheckRow {
  label: string
  state: CheckRowState
  evidence: string
  /** the signed gate checks this row covers (scan.py _certified_status), shown muted */
  keys?: string[]
  /** the last row: the answer rule that decides the mark */
  decides?: boolean
  /** a plain line under the deciding row */
  note?: string
}

const ROW_ANSWER = 'Answer: Safe to connect at 81+'
const ROW_PROVENANCE = 'Published package matches its source'
const ROW_FILES = 'Every file read, nothing changed'
const ROW_SEVERE = 'No critical or high finding'
const ROW_SANDBOX = 'Sandbox result is in, anyone can recompute'

const PHRASE_SHORT = { safe: 'Safe', review: 'Review', do_not_connect: 'Do not connect' } as const

/** The Certified checklist: the six signed gate checks (artifact_scanned,
 * provenance_verified, no_drift, full_coverage, no_critical_or_high, recompute_ready)
 * grouped into four rows, then ALWAYS the line that decides it: the answer rule, Safe
 * to connect at 81+ (approved score-page mock, 2026-11-10). Evidence only; the mark
 * itself is isCertified. */
export function certifiedRows(scan: unknown, kind: ResultKind, d: Decision = decisionOf(scan)): CheckRow[] {
  const o = asObj(scan)
  const checks = asObj(asObj(o.certified).checks)
  const score = typeof o.trust_score === 'number' ? o.trust_score : 0
  const gaps = asObj(o.coverage_gaps)
  const prov = asObj(o.provenance)
  const b = o.behavioral && typeof o.behavioral === 'object' ? asObj(o.behavioral) : null
  const gs = asObj(b?.grade_summary)
  const mark = isCertified(scan)
  const rows: CheckRow[] = []

  // 1 · provenance: the published artifact was scanned and its build provenance verified
  const binding = asObj(prov.binding)
  const boundRepo = typeof binding.repo === 'string' ? binding.repo.replace(/^github\.com\//, '') : ''
  const provKeys = ['artifact_scanned', 'provenance_verified']
  if (checks.artifact_scanned === true && checks.provenance_verified === true) {
    rows.push({ label: ROW_PROVENANCE, state: 'pass', evidence: boundRepo ? `Signed build provenance → ${boundRepo}` : 'Signed build provenance verified' })
  } else if (kind === 'mcp') {
    rows.push({ label: ROW_PROVENANCE, state: 'fail', evidence: 'A server checked by URL has no published package to match' })
  } else if (kind === 'a2a') {
    rows.push({ label: ROW_PROVENANCE, state: 'fail', evidence: 'An agent card checked by URL has no published package to match' })
  } else if (prov.present === true && prov.verified !== true) {
    rows.push({ label: ROW_PROVENANCE, state: 'fail', evidence: 'Provenance is published but did not verify' })
  } else if (checks.artifact_scanned === false) {
    rows.push({ label: ROW_PROVENANCE, state: 'fail', evidence: 'Scanned from source; no published package confirmed' })
  } else {
    rows.push({ label: ROW_PROVENANCE, state: 'fail', evidence: 'No build provenance' })
  }
  rows[rows.length - 1].keys = provKeys

  // 2 · every file read, no drift (the sandbox gap belongs to row 4)
  const fileGaps = { ...o, coverage_gaps: { ...gaps, sandbox_not_observed: undefined } }
  const notes = coverageGapNotes(fileGaps)
  const fileKeys = ['no_drift', 'full_coverage']
  if (gaps.tool_list_unread === true || gaps.tool_list_paged === true) {
    rows.push({ label: ROW_FILES, state: 'fail', evidence: gaps.tool_list_unread === true ? "The live tool list couldn't be read" : 'Only part of the live tool list was read' })
  } else if (checks.no_drift === false) {
    rows.push({ label: ROW_FILES, state: 'fail', evidence: 'The published files differ from the source' })
  } else if (checks.full_coverage === false || cheapCoverageGap(fileGaps)) {
    rows.push({ label: ROW_FILES, state: 'fail', evidence: notes[0] ? cap(notes[0]) : 'Part of it was not read' })
  } else if (!Object.keys(checks).length) {
    rows.push({ label: ROW_FILES, state: 'fail', evidence: 'Not checked for this result' })
  } else {
    rows.push({ label: ROW_FILES, state: 'pass', evidence: kind === 'mcp' ? 'Every served tool definition read, no drift' : kind === 'a2a' ? 'The whole agent card read: every skill, interface and auth scheme' : notes.length ? 'No drift; what an agent reads was read in full' : 'All files read, no drift' })
  }
  rows[rows.length - 1].keys = fileKeys

  // 3 · no critical or high finding: in the code, in the sandbox run (a live run's
  // findings, as decide() reads them), or wherever the answer's own reason cites one.
  // The row must never pass while the answer names a critical or high finding
  // (server-puppeteer 2025.5.12: a sandbox high read Review but this row passed).
  const f = asObj(o.findings)
  const crit = Number(f.critical ?? 0) || 0
  const high = Number(f.high ?? 0) || 0
  const bLive = !!(b && b.ran === true && b.pending !== true && b.plan !== 'live-probe' && b.advisory !== true)
  const bSev = (want: string) => (bLive && Array.isArray(b?.findings) ? (b?.findings as unknown[]) : [])
    .filter((x) => String(asObj(x).severity ?? '').toLowerCase() === want).length
  const bCrit = bSev('critical')
  const bHigh = bSev('high')
  // a counted finding ("one high finding", "2 critical findings"), never "no critical or high findings"
  const reasonCites = /\b(?:one|two|three|four|five|\d+)\s+(?:critical|high)\s+findings?\b/i.test(String(d.reason ?? ''))
  const severe = checks.no_critical_or_high === false || crit + high + bCrit + bHigh > 0 || reasonCites
  if (severe) {
    const parts = [crit && `${crit} critical`, high && `${high} high`].filter(Boolean)
    const bParts = [bCrit && `${bCrit} critical`, bHigh && `${bHigh} high`].filter(Boolean)
    const n = crit + high
    const bn = bCrit + bHigh
    const ev = [parts.length ? `${parts.join(', ')} finding${n === 1 ? '' : 's'}` : '',
      bParts.length ? `${bParts.join(', ')} finding${bn === 1 ? '' : 's'} in the sandbox` : '']
      .filter(Boolean).join('; ')
    rows.push({ label: ROW_SEVERE, state: 'fail', evidence: ev || 'A critical or high finding' })
  } else {
    rows.push({ label: ROW_SEVERE, state: 'pass', evidence: 'And nothing known-malicious' })
  }
  rows[rows.length - 1].keys = ['no_critical_or_high']

  // 4 · the sandbox ran it, and the signed result recomputes
  const why = gaps.sandbox_not_observed
  if (b?.pending === true) {
    rows.push({ label: ROW_SANDBOX, state: 'wait', evidence: b.state === 'queued' ? 'waiting for a sandbox slot' : 'running now · usually under a minute' })
  } else if (why === 'other_version' || b?.other_version === true) {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: 'the sandbox runs the latest release, not this pinned version' })
  } else if (typeof why === 'string' && why) {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: `the sandbox couldn't start it (${why.replace(/_/g, ' ')})` })
  } else if (checks.recompute_ready === false) {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: "the signed result can't be recomputed offline yet" })
  } else if (b?.ran === true) {
    const listed = typeof gs.tools_listed === 'number' ? gs.tools_listed : 0
    const calls = typeof gs.calls_total === 'number' ? gs.calls_total : 0
    rows.push({ label: ROW_SANDBOX, state: 'pass', evidence: listed ? `started, ${listed} tool${listed === 1 ? '' : 's'}, ${calls} call${calls === 1 ? '' : 's'} · signed result` : 'installed and run · signed result' })
  } else if (b && b.state === 'unavailable') {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: 'the sandbox was unavailable for this check' })
  } else if (b) {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: typeof b.reason === 'string' && b.reason ? `didn't run: ${b.reason}` : 'no finished run' })
  } else if (kind === 'mcp') {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: 'a server checked by URL is not run in the sandbox' })
  } else if (kind === 'a2a') {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: "an agent card is read, not run: the agent's code is not in the sandbox" })
  } else if (mark) {
    rows.push({ label: ROW_SANDBOX, state: 'na', evidence: "the sandbox doesn't run this kind of tool; the signed result recomputes offline" })
  } else {
    rows.push({ label: ROW_SANDBOX, state: 'fail', evidence: 'no finished run' })
  }
  rows[rows.length - 1].keys = ['recompute_ready']

  // 5 · always last: the answer rule, which decides the mark
  rows.push(answerRow(score, d))
  return rows
}

/** The deciding line: "Answer: Safe to connect at 81+ (reads Review at 86)". */
export function answerRow(score: number, d: Decision): CheckRow {
  const reads = `reads ${PHRASE_SHORT[d.decision]} at ${score}`
  if (d.decision === 'safe' && score >= CERTIFIED_MARK_MIN_SCORE) {
    return d.final
      ? { label: ROW_ANSWER, state: 'pass', evidence: reads, decides: true }
      : { label: ROW_ANSWER, state: 'wait', evidence: `${reads}, pending`, decides: true, note: 'The answer becomes final when the sandbox run finishes.' }
  }
  if (d.decision === 'safe') {
    return { label: ROW_ANSWER, state: 'fail', evidence: reads, decides: true, note: `Certified needs a trust score of ${CERTIFIED_MARK_MIN_SCORE} or above.` }
  }
  return { label: ROW_ANSWER, state: 'fail', evidence: reads, decides: true, note: d.reason ? `${cap(d.reason)}.` : undefined }
}

/** "Certified: pending" — the mark could still come when a check finishes (a sandbox
 * run queued or running holds the answer, or a coverage gap waits on that run). Null
 * when the mark is earned, can't be earned from here, or nothing is running. Never the
 * badge: the caller shows one dashed line instead. */
export function certifiedPending(scan: unknown, d: Decision = decisionOf(scan)): string | null {
  if (isCertified(scan)) return null
  const o = asObj(scan)
  if (d.decision !== 'safe') return null
  const score = typeof o.trust_score === 'number' ? o.trust_score : 0
  if (score < CERTIFIED_MARK_MIN_SCORE) return null
  const b = asObj(o.behavioral)
  const running = b.pending === true || !d.final || o.certified_mark_reason === 'sandbox_pending'
  if (!running) return null
  // The checks a sandbox run can't change must already pass.
  const checks = asObj(asObj(o.certified).checks)
  const ready = asObj(o.certified).eligible === true
    || (['artifact_scanned', 'provenance_verified', 'no_drift', 'no_critical_or_high'] as const).every((k) => checks[k] === true)
  if (!ready) return null
  return b.state === 'queued' ? 'waiting for a sandbox slot' : 'sandbox run in progress'
}

/** The checklist's status line, by state (copy from the build spec). */
export function certifiedStatus(scan: unknown, rows: CheckRow[], d: Decision = decisionOf(scan)): { lead: string; rest: string } {
  if (isCertified(scan)) return { lead: "Why it's Certified", rest: '' }
  const gaps = asObj(asObj(scan).coverage_gaps)
  if (gaps.tool_list_unread === true) return { lead: 'Not Certified', rest: "the live server couldn't be read" }
  if (d.decision === 'do_not_connect') return { lead: 'Not Certified', rest: 'the answer is Do not connect' }
  if (d.decision === 'review') return { lead: 'Not Certified', rest: 'the answer is Review' }
  const fails = rows.filter((r) => r.state === 'fail').length
  if (!d.final && fails === 0) return { lead: 'Certified is pending', rest: 'waiting on the sandbox run' }
  if (fails === 0) {
    const note = certifiedMarkNote(scan).replace(/^Certified checks pass; /, '')
    return { lead: 'Not Certified yet', rest: note || 'one check is missing' }
  }
  const words = ['', 'one', 'two', 'three', 'four']
  return { lead: 'Not Certified yet', rest: fails === 1 ? 'one check is missing' : `${words[fails] ?? fails} checks are missing` }
}


/** The behavioral block a result may carry, as far as the sandbox line reads it. */
export type SandboxScan = {
  behavioral?: {
    ran?: boolean; pending?: boolean; plan?: string; state?: string
    reason?: string | null; timed_out?: boolean
    canary_exfil?: unknown[]
    findings?: Array<{ severity?: string; name?: string; rule?: string }>
    exercise?: { launch_ok?: boolean; calls?: unknown[]; timed_out?: boolean } | null
    grade_summary?: { start_reason?: string } | null
    unexpected_egress?: string[]
  } | null
  behavioral_score_effect?: { applied?: boolean; delta?: number } | null
}

/** One plain line about the sandbox run (null when the result has no sandbox block).
 * The answer banner and the score page's "What we couldn't check" section both read
 * it. Wording only: it never changes the answer or the score. */
export function sandboxSummary(scan: SandboxScan): string | null {
  const b = scan.behavioral
  const bFindings = (b?.ran && !b.pending ? b.findings : []) ?? []
  // One line about the sandbox for the card, whatever the decision.
  const calls = b?.exercise?.calls?.length ?? 0
  const reason = (b?.grade_summary?.start_reason ?? '').replace(/_/g, ' ')
  const delta = scan.behavioral_score_effect?.applied ? scan.behavioral_score_effect.delta ?? 0 : 0
  const deltaTxt = delta ? ` · score ${delta > 0 ? '+' : ''}${delta}` : ''
  const severe = bFindings.filter((f) => f.severity === 'critical' || f.severity === 'high')
  const leaked = !!(b?.ran && (b.canary_exfil?.length ?? 0) > 0)
  // A run that hit its time limit is partial: the card must not read "clean" while the
  // behavioral panel below says "results may be partial".
  const partial = !!(b?.timed_out || b?.exercise?.timed_out)
  return !b ? null
    : b.pending && b.state === 'queued' ? 'Sandbox: waiting for a free slot — this answer may move to Review when it lands'
    : b.pending ? 'Sandbox: still running — this answer may move to Review when it lands'
    : b.state === 'unavailable' ? 'Sandbox: unavailable — this answer is static analysis only'
    : !b.ran ? (b.reason ? `Sandbox: did not run (${b.reason}) — this answer is static analysis only` : null)
    : leaked ? `Sandbox: caught — a planted credential left the sandbox${deltaTxt}`
    : severe.length ? `Sandbox: caught — ${severe[0].name ?? 'a behavioral finding'}${deltaTxt}`
    : bFindings.length ? `Sandbox: ran${partial ? ' partly (hit its time limit)' : ''}, ${bFindings.length} minor finding${bFindings.length === 1 ? '' : 's'}${deltaTxt}`
    : b.exercise?.launch_ok ? (partial
      ? `Sandbox: ran partly (hit its time limit), called ${calls} tool${calls === 1 ? '' : 's'}, nothing caught${deltaTxt}`
      : `Sandbox: called ${calls} tool${calls === 1 ? '' : 's'}, clean${deltaTxt}`)
    : reason === 'install failed' ? 'Sandbox: the install failed, so nothing ran — not a finding'
    : reason && reason !== 'not applicable' && reason !== 'started' ? `Sandbox: installed; server not started (${reason}) — not a finding`
    : partial ? `Sandbox: ran partly (hit its time limit), nothing caught${deltaTxt}`
    : 'Sandbox: installed and imported, clean'
}
