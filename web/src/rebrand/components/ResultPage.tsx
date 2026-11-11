import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { rp } from '../basePath'
import { publicApi } from '../../lib/scanApi'
import { coverageGapNotes, decisionOf, decisionPhrase, isCertified, type Decision } from '../../components/trust/gradeSystem'
import { TrustBar, AdoptionNeedle, CertifiedBadge } from './TrustMark'
import { AgentAvowChooser } from './AgentAvowChooser'
import { Reveal } from './motion'
import { useIsDesktop } from '../lib/hooks'
import {
  certifiedPending, certifiedRows, certifiedStatus, checkedAgo, fixText, sandboxSummary, topFindings,
  type CheckRow, type CheckRowState, type ResultKind, type TopFinding,
} from '../lib/resultPage'

export type { ResultKind } from '../lib/resultPage'

type Obj = Record<string, unknown>
const asObj = (v: unknown): Obj => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : {})
const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s)

const SEV_CLASS: Record<string, string> = {
  critical: 'text-danger bg-danger/15',
  high: 'text-warning bg-warning/15',
  medium: 'text-warning bg-warning/10',
  low: 'text-text-muted bg-surface-hover',
  info: 'text-text-muted bg-surface-hover',
}

/**
 * The ONE top of every score page: repo, package (npm, PyPI, crates, Docker, Hugging
 * Face), live MCP server, Agent Skill and private one-time scan all render through
 * <ResultPage>, so every result type shows the same sections in the same order
 * (website build spec 2026-11-07, score page):
 *
 *   incident banner · eyebrow (surface, name, version, checked time, Re-check) · title
 *   1  the answer and its reason
 *   2  trust score (the Certified badge in its place when earned) and adoption score
 *   3  the Certified checklist, always ending with the line that decides it
 *   4  what the check found: top 3 findings with fixes, then all findings
 *   5  what we couldn't check
 *   6  next steps: 1 keep an eye on it (Watch) · 2 is this yours? (claim, badge) ·
 *      3 check tools like this automatically (every AgentAvow path) · 4 how to
 *      install this tool (collapsed). A step whose action doesn't exist is hidden.
 *   7  keep watching it
 *   8  what's inside
 *   9  badges (and the share panel)
 *   10 verify it yourself (collapsed)
 *
 * Certified shows once: the badge in the trust-score slot (approved mock, 2026-11-10).
 *
 * The answer is the API's own decision read through gradeSystem.decisionOf (the twin of
 * src/scanner/verdict.py decide()); the mark is isCertified. Nothing here re-decides.
 * Type-specific panels come in as slots; the order and headings are fixed here.
 */


export interface ResultAdoption {
  /** headline count + unit for the needle (0 = no usage data) */
  count: number
  unit?: string
  /** the 0–100 adoption score, when the API has one */
  scorePct?: number
  /** one plain line under the needle */
  sub: string
}

export interface ResultRecheck {
  run: () => void
  pending: boolean
  error: boolean
}

export interface ResultPageProps {
  scan: Obj & { trust_score: number }
  kind: ResultKind
  /** eyebrow parts before the version and checked time, e.g. ['npm', '@notionhq/notion-mcp-server'] */
  eyebrow: string[]
  /** the version control for packages (a picker), rendered in the eyebrow */
  version?: ReactNode
  /** the tool's name as the title reads it: "Is <name> safe to connect?" */
  name: string
  /** 'one-time' hides everything that needs a stored result (watch, history, badge, share) */
  privateScan?: 'one-time' | 'stored'
  /** chips under the title (claimed, provenance, surface badges) */
  chips?: ReactNode
  /** description / notes under the title */
  intro?: ReactNode
  adoption: ResultAdoption | null
  recheck?: ResultRecheck
  /** the full grouped findings list, behind "See all findings" */
  allFindings: ReactNode
  /** a plain-English summary above the top findings */
  findingsIntro?: ReactNode
  /** extra type-specific "what we couldn't check" lines */
  gapNotes?: ReactNode[]
  /** a full panel for the couldn't-check section (e.g. what doesn't apply to a hosted endpoint) */
  gapPanel?: ReactNode
  /** step 4, "How to install this tool" (replaced by one line on Do not connect) */
  install?: ReactNode
  /** step 1, the watch button (absent where watching doesn't exist: one-time private
   * scans, A2A cards, surfaces the watch API doesn't take) */
  watch?: ReactNode
  /** markdown of the public badge; when set, step 2 offers "Add the badge ↓" */
  badgeMarkdown?: string
  /** step 2, "Is this yours?" (absent where claiming doesn't exist: Docker, Hugging
   * Face, A2A) */
  ownerStep?: OwnerStep
  /** the share panel (renders #share); the card footer links to it when present */
  sharePanel?: ReactNode
  /** true when a #share target exists without a sharePanel (a published private repo
   * shares from its publish control) */
  shareAnchor?: boolean
  keepWatching?: { history?: ReactNode; adoption?: ReactNode; drift?: ReactNode; note?: ReactNode }
  inside: ReactNode
  /** the Badges section at the bottom: badge / card / widget */
  badges?: ReactNode
  /** the "What we checked" facts, inside Verify it yourself */
  whatWeChecked?: ReactNode
  /** the signed proof (VerifyPanel) */
  proof?: ReactNode
  /** the incident / deprecation banner, above the title */
  banner?: ReactNode
}

/** Step 2's body: one line and the claim (or publish) control. */
export interface OwnerStep {
  text: ReactNode
  actions: ReactNode
}

const ROW_STYLE: Record<CheckRowState, { tag: string; cls: string }> = {
  pass: { tag: 'PASS', cls: 'text-success bg-success/12 border-success/30' },
  fail: { tag: 'FAIL', cls: 'text-danger bg-danger/10 border-danger/30' },
  wait: { tag: 'WAIT', cls: 'text-warning bg-warning/12 border-warning/30' },
  na: { tag: 'N/A', cls: 'text-text-muted bg-surface border-border' },
}

export function CertifiedChecklist({ scan, kind, decision, rowsOverride, statusOverride }: {
  scan: unknown; kind: ResultKind; decision?: Decision
  rowsOverride?: CheckRow[]; statusOverride?: { lead: string; rest: string }
}) {
  const d = decision ?? decisionOf(scan)
  const rows = rowsOverride ?? certifiedRows(scan, kind, d)
  const st = statusOverride ?? certifiedStatus(scan, rows, d)
  const checks = rows.filter((r) => !r.decides)
  const decide = rows.find((r) => r.decides)
  const earned = isCertified(scan)
  return (
    <Reveal>
      <div className={`mt-4 rounded-2xl px-5 py-4 border ${earned ? 'border-accent/40 bg-[linear-gradient(100deg,rgba(45,212,191,.08),rgba(232,121,249,.06)_70%)]' : 'glass border-transparent'}`} data-testid="certified-checklist">
        <div className="flex items-baseline justify-between gap-x-3 gap-y-1 flex-wrap">
          <div className="text-[14.5px]"><b>{st.lead}</b>{st.rest && <span className="text-text-muted"> · {st.rest}</span>}</div>
          <Link to={rp('/rebrand/certified')} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">What Certified means →</Link>
        </div>
        <ul className="mt-3 grid sm:grid-cols-2 gap-x-5 gap-y-2.5">
          {checks.map((r) => (
            <li key={r.label} className="flex items-start gap-2.5 text-[13px] min-w-0" data-state={r.state}>
              <span className={`font-mono text-[10px] font-bold tracking-wide px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${ROW_STYLE[r.state].cls}`}>{ROW_STYLE[r.state].tag}</span>
              <span className="min-w-0">
                <span className="text-text">{r.label}</span>
                <span className="block text-[11.5px] text-text-muted break-words">{r.evidence}</span>
                {r.keys?.length ? <span className="block font-mono text-[10.5px] text-text-muted/70 break-words">{r.keys.join(' · ')}</span> : null}
              </span>
            </li>
          ))}
        </ul>
        {decide && (
          <div className="mt-3 pt-3 border-t border-border/70 flex items-start gap-2.5 text-[13.5px]" data-state={decide.state} data-testid="certified-decides">
            <span className={`font-mono text-[10px] font-bold tracking-wide px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${ROW_STYLE[decide.state].cls}`}>{ROW_STYLE[decide.state].tag}</span>
            <span className="min-w-0">
              <b className="font-semibold">{decide.label}</b> <span className="text-text-muted">({decide.evidence})</span>
              {decide.note && <span className="block text-[12px] text-text-muted break-words">{decide.note}</span>}
            </span>
          </div>
        )}
      </div>
    </Reveal>
  )
}

// ── the answer + the two scores ─────────────────────────────────────────────────

const ANSWER_STYLE = {
  safe: { fg: 'text-success', icon: '✓', border: 'border-success/30' },
  review: { fg: 'text-warning', icon: '!', border: 'border-warning/40' },
  do_not_connect: { fg: 'text-danger', icon: '✕', border: 'border-danger/50' },
} as const

function Percentile({ score }: { score: number }) {
  const { data } = useQuery({
    queryKey: ['score-percentile', score],
    queryFn: async () => (await publicApi.get<{ percentile: number | null; population: number }>(
      `/public/scan-catalog/percentile?score=${score}`)).data,
    staleTime: 600_000, retry: 0,
  })
  if (data?.percentile == null) return null
  return <> · higher than <b className="text-text tabular-nums">{data.percentile}%</b> of {data.population ? `${data.population.toLocaleString('en-US')} ` : ''}tools</>
}

function AnswerCard({ scan, kind, adoption, share }: { scan: ResultPageProps['scan']; kind: ResultKind; adoption: ResultAdoption | null; share: boolean }) {
  const d = decisionOf(scan)
  const p = decisionPhrase(d.decision)
  const st = ANSWER_STYLE[d.decision]
  // Certified shows ONCE: the badge takes the trust score's place. Never while pending.
  const certified = isCertified(scan) && d.decision === 'safe'
  const pending = certified ? null : certifiedPending(scan, d)
  const desktop = useIsDesktop()
  const big = desktop ? 1.35 : 1
  const crit = Number(asObj(scan.findings).critical ?? 0)
  const reason = d.reason ? cap(d.reason) + '.' : ''
  const signed = typeof scan.jws === 'string' && !!scan.jws
  const scoreSub = kind === 'mcp'
    ? 'Signed · scored on the tools it serves, not its server code'
    : kind === 'a2a'
    ? "Signed · scored on its agent card, not the agent's code"
    : crit > 0 && scan.trust_score <= 45 ? 'Signed · a critical finding caps the score at 45' : null
  const openVerify = () => { const el = document.getElementById('verify'); if (el) el.setAttribute('open', '') }
  return (
    <Reveal>
      <div className={`mt-6 glass rounded-2xl border ${st.border} overflow-hidden`} data-decision={d.decision} data-certified={certified ? 'earned' : pending ? 'pending' : 'no'} data-testid="answer-card">
        <div className="px-6 pt-6 pb-5">
          <div className={`flex items-center gap-2.5 flex-wrap text-[22px] sm:text-[26px] font-extrabold tracking-tight leading-tight ${st.fg}`}>
            <span aria-hidden="true">{st.icon}</span>
            <span>{p.phrase}</span>
            {!d.final && <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-1 rounded-md bg-surface border border-border text-text-muted">provisional</span>}
          </div>
          <p className="mt-2 text-[14.5px] text-text-muted max-w-[68ch]">
            {reason}
            {!d.final && (asObj(scan.behavioral).state === 'queued' ? ' This answer can still change when the sandbox runs it.' : ' The sandbox is running this version now, so this answer can still change. Usually under a minute.')}
          </p>
        </div>
        <div className="grid grid-cols-2 border-t border-border/60">
          <div className="px-3 py-5 sm:p-6 text-center flex flex-col items-center min-w-0">
            <div className="min-h-[96px] sm:min-h-[124px] flex items-center justify-center" data-testid={certified ? 'certified-badge' : 'trust-bar'}>
              {certified
                ? <CertifiedBadge score={scan.trust_score} size={desktop ? 'lg' : 'md'} />
                : <TrustBar score={scan.trust_score} scale={big} />}
            </div>
            <div className="mt-3 font-mono text-[11px] font-bold uppercase tracking-[0.16em] text-text">Trust score</div>
            <div className="mt-0.5 text-[11.5px] text-text-muted">{scoreSub ?? <>Signed<Percentile score={scan.trust_score} /></>}</div>
            {pending && (
              <span className="mt-2 inline-flex items-center gap-1.5 text-[12px] text-warning border-[1.5px] border-dashed border-warning/80 rounded-full px-2.5 py-0.5" data-testid="certified-pending">
                <span className="w-2 h-2 rounded-full border-2 border-current border-t-transparent animate-spin motion-reduce:animate-none" aria-hidden="true" />
                Certified: pending · {pending}
              </span>
            )}
          </div>
          <div className="px-3 py-5 sm:p-6 text-center flex flex-col items-center min-w-0 border-l border-border/60">
            <div className="min-h-[96px] sm:min-h-[124px] flex items-center justify-center">
              <AdoptionNeedle count={adoption?.count ?? 0} unit={adoption?.count ? adoption.unit : undefined} scorePct={adoption?.scorePct} scale={big} />
            </div>
            <div className="mt-3 font-mono text-[11px] font-bold uppercase tracking-[0.16em] gradient-text">Adoption score</div>
            <div className="mt-0.5 text-[11.5px] text-text-muted">{adoption?.sub || 'No usage data'}</div>
          </div>
        </div>
        <div className="px-6 py-3 border-t border-border/60 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px]">
          {signed && <span className="text-success font-mono text-[11.5px]">✓ Signed · Ed25519 / JWS</span>}
          {share && <a href="#share" className="font-semibold text-primary-light hover:text-primary">Share this result</a>}
          <a href="#verify" onClick={openVerify} className="font-semibold text-primary-light hover:text-primary">Verify it yourself ↓</a>
        </div>
      </div>
    </Reveal>
  )
}

// ── sections ────────────────────────────────────────────────────────────────────

export function Section({ id, title, sub, children }: { id?: string; title: string; sub?: ReactNode; children: ReactNode }) {
  return (
    <section id={id} className="mt-12 scroll-mt-24">
      <Reveal>
        <h2 className="text-[22px] font-bold tracking-tight">{title}</h2>
        {sub && <p className="mt-1 text-[13.5px] text-text-muted max-w-[68ch]">{sub}</p>}
      </Reveal>
      {children}
    </section>
  )
}

/** A panel that has nothing to show says so plainly instead of disappearing. */
export function EmptyPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl px-6 py-4">
        <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">{title}</h3>
        <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">{children}</p>
      </div>
    </Reveal>
  )
}

function FindingsSection({ scan, allFindings, intro }: { scan: Obj; allFindings: ReactNode; intro?: ReactNode }) {
  const [all, setAll] = useState(false)
  const top = topFindings(scan, 3)
  const total = Number(asObj(scan.findings).total ?? ((asObj(scan.findings).items as unknown[] | undefined)?.length ?? 0))
  const gaps = coverageGapNotes(scan).length > 0
  return (
    <Section id="findings" title="What the check found">
      {intro}
      {top.length === 0 ? (
        <Reveal><div className="mt-4 glass rounded-2xl p-5 text-[14px] text-success">✓ Nothing found in what we read.{gaps ? ' See what we couldn’t check below.' : ''}</div></Reveal>
      ) : (
        <div className="mt-4 flex flex-col gap-2.5" data-testid="top-findings">
          {top.map((it, i) => {
            const sev = (it.severity || 'info').toLowerCase()
            const fix = fixText(it)
            return (
              <Reveal key={i}>
                <div className={`glass rounded-xl px-4 py-3.5 flex gap-3 items-start ${sev === 'critical' ? 'border border-danger/40' : ''}`}>
                  <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV_CLASS[sev] || SEV_CLASS.info}`}>{sev}</span>
                  <div className="min-w-0">
                    <div className="text-[14.5px] font-semibold">{it.name}</div>
                    {it.file_path && <div className="font-mono text-[11.5px] text-text-muted break-all">{it.file_path}{it.line_number ? `:${it.line_number}` : ''}{it.category ? <span className="font-sans"> · category: {it.category.replace(/_/g, ' ')}</span> : null}{it.shipped === false ? <span className="font-sans"> · in tests</span> : null}</div>}
                    {fix && <div className="mt-1 text-[13px] text-text-muted"><b className="text-text">Fix:</b> {fix}</div>}
                  </div>
                </div>
              </Reveal>
            )
          })}
        </div>
      )}
      <button type="button" onClick={() => setAll((v) => !v)} aria-expanded={all}
        className="mt-3 text-[13px] font-semibold text-primary-light hover:text-primary">
        {all ? 'Hide the full list ▴' : total > 0 ? `See all ${total} finding${total === 1 ? '' : 's'} →` : 'See the full breakdown →'}
      </button>
      {all && <div data-testid="all-findings">{allFindings}</div>}
    </Section>
  )
}

function oversizedFiles(scan: Obj): string[] {
  const items = (asObj(scan.findings).items as TopFinding[] | undefined) ?? []
  return Array.from(new Set(items.filter((i) => /too large to scan in full|over 500 KB/i.test(i.name || '') && i.file_path).map((i) => i.file_path as string)))
}

function GapsSection({ scan, extra, panel }: { scan: Obj; extra?: ReactNode[]; panel?: ReactNode }) {
  const sandbox = sandboxSummary(scan)
  const notes = coverageGapNotes(scan).filter((n) => !(sandbox && n.startsWith('the sandbox')))
  const big = oversizedFiles(scan)
  const rows: ReactNode[] = notes.map((n, i) => (
    <p key={`g${i}`}><b>{cap(n)}</b>{/over 500 KB/.test(n) && big.length ? <> (<code className="font-mono text-[12px]">{big.slice(0, 3).join(', ')}</code>)</> : null}.</p>
  ))
  if (sandbox) rows.push(<p key="sb"><b>Sandbox:</b> {sandbox.replace(/^Sandbox: /, '')}.</p>)
  for (const [i, x] of (extra ?? []).entries()) rows.push(<div key={`x${i}`}>{x}</div>)
  return (
    <Section id="not-checked" title="What we couldn't check">
      <Reveal>
        <div className={`mt-4 glass rounded-2xl px-5 py-4 flex flex-col gap-2 text-[13.5px] text-text-muted ${notes.length ? 'border border-warning/35' : ''}`} data-testid="not-checked">
          {rows.length ? rows : <p className="text-success">✓ Everything was read.</p>}
        </div>
      </Reveal>
      {panel}
    </Section>
  )
}

const BTN = 'inline-flex items-center justify-center gap-1.5 text-[13px] font-semibold px-3.5 py-2 rounded-xl transition-colors'
export const BTN_GHOST = `${BTN} border border-border text-text hover:border-primary-light hover:text-primary-light`

/** One numbered step. */
function Step({ n, title, children, id }: { n: number; title?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <li id={id} className="glass rounded-2xl p-4 sm:p-5 grid grid-cols-[30px_minmax(0,1fr)] max-[480px]:grid-cols-[minmax(0,1fr)] gap-3 scroll-mt-24" data-step={n}>
      <span className="w-[26px] h-[26px] rounded-full grid place-items-center font-mono text-[12.5px] font-bold text-primary-light border-[1.5px] border-primary-light" aria-hidden="true">{n}</span>
      <div className="min-w-0">
        {title && <h3 className="text-[16px] font-bold tracking-tight">{title}</h3>}
        {children}
      </div>
    </li>
  )
}

/** The four next steps (approved mock, Kenne's order, 2026-11-10). A step whose action
 * doesn't exist for this result is left out, and the rest renumber. Watch and the badge
 * appear once each on the page. Exported for the couldn't-check pages, which only have
 * step 3. */
export function NextSteps({ dnc = false, watch, ownerStep, badge = false, install, installed = true }: {
  dnc?: boolean; watch?: ReactNode; ownerStep?: OwnerStep; badge?: boolean
  install?: ReactNode
  /** false hides step 4 entirely (no stored result to install from) */
  installed?: boolean
}) {
  const steps: { key: string; title?: ReactNode; id?: string; body: ReactNode }[] = []
  if (watch) {
    steps.push({ key: 'watch', title: 'Keep an eye on it', id: 'watch-it', body: <>
      <p className="mt-1 text-[14px] text-text-muted max-w-[64ch]">Get an email or a signed webhook when the answer gets worse, the Certified mark comes off, the score drops, or its tool definitions change. We re-check watched tools every day.</p>
      <div className="mt-3 max-w-[420px]">{watch}</div>
    </> })
  }
  if (ownerStep) {
    steps.push({ key: 'owner', title: 'Is this yours?', id: 'claim', body: <>
      <p className="mt-1 text-[14px] text-text-muted max-w-[64ch]">{ownerStep.text}</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        {ownerStep.actions}
        {badge && <a href="#badge" className={BTN_GHOST}>Add the badge ↓</a>}
      </div>
    </> })
  }
  steps.push({ key: 'agentavow', title: dnc ? 'Stop tools like this automatically' : 'Check tools like this automatically', body: <>
    <p className="mt-1 text-[14px] text-text-muted">Get AgentAvow where you work. Pick one and we&apos;ll remember it.</p>
    <AgentAvowChooser dnc={dnc} />
  </> })
  if (installed && (dnc || install)) {
    steps.push({ key: 'install', body: dnc
      ? <><h3 className="text-[16px] font-bold tracking-tight">How to install this tool</h3><p className="mt-1 text-[14px] text-text-muted">No install line on a Do not connect result.</p></>
      : install })
  }
  return (
    <ol className="mt-4 flex flex-col gap-3 list-none p-0" data-testid="next-steps">
      {steps.map((st, i) => <Step key={st.key} n={i + 1} title={st.title} id={st.id}>{st.body}</Step>)}
    </ol>
  )
}

/** "Is <tool> safe to connect?" with the eyebrow line and the banner slot above it. */
export function ResultTitle({ banner, eyebrow, version, checked, recheck, name, chips, intro }: {
  banner?: ReactNode; eyebrow: string[]; version?: ReactNode; checked?: string; recheck?: ResultRecheck
  name: string; chips?: ReactNode; intro?: ReactNode
}) {
  return (
    <>
      {banner}
      <p className="mt-2 font-mono text-[12px] text-text-muted flex flex-wrap items-center gap-x-1.5 gap-y-1 break-all" data-testid="eyebrow">
        {eyebrow.filter(Boolean).map((e, i) => <span key={i}>{i > 0 && <span className="mr-1.5 text-text-muted/50">·</span>}{e}</span>)}
        {version && <span><span className="mr-1.5 text-text-muted/50">·</span>{version}</span>}
        {checked && <span><span className="mr-1.5 text-text-muted/50">·</span>checked {checked}</span>}
        {recheck && (
          <span><span className="mr-1.5 text-text-muted/50">·</span>
            <button type="button" onClick={recheck.run} disabled={recheck.pending} className="text-primary-light hover:text-primary disabled:opacity-60" title="Run a fresh check (rate-limited)">
              {recheck.pending ? 'Re-checking…' : 'Re-check'}
            </button>
            {recheck.error && <span className="ml-1.5 text-danger">couldn&apos;t re-check now, try again later</span>}
          </span>
        )}
      </p>
      <h1 className="mt-2 text-[28px] sm:text-[34px] font-extrabold tracking-tight leading-tight break-words">Is <span className="break-all">{name}</span> safe to connect?</h1>
      {chips && <div className="mt-2.5 flex items-center gap-2 flex-wrap">{chips}</div>}
      {intro}
    </>
  )
}

export function ResultPage(props: ResultPageProps) {
  const { scan, kind, adoption, privateScan } = props
  const d = decisionOf(scan)
  const oneTime = privateScan === 'one-time'
  const dnc = d.decision === 'do_not_connect'
  const kw = props.keepWatching ?? {}
  const canShare = !!props.sharePanel || !!props.shareAnchor
  return (
    <div className="max-w-[860px] mx-auto px-6 py-14" data-result-kind={kind}>
      <ResultTitle banner={props.banner} eyebrow={props.eyebrow} version={props.version} checked={checkedAgo(scan.scanned_at)}
        recheck={props.recheck} name={props.name} chips={props.chips} intro={props.intro} />

      {/* 1 + 2 · the answer and the two scores (the Certified badge in the trust slot) */}
      <AnswerCard scan={scan} kind={kind} adoption={adoption} share={canShare} />

      {/* 3 · why it's Certified, or which check is missing; the deciding line last */}
      <CertifiedChecklist scan={scan} kind={kind} decision={d} />

      {/* 4 · top 3 findings with fixes, then all of them */}
      <FindingsSection scan={scan} allFindings={props.allFindings} intro={props.findingsIntro} />

      {/* 5 · what we couldn't check */}
      <GapsSection scan={scan} extra={props.gapNotes} panel={props.gapPanel} />

      {/* 6 · next steps: watch · is this yours? · AgentAvow · install this tool */}
      <Section id="next-steps" title="Next steps">
        <NextSteps dnc={dnc} watch={oneTime ? undefined : props.watch} ownerStep={props.ownerStep}
          badge={!oneTime && !!props.badgeMarkdown && !!props.badges} install={props.install} />
      </Section>

      {/* 7 · keep watching it (Watch itself is step 1, once) */}
      <Section id="watch" title="Keep watching it" sub={oneTime ? 'Nothing is stored for a one-time scan, so there is no history to keep.' : 'History, adoption and changes over time.'}>
        {kw.note}
        {kw.history}
        {kw.adoption}
        {kw.drift}
      </Section>

      {/* 8 · what's inside */}
      <Section id="inside" title="What's inside" sub="What the tool can do, what the sandbox saw, and what it depends on.">
        {props.inside}
      </Section>

      {/* 9 · badges (step 2's "Add the badge" lands here), then the share panel */}
      {(props.badges || props.sharePanel) && (
        <Section id="badge" title={props.badges ? 'Badges' : 'Share'}>
          {props.badges}
          {props.sharePanel}
        </Section>
      )}

      {/* 10 · verify it yourself (collapsed) */}
      <VerifyItYourself scan={scan} proof={props.proof} whatWeChecked={props.whatWeChecked} />
    </div>
  )
}

function VerifyItYourself({ scan, proof, whatWeChecked }: { scan: Obj; proof?: ReactNode; whatWeChecked?: ReactNode }) {
  const downloadJson = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url; a.download = 'scan.json'; a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <details id="verify" className="mt-12 glass rounded-2xl px-5 py-4 group scroll-mt-24" data-testid="verify-it-yourself">
      <summary className="cursor-pointer list-none flex items-baseline justify-between gap-3 flex-wrap">
        <span className="text-[16px] font-bold">Verify it yourself <span className="font-normal text-[13px] text-text-muted">signed proof, raw details, what we checked</span></span>
        <span className="text-text-muted text-[12px] group-open:rotate-180 transition-transform" aria-hidden="true">▾</span>
      </summary>
      {proof}
      {whatWeChecked}
      <div className="mt-4 flex items-center gap-2 flex-wrap text-[12.5px] text-text-muted">
        <span>The scan&apos;s raw data:</span>
        <button type="button" onClick={downloadJson} className="font-mono text-[10.5px] px-2 py-0.5 rounded bg-surface-hover border border-border text-text-muted hover:text-primary-light">download scan.json</button>
      </div>
    </details>
  )
}
