import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { rp } from '../basePath'
import { publicApi } from '../../lib/scanApi'
import { trackBadgeCopied } from '../../lib/analytics'
import { CHATGPT_LISTING, CLAUDE_LISTING, trackListing } from '../lib/listings'
import { coverageGapNotes, decisionOf, decisionPhrase, isCertified, type Decision } from '../../components/trust/gradeSystem'
import { TrustBar, AdoptionNeedle } from './TrustMark'
import { Reveal } from './motion'
import { useIsDesktop } from '../lib/hooks'
import {
  certifiedRows, certifiedStatus, checkedAgo, fixText, sandboxSummary, topFindings,
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
 *   1  the answer and its reason, with the CERTIFIED mark (here only)
 *   2  trust score and adoption score
 *   3  the slim Certified checklist
 *   4  what the check found: top 3 findings with fixes, then all findings
 *   5  what we couldn't check
 *   6  next steps
 *   7  keep watching it
 *   8  what's inside
 *   9  badge, claim and share
 *   10 verify it yourself (collapsed)
 *
 * The answer is the API's own decision read through gradeSystem.decisionOf (the twin of
 * src/scanner/verdict.py decide()); the mark is isCertified. Nothing here re-decides.
 * Type-specific panels come in as slots; the order and headings are fixed here.
 */

/** Where "Get this check automatically" points: the Claude Code landing page. */
const CLAUDE_CODE_PAGE = '/rebrand/claude-code'


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
  /** install / connect block (hidden on Do not connect) */
  install?: ReactNode
  /** the watch button (absent for a one-time private scan) */
  watch?: ReactNode
  /** markdown for "Copy the badge" (absent where there is no public badge) */
  badgeMarkdown?: string
  keepWatching?: { history?: ReactNode; adoption?: ReactNode; drift?: ReactNode; note?: ReactNode }
  inside: ReactNode
  badgeClaimShare: ReactNode
  /** the "What we checked" facts, inside Verify it yourself */
  whatWeChecked?: ReactNode
  /** the signed proof (VerifyPanel) */
  proof?: ReactNode
  /** the incident / deprecation banner, above the title */
  banner?: ReactNode
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
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl px-5 py-4" data-testid="certified-checklist">
        <div className="flex items-baseline justify-between gap-3 flex-wrap">
          <div className="text-[14.5px]"><b>{st.lead}</b>{st.rest && <span className="text-text-muted"> · {st.rest}</span>}</div>
          <Link to={rp('/rebrand/certified')} className="text-[12.5px] font-semibold text-primary-light hover:text-primary">What Certified means →</Link>
        </div>
        <ul className="mt-3 grid sm:grid-cols-2 gap-x-5 gap-y-2.5">
          {rows.map((r) => (
            <li key={r.label} className="flex items-start gap-2.5 text-[13px]" data-state={r.state}>
              <span className={`font-mono text-[10px] font-bold tracking-wide px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${ROW_STYLE[r.state].cls}`}>{ROW_STYLE[r.state].tag}</span>
              <span className="min-w-0"><span className="text-text">{r.label}</span><span className="block text-[11.5px] text-text-muted break-words">{r.evidence}</span></span>
            </li>
          ))}
        </ul>
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

function AnswerCard({ scan, kind, adoption }: { scan: ResultPageProps['scan']; kind: ResultKind; adoption: ResultAdoption | null }) {
  const d = decisionOf(scan)
  const p = decisionPhrase(d.decision)
  const st = ANSWER_STYLE[d.decision]
  const certified = isCertified(scan)
  const eligible = asObj(scan.certified).eligible === true
  const big = useIsDesktop() ? 1.35 : 1
  const crit = Number(asObj(scan.findings).critical ?? 0)
  const reason = d.reason ? cap(d.reason) + '.' : ''
  const scoreSub = kind === 'mcp'
    ? 'Signed · scored on the tools it serves, not its server code'
    : crit > 0 && scan.trust_score <= 45 ? 'Signed · a critical finding caps the score at 45' : null
  return (
    <Reveal>
      <div className={`mt-6 glass rounded-2xl border ${st.border} overflow-hidden`} data-decision={d.decision} data-testid="answer-card">
        <div className="px-6 pt-6 pb-5">
          <div className={`flex items-center gap-2.5 flex-wrap text-[22px] sm:text-[26px] font-extrabold tracking-tight leading-tight ${st.fg}`}>
            <span aria-hidden="true">{st.icon}</span>
            <span>{p.phrase}</span>
            {certified && <span className="font-mono text-[11px] font-bold tracking-[0.14em] px-2 py-1 rounded-md text-white bg-gradient-to-r from-primary to-accent" data-testid="certified-mark">CERTIFIED</span>}
            {!d.final && eligible && d.decision === 'safe' && <span className="font-mono text-[11px] font-bold tracking-[0.14em] px-2 py-1 rounded-md border border-primary/50 text-primary-light">CERTIFIED · PENDING</span>}
            {!d.final && <span className="font-mono text-[10.5px] uppercase tracking-wide px-2 py-1 rounded-md bg-surface border border-border text-text-muted">provisional</span>}
          </div>
          <p className="mt-2 text-[14.5px] text-text-muted max-w-[68ch]">
            {reason}
            {!d.final && (asObj(scan.behavioral).state === 'queued' ? ' This answer can still change when the sandbox runs it.' : ' The sandbox is running this version now, so this answer can still change. Usually under a minute.')}
          </p>
        </div>
        <div className="grid grid-cols-2 border-t border-border/60">
          <div className="px-3 py-5 sm:p-6 text-center flex flex-col items-center min-w-0">
            <div className="min-h-[96px] sm:min-h-[124px] flex items-center justify-center"><TrustBar score={scan.trust_score} scale={big} /></div>
            <div className="mt-3 font-mono text-[11px] font-bold uppercase tracking-[0.16em] text-text">Trust score</div>
            <div className="mt-0.5 text-[11.5px] text-text-muted">{scoreSub ?? <>Signed<Percentile score={scan.trust_score} /></>}</div>
          </div>
          <div className="px-3 py-5 sm:p-6 text-center flex flex-col items-center min-w-0 border-l border-border/60">
            <div className="min-h-[96px] sm:min-h-[124px] flex items-center justify-center">
              <AdoptionNeedle count={adoption?.count ?? 0} unit={adoption?.count ? adoption.unit : undefined} scorePct={adoption?.scorePct} scale={big} />
            </div>
            <div className="mt-3 font-mono text-[11px] font-bold uppercase tracking-[0.16em] gradient-text">Adoption score</div>
            <div className="mt-0.5 text-[11.5px] text-text-muted">{adoption?.sub || 'No usage data'}</div>
          </div>
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

function StepCard({ title, text, children, lead = false }: { title: string; text: string; children: ReactNode; lead?: boolean }) {
  return (
    <div className={`glass rounded-2xl p-5 flex flex-col ${lead ? 'border border-primary/40' : ''}`}>
      <h3 className="text-[15px] font-bold">{title}</h3>
      <p className="mt-1 text-[13px] text-text-muted flex-1">{text}</p>
      <div className="mt-4 flex flex-wrap gap-2">{children}</div>
    </div>
  )
}

const BTN = 'inline-flex items-center justify-center gap-1.5 text-[13px] font-semibold px-3.5 py-2 rounded-xl transition-colors'
const BTN_SOLID = `${BTN} text-white bg-gradient-to-r from-primary to-primary-dark`
const BTN_GHOST = `${BTN} border border-border text-text hover:border-primary-light hover:text-primary-light`

/** The first two next-step cards (Claude Code, and Claude / ChatGPT). Exported for the
 * couldn't-check page, which has no stored result to watch. */
export function NextStepCards({ dnc = false, watch, badgeMarkdown, oneTime = false }: { dnc?: boolean; watch?: ReactNode; badgeMarkdown?: string; oneTime?: boolean }) {
  const [copied, setCopied] = useState(false)
  const copyBadge = () => {
    if (!badgeMarkdown) return
    void navigator.clipboard?.writeText(badgeMarkdown)
    trackBadgeCopied('badge')
    setCopied(true); setTimeout(() => setCopied(false), 1400)
  }
  return (
    <div className={`mt-4 grid gap-3 ${oneTime ? 'md:grid-cols-2' : 'md:grid-cols-3'}`} data-testid="next-steps">
      <StepCard lead title={dnc ? 'Stop tools like this automatically' : 'Get this check automatically'}
        text={dnc ? 'Claude Code asks you first before a server or package that reads Do not connect is added.' : 'Claude Code checks new MCP servers and packages before your agent uses them.'}>
        <Link to={rp(CLAUDE_CODE_PAGE)} className={BTN_SOLID}>Get it for Claude Code</Link>
      </StepCard>
      <StepCard title="Ask in Claude or ChatGPT" text="Add AgentAvow and ask before you connect anything.">
        <a href={CLAUDE_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CLAUDE_LISTING)} className={BTN_GHOST}>Add to Claude ↗</a>
        <a href={CHATGPT_LISTING} target="_blank" rel="noopener noreferrer" onClick={() => trackListing(CHATGPT_LISTING)} className={BTN_GHOST}>Add to ChatGPT ↗</a>
      </StepCard>
      {!oneTime && (
        <StepCard title="Keep an eye on it" text="Get an alert if this answer drops or its tool definitions change.">
          {watch}
          {badgeMarkdown
            ? <button type="button" onClick={copyBadge} className={BTN_GHOST}>{copied ? 'Copied ✓' : 'Copy the badge'}</button>
            : <a href="#badge" className={BTN_GHOST}>Badge options ↓</a>}
        </StepCard>
      )}
    </div>
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
  return (
    <div className="max-w-[860px] mx-auto px-6 py-14" data-result-kind={kind}>
      <ResultTitle banner={props.banner} eyebrow={props.eyebrow} version={props.version} checked={checkedAgo(scan.scanned_at)}
        recheck={props.recheck} name={props.name} chips={props.chips} intro={props.intro} />

      {/* 1 + 2 · the answer (CERTIFIED here only) and the two scores */}
      <AnswerCard scan={scan} kind={kind} adoption={adoption} />

      {/* 3 · why it's Certified, or which check is missing */}
      <CertifiedChecklist scan={scan} kind={kind} decision={d} />

      {/* 4 · top 3 findings with fixes, then all of them */}
      <FindingsSection scan={scan} allFindings={props.allFindings} intro={props.findingsIntro} />

      {/* 5 · what we couldn't check */}
      <GapsSection scan={scan} extra={props.gapNotes} panel={props.gapPanel} />

      {/* 6 · next steps */}
      <Section id="next-steps" title="Next steps">
        <NextStepCards dnc={dnc} watch={props.watch} badgeMarkdown={props.badgeMarkdown} oneTime={oneTime} />
        {!dnc && props.install}
        <p className="mt-3 text-[12.5px] text-text-muted">
          {dnc && 'No install line on a Do not connect result · '}
          {!oneTime && <><a href="#share" className="text-primary-light hover:text-primary">Share this result</a> · </>}
          <a href="#claim" className="text-primary-light hover:text-primary">{privateScan ? 'Claim or publish it' : 'Claim this tool'}</a>
        </p>
      </Section>

      {/* 7 · keep watching it */}
      <Section id="watch" title="Keep watching it" sub={oneTime ? 'Nothing is stored for a one-time scan, so there is no history to keep.' : 'History, adoption and changes over time.'}>
        {kw.note}
        {kw.history}
        {kw.adoption}
        {kw.drift}
        {!oneTime && props.watch && (
          <Reveal>
            <div className="mt-4 glass rounded-2xl p-6">
              <h3 className="text-[13px] font-mono uppercase tracking-wide text-text-muted">Watch this tool</h3>
              <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">Get an email or a signed webhook when the answer drops, the Certified mark comes off, or a tool definition changes. We re-check watched tools every day.</p>
              <div className="mt-3 max-w-[420px]">{props.watch}</div>
            </div>
          </Reveal>
        )}
      </Section>

      {/* 8 · what's inside */}
      <Section id="inside" title="What's inside" sub="What the tool can do, what the sandbox saw, and what it depends on.">
        {props.inside}
      </Section>

      {/* 9 · badge, claim and share */}
      <Section id="badge" title="Badge, claim and share">
        {props.badgeClaimShare}
      </Section>

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
    <details className="mt-12 glass rounded-2xl px-5 py-4 group" data-testid="verify-it-yourself">
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
