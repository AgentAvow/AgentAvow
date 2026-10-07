/**
 * Plain-English scan summary for non-technical users. Deterministic — derived
 * straight from the scan data (no LLM, nothing to leak, nothing to hallucinate).
 * The goal: anyone can read this and decide "is this safe for me?" in ten seconds.
 */
import { decisionOf, decisionPhrase, isCertified, type DecisionValue } from '../../components/trust/gradeSystem'

const CAT_HUMAN: Record<string, { good: string; weak: string }> = {
  secret_hygiene: { good: 'keeps secrets and API keys out of its code', weak: 'may expose secrets or API keys' },
  code_safety: { good: 'avoids dangerous code execution', weak: 'runs code in ways that can be risky' },
  data_handling: { good: 'handles your data carefully', weak: 'moves data around in risky ways' },
  filesystem_access: { good: 'stays within safe file boundaries', weak: 'reaches into files it may not need' },
  dependency_health: { good: 'uses healthy, up-to-date dependencies', weak: 'relies on outdated or risky dependencies' },
}

export interface ScanLike {
  trust_score: number
  trust_tier?: string
  decision?: string | null
  decision_final?: boolean | null
  decision_reason?: string | null
  certified?: { eligible?: boolean } | null
  findings?: { total?: number; critical?: number; high?: number } | null
  category_scores?: Record<string, number> | null
  positive_signals?: string[] | null
  metadata?: { primary_language?: string | null; files_scanned?: number | null } | null
}

export interface PlainSummary {
  /** The three-phrase decision — the same value the verdict banner (VerdictBadge) shows. */
  verdict: DecisionValue
  /** "Safe to connect" / "Review before you connect" / "Do not connect" (+ " · Certified"). */
  headline: string
  /** The one condition that triggered the decision. */
  reason: string
  paragraph: string
  goodPractices: string[]
  risks: string[]
  facts: string[]
}

export function summarize(s: ScanLike, repo: string): PlainSummary {
  const crit = s.findings?.critical ?? 0
  const high = s.findings?.high ?? 0
  const total = s.findings?.total ?? 0
  const cats = s.category_scores ?? {}

  // ONE decision drives the headline AND the verdict banner (gradeSystem.decisionOf
  // reads the API's `decision`, else applies the same rule), so the two can never
  // disagree. The score and tier are evidence underneath, not the headline.
  const d = decisionOf(s)
  const verdict = d.decision
  const headline = decisionPhrase(verdict).phrase + (isCertified(s) ? ' · Certified' : '')
  const reason = d.reason

  // Good practices — from the categories it scored well on, plus any clean signals.
  const goodPractices: string[] = []
  for (const [key, meta] of Object.entries(CAT_HUMAN)) {
    const sc = cats[key]
    if (sc != null && sc >= 80) goodPractices.push(`It ${meta.good}.`)
  }
  if (s.positive_signals) {
    for (const p of s.positive_signals.slice(0, 3)) goodPractices.push(p)
  }

  // Risks — from weak categories + finding counts.
  const risks: string[] = []
  if (crit > 0) risks.push(`${crit} critical issue${crit > 1 ? 's' : ''} that could put you at real risk.`)
  if (high > 0) risks.push(`${high} high-severity issue${high > 1 ? 's' : ''} worth a closer look.`)
  for (const [key, meta] of Object.entries(CAT_HUMAN)) {
    const sc = cats[key]
    if (sc != null && sc < 50) risks.push(`It ${meta.weak}.`)
  }

  // The paragraph — plain, direct, no jargon.
  const short = repo.split('/').pop() || repo
  let paragraph: string
  if (verdict === 'safe' && total === 0) {
    paragraph = `We scanned ${short} across 12 safety categories and found nothing blocking. It carries a signed, verifiable score — safe to connect to your agent.`
  } else if (verdict === 'safe') {
    paragraph = `${short} has no critical or high findings. We noted ${total} minor thing${total === 1 ? '' : 's'}, listed below for context — safe to connect.`
  } else if (verdict === 'review') {
    paragraph = `Review ${short} before you connect it: ${reason}. ${high ? `The high-severity finding${high === 1 ? ' is' : 's are'} listed below with the file and line.` : 'The details below say what to check.'}`
  } else {
    paragraph = `Do not connect ${short}: ${reason}. ${crit ? `The critical finding${crit === 1 ? ' is' : 's are'} listed below with the file and line.` : 'The details below say what was found.'}`
  }

  const facts: string[] = ['Scanned across 12 safety categories', 'Result is signed (Ed25519) and verifiable offline']
  if (s.metadata?.files_scanned) facts.unshift(`${s.metadata.files_scanned.toLocaleString()} files analyzed`)
  if (s.metadata?.primary_language) facts.unshift(`Mostly ${s.metadata.primary_language}`)

  return { verdict, headline, reason, paragraph, goodPractices: goodPractices.slice(0, 5), risks: risks.slice(0, 5), facts }
}
