/**
 * Plain-English scan summary for non-technical users. Deterministic — derived
 * straight from the scan data (no LLM, nothing to leak, nothing to hallucinate).
 * The goal: anyone can read this and decide "is this safe for me?" in ten seconds.
 */

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
  findings?: { total?: number; critical?: number; high?: number } | null
  category_scores?: Record<string, number> | null
  positive_signals?: string[] | null
  metadata?: { primary_language?: string | null; files_scanned?: number | null } | null
}

export interface PlainSummary {
  verdict: 'safe' | 'ok' | 'caution' | 'risky'
  headline: string
  paragraph: string
  goodPractices: string[]
  risks: string[]
  facts: string[]
}

export function summarize(s: ScanLike, repo: string): PlainSummary {
  const score = s.trust_score
  const crit = s.findings?.critical ?? 0
  const high = s.findings?.high ?? 0
  const total = s.findings?.total ?? 0
  const cats = s.category_scores ?? {}

  // Aligned to the trust tiers: Trusted (≥80) · Standard (≥60) · Caution (≥40) · below.
  // A solid Standard-tier tool reads as "generally safe", not "caution" — the old
  // safe≥81/caution≥51 split (calibrated for inflated scores) mislabelled the whole
  // 60–80 band as caution.
  const verdict: PlainSummary['verdict'] =
    score >= 80 ? 'safe' : score >= 60 ? 'ok' : score >= 40 ? 'caution' : 'risky'
  const headline =
    verdict === 'safe' ? 'Looks safe to connect'
    : verdict === 'ok' ? 'Generally safe to connect'
    : verdict === 'caution' ? 'Connect with caution'
    : 'Think twice before connecting'

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
    paragraph = `We scanned ${short} across 12 safety categories and found nothing alarming. It follows good security practices and carries a signed, verifiable score — reasonable to connect to your agent.`
  } else if (verdict === 'safe') {
    paragraph = `${short} scored well overall. We found ${total} minor thing${total === 1 ? '' : 's'} but no critical risks — it follows solid security practices and is generally safe to connect.`
  } else if (verdict === 'ok') {
    paragraph = `${short} scored solidly. We flagged ${total} thing${total === 1 ? '' : 's'} worth a glance${high ? `, ${high} of them higher-severity` : ''} but nothing critical — generally safe to connect once you've skimmed the details below.`
  } else if (verdict === 'caution') {
    paragraph = `${short} is a mixed bag. It does some things well, but we flagged ${total} issue${total === 1 ? '' : 's'}${high ? `, including ${high} worth reviewing` : ''}. Read the details below before you connect it to anything sensitive.`
  } else {
    paragraph = `We'd be careful with ${short}. Our scan found ${total} issue${total === 1 ? '' : 's'}${crit ? `, including ${crit} critical one${crit > 1 ? 's' : ''}` : ''}. Unless you know exactly what you're doing, this isn't one to connect to your agent.`
  }

  const facts: string[] = ['Scanned across 12 safety categories', 'Result is signed (Ed25519) and verifiable offline']
  if (s.metadata?.files_scanned) facts.unshift(`${s.metadata.files_scanned.toLocaleString()} files analyzed`)
  if (s.metadata?.primary_language) facts.unshift(`Mostly ${s.metadata.primary_language}`)

  return { verdict, headline, paragraph, goodPractices: goodPractices.slice(0, 5), risks: risks.slice(0, 5), facts }
}
