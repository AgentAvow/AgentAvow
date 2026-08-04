import { useParams, Link } from 'react-router-dom'

/**
 * Rebrand Legal shell (Terms / Privacy / DMCA / Moderation) — re-skinned + navigable.
 * The binding legal TEXT is NOT written here: the current live terms are social-era
 * ("content you post on the Platform") and must be rewritten for the AgentAvow entity +
 * the trust/scan product, then reviewed by counsel. This page carries plain-language
 * summaries + the flag until that pass happens at cutover.
 */

const SECTIONS = [
  { path: 'terms', label: 'Terms of Service' },
  { path: 'privacy', label: 'Privacy Policy' },
  { path: 'dmca', label: 'DMCA' },
  { path: 'moderation-policy', label: 'Moderation' },
]

const SUMMARY: Record<string, { title: string; contact: string; points: string[] }> = {
  terms: {
    title: 'Terms of Service',
    contact: 'legal@agentavow.com',
    points: [
      'Scanning tools, MCP servers, and packages is free and requires no account.',
      'Scan results and grades are provided as-is, on a best-effort basis — they inform a decision, they are not a warranty.',
      'An account is only needed for watch/alerts and claiming your own repos.',
      'Don\'t abuse the service (no scraping to resell, no attempts to evade rate limits).',
    ],
  },
  privacy: {
    title: 'Privacy Policy',
    contact: 'privacy@agentavow.com',
    points: [
      'Checking a tool is anonymous — no account, no tracking required to get a result.',
      'If you create an account, we store your email to send the alerts you asked for.',
      'We don\'t sell your data.',
      'Scan results about public tools/repos are public.',
    ],
  },
  dmca: { title: 'DMCA', contact: 'legal@agentavow.com', points: ['Report claimed infringement to legal@agentavow.com with the required details.'] },
  'moderation-policy': { title: 'Moderation', contact: 'abuse@agentavow.com', points: ['Report abuse or a bad actor to abuse@agentavow.com.'] },
}

export default function RebrandLegal() {
  const { section } = useParams()
  const key = section && SUMMARY[section] ? section : 'terms'
  const s = SUMMARY[key]

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14 grid md:grid-cols-[200px_1fr] gap-10">
      <aside className="md:sticky md:top-[86px] self-start flex flex-col gap-1">
        {SECTIONS.map((sec) => (
          <Link
            key={sec.path}
            to={`/rebrand/legal/${sec.path}`}
            className={`text-[14px] px-3 py-2 rounded-lg transition-colors ${
              key === sec.path ? 'bg-primary/10 text-primary-light font-medium' : 'text-text-muted hover:text-text hover:bg-surface'
            }`}
          >
            {sec.label}
          </Link>
        ))}
      </aside>

      <article className="min-w-0">
        <div className="glass rounded-xl px-4 py-3 mb-6 text-[13px] text-warning border border-warning/30">
          ⚠️ Draft — plain-language summary only. The full AgentAvow {s.title.toLowerCase()} is being rewritten
          for the new entity + the trust/scan product and reviewed before launch.
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight">{s.title}</h1>
        <p className="mt-2 text-text-muted text-[14px]">In plain language, here's what to expect:</p>
        <ul className="list-disc pl-5 mt-4 space-y-2 text-text-muted">
          {s.points.map((p) => <li key={p} className="leading-relaxed">{p}</li>)}
        </ul>
        <p className="mt-8 text-[14px] text-text-muted">Questions? <a href={`mailto:${s.contact}`} className="text-primary-light hover:text-primary">{s.contact}</a></p>
      </article>
    </div>
  )
}
