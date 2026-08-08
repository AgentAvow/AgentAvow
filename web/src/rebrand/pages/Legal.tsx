import { useParams, Link } from 'react-router-dom'
import { rp } from '../basePath'

/**
 * Rebrand Legal — real clauses ported from the existing agentgraph.co legal pages,
 * brand-swapped to AgentAvow and adapted for the trust/scan product. All four are
 * navigable here; the footer links only Terms + Privacy. This is a faithful port,
 * not fresh legal drafting.
 */

const SECTIONS = [
  { path: 'terms', label: 'Terms of Service' },
  { path: 'privacy', label: 'Privacy Policy' },
  { path: 'dmca', label: 'DMCA' },
  { path: 'moderation-policy', label: 'Moderation' },
]

interface Clause { h: string; body: React.ReactNode }

const TERMS: Clause[] = [
  { h: '1. Acceptance of Terms', body: 'By accessing or using AgentAvow (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, do not use the Service.' },
  { h: '2. The Service', body: 'AgentAvow scans tools, MCP servers, and packages and produces a signed, verifiable safety grade. Checking is free and requires no account. An account is needed only for watch/alerts, API keys, and claiming repositories you own.' },
  { h: '3. Eligibility', body: 'You must be at least 13 years of age (16 in the European Economic Area) to create an account. By registering, you represent that you meet this requirement.' },
  { h: '4. Accounts', body: (<ul className="list-disc pl-5 space-y-1 mt-1"><li>Provide accurate information when creating an account.</li><li>You are responsible for keeping your credentials and API keys secure.</li><li>Do not create accounts for spamming, impersonation, or abuse.</li><li>We may suspend or terminate accounts that violate these Terms.</li></ul>) },
  { h: '5. Scan Results — provided "as is"', body: (<><p>Scan grades and attestations are computed algorithmically and provided for informational purposes only. They inform a decision — they are not a warranty. AgentAvow does not guarantee their accuracy or completeness and is not liable for decisions made in reliance on them.</p><p className="mt-2">Grades reflect a scan at a point in time; a tool can change after it is scanned. Verify anything you depend on, and consider watching it for changes.</p></>) },
  { h: '6. Acceptable Use', body: (<ul className="list-disc pl-5 space-y-1 mt-1"><li>Do not attempt to manipulate or game grades.</li><li>Do not scrape the Service or evade rate limits.</li><li>Do not use the Service to distribute malware, phishing, or spam.</li><li>Do not attempt to circumvent security or moderation systems.</li></ul>) },
  { h: '7. Disclaimer of Warranties', body: (<p className="uppercase text-[12px] tracking-wide">The Service is provided "as is" and "as available" without warranties of any kind, express or implied, including merchantability, fitness for a particular purpose, and non-infringement. AgentAvow does not warrant that the Service will be uninterrupted, error-free, or secure.</p>) },
  { h: '8. Limitation of Liability', body: (<p className="uppercase text-[12px] tracking-wide">To the maximum extent permitted by law, AgentAvow shall not be liable for any indirect, incidental, special, consequential, or punitive damages, or loss of profits, data, or goodwill, arising from your use of or inability to use the Service. AgentAvow's aggregate liability shall not exceed one hundred U.S. dollars (US $100) or the amount you paid AgentAvow in the prior twelve months, whichever is greater.</p>) },
  { h: '9. Dispute Resolution', body: (<>Before any formal proceeding, contact us at <a href="mailto:legal@agentavow.com" className="text-primary-light hover:text-primary">legal@agentavow.com</a> and attempt to resolve the dispute informally for at least 30 days.</>) },
  { h: '10. Changes', body: 'We may update these Terms. Material changes will be posted here with an updated date. Continued use after changes constitutes acceptance.' },
  { h: '11. Contact', body: (<>Questions about these Terms: <a href="mailto:legal@agentavow.com" className="text-primary-light hover:text-primary">legal@agentavow.com</a>.</>) },
]

const PRIVACY: Clause[] = [
  { h: '1. Overview', body: 'This Policy describes what AgentAvow collects and how we use it. Checking a tool is anonymous — no account or tracking is required to get a result.' },
  { h: '2. What We Collect', body: (<ul className="list-disc pl-5 space-y-1 mt-1"><li><strong>Account data</strong> (if you register): email, display name.</li><li><strong>Watch/alert data:</strong> the tools you watch and any webhook URL you configure.</li><li><strong>Usage data:</strong> aggregate, privacy-preserving analytics about how the Service is used.</li></ul>) },
  { h: '3. How We Use It', body: (<ul className="list-disc pl-5 space-y-1 mt-1"><li>To provide scans, alerts, and the features you request.</li><li>To send the change-alerts you subscribe to.</li><li>To secure and improve the Service.</li></ul>) },
  { h: '4. Public Information', body: 'Scan results about public tools and repositories are public. Do not submit anything you consider confidential when scanning.' },
  { h: '5. Sharing', body: 'We do not sell your data. We share it only with service providers who help us run the Service, or when required by law.' },
  { h: '6. Retention & Your Rights', body: (<>We keep account data while your account is active. You may request access to or deletion of your personal data at <a href="mailto:privacy@agentavow.com" className="text-primary-light hover:text-primary">privacy@agentavow.com</a>.</>) },
  { h: '7. Contact', body: (<>Privacy questions: <a href="mailto:privacy@agentavow.com" className="text-primary-light hover:text-primary">privacy@agentavow.com</a>.</>) },
]

const DMCA: Clause[] = [
  { h: 'Copyright Infringement', body: (<>If you believe content on AgentAvow infringes your copyright, send a notice to <a href="mailto:legal@agentavow.com" className="text-primary-light hover:text-primary">legal@agentavow.com</a> with: (a) your signature; (b) identification of the work; (c) the material's location; (d) your contact information; (e) a good-faith statement; and (f) a statement, under penalty of perjury, that the notice is accurate and you are authorized to act.</>) },
  { h: 'Counter-Notice', body: 'If your material was removed in error, you may submit a counter-notice with the same contact address and the required statements.' },
]

const MODERATION: Clause[] = [
  { h: 'What we moderate', body: 'AgentAvow may remove abusive submissions, spam, or attempts to manipulate grades, and may restrict accounts that do so.' },
  { h: 'Reporting', body: (<>Report abuse or a bad actor to <a href="mailto:abuse@agentavow.com" className="text-primary-light hover:text-primary">abuse@agentavow.com</a>.</>) },
  { h: 'Appeals', body: 'If you believe a moderation action was a mistake, contact abuse@agentavow.com and we will review it.' },
]

const CONTENT: Record<string, { title: string; clauses: Clause[] }> = {
  terms: { title: 'Terms of Service', clauses: TERMS },
  privacy: { title: 'Privacy Policy', clauses: PRIVACY },
  dmca: { title: 'DMCA', clauses: DMCA },
  'moderation-policy': { title: 'Moderation Policy', clauses: MODERATION },
}

export default function RebrandLegal() {
  const { section } = useParams()
  const key = section && CONTENT[section] ? section : 'terms'
  const c = CONTENT[key]

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14 grid md:grid-cols-[200px_1fr] gap-10">
      <aside className="md:sticky md:top-[86px] self-start flex flex-col gap-1">
        {SECTIONS.map((sec) => (
          <Link
            key={sec.path}
            to={rp(`/rebrand/legal/${sec.path}`)}
            className={`text-[14px] px-3 py-2 rounded-lg transition-colors ${
              key === sec.path ? 'bg-primary/10 text-primary-light font-medium' : 'text-text-muted hover:text-text hover:bg-surface'
            }`}
          >
            {sec.label}
          </Link>
        ))}
      </aside>

      <article className="min-w-0">
        <h1 className="text-3xl font-extrabold tracking-tight">{c.title}</h1>
        <div className="mt-6 flex flex-col gap-6">
          {c.clauses.map((cl) => (
            <section key={cl.h}>
              <h2 className="text-[16px] font-semibold">{cl.h}</h2>
              <div className="mt-1.5 text-text-muted text-[14px] leading-relaxed">{cl.body}</div>
            </section>
          ))}
        </div>
      </article>
    </div>
  )
}
