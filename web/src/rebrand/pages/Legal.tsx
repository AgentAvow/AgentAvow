import { useParams, Link } from 'react-router-dom'
import { rp } from '../basePath'
import SEOHead from '../../components/SEOHead'

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

// `html` is static, first-party policy text (never user input).
interface Clause { h: string; body?: React.ReactNode; html?: string }

const TERMS: Clause[] = [
  { h: '1. Acceptance of Terms', body: 'By accessing or using AgentAvow (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, do not use the Service.' },
  { h: '2. The Service', body: 'AgentAvow scans tools, MCP servers, and packages and produces a signed, verifiable safety score. Checking is free and requires no account. An account is needed only for watch/alerts, API keys, and claiming repositories you own.' },
  { h: '3. Eligibility', body: 'You must be at least 13 years of age (16 in the European Economic Area) to create an account. By registering, you represent that you meet this requirement.' },
  { h: '4. Accounts', body: (<ul className="list-disc pl-5 space-y-1 mt-1"><li>Provide accurate information when creating an account.</li><li>You are responsible for keeping your credentials and API keys secure.</li><li>Do not create accounts for spamming, impersonation, or abuse.</li><li>We may suspend or terminate accounts that violate these Terms.</li></ul>) },
  { h: '5. Scan Results — provided "as is"', body: (<><p>Scan scores and attestations are computed algorithmically and provided for informational purposes only. They inform a decision — they are not a warranty. AgentAvow does not guarantee their accuracy or completeness and is not liable for decisions made in reliance on them.</p><p className="mt-2">Scores reflect a scan at a point in time; a tool can change after it is scanned. Verify anything you depend on, and consider watching it for changes.</p></>) },
  { h: '6. Acceptable Use', body: (<ul className="list-disc pl-5 space-y-1 mt-1"><li>Do not attempt to manipulate or game scores.</li><li>Do not scrape the Service or evade rate limits.</li><li>Do not use the Service to distribute malware, phishing, or spam.</li><li>Do not attempt to circumvent security or moderation systems.</li></ul>) },
  { h: '7. Disclaimer of Warranties', body: (<p className="uppercase text-[12px] tracking-wide">The Service is provided "as is" and "as available" without warranties of any kind, express or implied, including merchantability, fitness for a particular purpose, and non-infringement. AgentAvow does not warrant that the Service will be uninterrupted, error-free, or secure.</p>) },
  { h: '8. Limitation of Liability', body: (<p className="uppercase text-[12px] tracking-wide">To the maximum extent permitted by law, AgentAvow shall not be liable for any indirect, incidental, special, consequential, or punitive damages, or loss of profits, data, or goodwill, arising from your use of or inability to use the Service. AgentAvow's aggregate liability shall not exceed one hundred U.S. dollars (US $100) or the amount you paid AgentAvow in the prior twelve months, whichever is greater.</p>) },
  { h: '9. Dispute Resolution', body: (<>Before any formal proceeding, contact us at <a href="mailto:legal@agentavow.com" className="text-primary-light hover:text-primary">legal@agentavow.com</a> and attempt to resolve the dispute informally for at least 30 days.</>) },
  { h: '10. Changes', body: 'We may update these Terms. Material changes will be posted here with an updated date. Continued use after changes constitutes acceptance.' },
  { h: '11. Contact', body: (<>Questions about these Terms: <a href="mailto:legal@agentavow.com" className="text-primary-light hover:text-primary">legal@agentavow.com</a>.</>) },
]

// Same text as src/api/legal_router.py _PRIVACY_CLAUSES (the no-JS page). Keep both in step.
const PRIVACY: Clause[] = [
  { h: "1. Overview", html: "Effective October 23, 2026. AgentAvow checks whether a software tool is safe for an AI agent to connect to: a GitHub repository, a published package, or a live MCP server. This policy explains what we receive when you use agentavow.com, our public API, or our connector for AI assistants, what we do with it, and how long we keep it. Checking a tool does not require an account." },
  { h: "2. Using the connector in an AI assistant (MCP)", html: "<p>When an AI assistant calls one of our tools on your behalf, we receive:</p><ul><li><strong>The tool's inputs:</strong> the repository, package name and optional version, MCP server URL, or agent identifier you asked about, and whether to re-scan.</li><li><strong>Standard request data:</strong> the IP address and User-Agent of the request.</li></ul><p>Our tools accept only those inputs. We do not ask for your conversation, chat history, memories, files, name, email address, or account with the assistant, and we do not store anything beyond the inputs listed above. Your assistant decides what to put in those inputs; they are short identifiers such as a package name or URL. Some assistants attach optional hints to a request (for example a coarse location or an anonymous identifier); we do not read or store them. The connector has no sign-in.</p><p>We use the inputs only to run the check you asked for: we fetch public information about that tool from its source (GitHub, the package registry, or the MCP server itself), analyze it, and return the result. All eight tools are read-only: they never change anything in your accounts or in the tool being checked.</p>" },
  { h: "3. What our results contain", html: "Results describe the tool that was checked: an answer (Safe to connect, Review before you connect, or Do not connect) with its reason, a trust score, an adoption score, findings, and a signed attestation. They contain no personal data about you. Results for public tools are public: they may be cached, shown on agentavow.com, and listed in our public catalog. Do not submit anything you consider confidential." },
  { h: "4. Accounts and alerts (optional)", html: "If you create an account: your email address, display name, and, if you sign in with Google, the basic profile Google shares. If you watch a tool: the tools you watch and any webhook URL you configure (its signing secret is stored encrypted). If you scan a private repository with a GitHub token, the token is used for that scan only and is not stored." },
  { h: "5. Logs, metrics and analytics", html: "<ul><li><strong>Server logs</strong> (IP address, User-Agent, the requested path including the tool checked, time, status) are kept to operate and secure the service. They are rotated automatically and typically kept for less than 30 days.</li><li><strong>Usage metrics</strong> are daily counts (for example, calls per tool and per assistant product). To count distinct callers we store a one-way hash of the IP address and User-Agent combined with a salt that changes every day, not the IP address itself. Metrics are kept for up to 90 days.</li><li><strong>Website analytics</strong> use Cloudflare Web Analytics, which does not use cookies.</li><li><strong>Error reports</strong> are sent to our error-tracking provider (Sentry) to fix bugs.</li></ul>" },
  { h: "6. How we use data", html: "To run the checks and features you request, send the alerts you subscribe to, secure the service against abuse, and understand aggregate usage. We do not sell personal data, use it for advertising, or use it to train AI models." },
  { h: "7. Sharing", html: "We share data only with service providers that run parts of the service for us (Amazon Web Services for hosting and email, Resend for email delivery, Sentry for error tracking, Cloudflare for website analytics, and Google only if you choose Google sign-in), and when the law requires it. When we check a tool, we contact that tool's public source (GitHub, a package registry, or the MCP server you named)." },
  { h: "8. Retention and your rights", html: "Account data is kept while your account is active and deleted on request. Logs and metrics are kept as described in section 5. You may ask for access to, correction of, or deletion of your personal data at <a href=\"mailto:privacy@agentavow.com\">privacy@agentavow.com</a>." },
  { h: "9. Children", html: "AgentAvow is a developer tool and is not directed at children under 16. We do not knowingly collect their personal data." },
  { h: "10. Changes", html: "We will post changes here with a new effective date." },
  { h: "11. Contact", html: "Privacy questions: <a href=\"mailto:privacy@agentavow.com\">privacy@agentavow.com</a>." },
]

const DMCA: Clause[] = [
  { h: 'Copyright Infringement', body: (<>If you believe content on AgentAvow infringes your copyright, send a notice to <a href="mailto:legal@agentavow.com" className="text-primary-light hover:text-primary">legal@agentavow.com</a> with: (a) your signature; (b) identification of the work; (c) the material's location; (d) your contact information; (e) a good-faith statement; and (f) a statement, under penalty of perjury, that the notice is accurate and you are authorized to act.</>) },
  { h: 'Counter-Notice', body: 'If your material was removed in error, you may submit a counter-notice with the same contact address and the required statements.' },
]

const MODERATION: Clause[] = [
  { h: 'What we moderate', body: 'AgentAvow may remove abusive submissions, spam, or attempts to manipulate scores, and may restrict accounts that do so.' },
  { h: 'Reporting', body: (<>Report abuse or a bad actor to <a href="mailto:abuse@agentavow.com" className="text-primary-light hover:text-primary">abuse@agentavow.com</a>.</>) },
  { h: 'Appeals', body: 'If you believe a moderation action was a mistake, contact abuse@agentavow.com and we will review it.' },
]

const CONTENT: Record<string, { title: string; description: string; clauses: Clause[] }> = {
  terms: { title: 'Terms of Service', clauses: TERMS,
    description: 'AgentAvow Terms of Service: the free scan service, accounts, acceptable use, and how trust scores and attestations are provided.' },
  privacy: { title: 'Privacy Policy', clauses: PRIVACY,
    description: 'AgentAvow Privacy Policy: checking a tool is anonymous. What we collect for accounts and watch alerts, how we use it, and your rights.' },
  dmca: { title: 'DMCA', clauses: DMCA,
    description: 'How to send a DMCA copyright notice or counter-notice to AgentAvow, and what it must contain.' },
  'moderation-policy': { title: 'Moderation Policy', clauses: MODERATION,
    description: 'What AgentAvow moderates — abusive submissions, spam, and attempts to manipulate scores — and how to report abuse or appeal a decision.' },
}

export default function RebrandLegal() {
  const { section } = useParams()
  const key = section && CONTENT[section] ? section : 'terms'
  const c = CONTENT[key]

  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14 grid md:grid-cols-[200px_1fr] gap-10">
      <SEOHead title={c.title} description={c.description} path={`/legal/${key}`} />
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
              {cl.html
                ? <div className="mt-1.5 text-text-muted text-[14px] leading-relaxed [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1 [&_ul]:mt-1 [&_p]:mt-2 [&_a]:text-primary-light" dangerouslySetInnerHTML={{ __html: cl.html }} />
                : <div className="mt-1.5 text-text-muted text-[14px] leading-relaxed">{cl.body}</div>}
            </section>
          ))}
        </div>
      </article>
    </div>
  )
}
