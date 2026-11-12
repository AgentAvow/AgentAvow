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
  { h: '1. Acceptance of Terms', body: 'Effective October 9, 2026. By accessing or using AgentAvow (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, do not use the Service.' },
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
  { h: "1. Overview", html: "Effective November 12, 2026. AgentAvow checks whether a software tool is safe for an AI agent to connect to: a GitHub repository, a published package, a live MCP server, an agent skill, or an A2A agent card. This policy explains what we receive when you use agentavow.com, our public API, or our connector for AI assistants, what we do with it, and how long we keep it. Checking a tool does not require an account." },
  { h: "2. Using the connector in an AI assistant (MCP)", html: "<p>When an AI assistant calls one of our tools on your behalf, we receive:</p><ul><li><strong>The tool's inputs:</strong> the repository, package name and optional version, MCP server URL, or agent identifier you asked about, and whether to re-scan.</li><li><strong>Standard request data:</strong> the IP address and User-Agent of the request.</li></ul><p>Our tools accept only those inputs. We do not ask for your conversation, chat history, memories, files, name, email address, or account with the assistant, and we do not store anything beyond the inputs listed above. Your assistant decides what to put in those inputs; they are short identifiers such as a package name or URL. Some assistants attach optional hints to a request (for example a coarse location or an anonymous identifier); we do not read or store them. The connector has no sign-in.</p><p>We use the inputs only to run the check you asked for: we fetch public information about that tool from its source (GitHub, the package registry, or the MCP server itself), analyze it, and return the result. All eight tools are read-only: they never change anything in your accounts or in the tool being checked.</p>" },
  { h: "3. What our results contain", html: "Results describe the tool that was checked: an answer (Safe to connect, Review before you connect, or Do not connect) with its reason, a trust score, an adoption score, findings, and a signed attestation. They contain no personal data about you. Results for public tools are public: they may be cached, shown on agentavow.com, and listed in our public catalog. Do not submit anything you consider confidential." },
  { h: "4. Accounts and alerts (optional)", html: "If you create an account: your email address, display name, and, if you sign in with Google, the basic profile Google shares, or, if you sign in with GitHub, your GitHub user ID, username, name, avatar and verified email address (read-only access; the GitHub sign-in token is not stored). If you watch a tool: the tools you watch and any webhook URL you configure (its signing secret is stored encrypted). If you scan a private repository with a GitHub token, the token is used for that scan only and is not stored." },
  { h: "5. Logs, metrics and analytics", html: "<ul><li><strong>Server logs</strong> (IP address, User-Agent, the requested path including the tool checked, time, status) are kept to operate and secure the service. They are rotated automatically and typically kept for less than 30 days.</li><li><strong>Usage metrics</strong> are daily counts (for example, calls per tool and per assistant product). To count distinct callers we store a one-way hash of the IP address and User-Agent combined with a salt that changes every day, not the IP address itself. Metrics are kept for up to 90 days.</li><li><strong>Claude Code plugin install ID:</strong> The Claude Code plugin sends a random install ID with each check. It's generated on your device, contains no personal information, and is used only to count active installs and how many return. We don't link it to IP addresses, accounts or anything else, and we don't share it. You can disable it with <code>AGENTAVOW_ANON_ID=off</code>. We store only a one-way hash of it for each day it was seen, and delete those records after 40 days.</li><li><strong>Cloudflare Web Analytics</strong> measures page loads and does not use cookies. It receives the address of the pages you view, without the query string. It never receives the address of a check result page (any page under /check/, whose address names the tool you checked or, for a private scan, your repository): it does not run on those pages, and once you open one from another page it sends nothing more until you reload.</li><li><strong>Our own site analytics</strong> do not use cookies either, and are stored in our own database. The first time you open agentavow.com, our code stores a random identifier called <code>ag_session_id</code> in your browser's local storage. It holds no name or email address. It stays until you clear your browser's data for our site, and your next visit then creates a new one. If you create an account, we link the identifier to that account.</li><li><strong>What those analytics record:</strong> pages you view, submitting a check box (not what you typed), results shown, clicks on our add and install links, copies of an install command or a badge, and steps in creating an account. Each record holds the event, the identifier, the page path, the time, a one-way hash of the IP address of the request, and a coarse label for the kind of client (browser, bot or unknown). We do not store the IP address itself or the User-Agent. The hash is made with a random salt that changes every day and is kept for about two days, never with the records, so once it is gone a hash cannot be traced back to an IP address or matched with records from another day. When you land on the site from another one, the record of that landing also holds the host of the site that sent you (for example google.com), never the full address of the page you came from. On a check page the path names the tool you checked. The query string is left out, so an MCP server URL given there is not recorded, and a one-time private scan is recorded as /check/private with no repository name.</li><li><strong>Campaign links:</strong> if you arrive through a link with campaign tags (utm_source, utm_medium, utm_campaign, utm_content, utm_term), your browser keeps them in session storage as <code>ag_utm</code> until the tab closes and sends them with each event. It also keeps a marker, <code>ag_landed</code>, so a landing counts once per tab. We store the first tags we see for an identifier, with the page it landed on, so a later visit from the same browser counts toward the same campaign.</li><li><strong>How long:</strong> these analytics records have no automatic deletion date. Records written before November 11, 2026 also hold the raw IP address of the request; that IP address is deleted once the record is 30 days old. You can ask us to delete the records (section 8).</li><li><strong>Meta Pixel, on /claude-code only:</strong> /claude-code is the page our ads on Facebook and Instagram lead to. That page, and no other page on agentavow.com, loads the Meta Pixel, a script from Meta Platforms (connect.facebook.net), so we can measure how many people our ads bring there and how many copy the install command. It never runs on a check page. When it runs, your browser sends Meta a page-view event and, the first time you copy the install command, one copy event. With them Meta receives the page address (including any campaign tags in it), the page you came from, your IP address and browser details, and any cookies your browser already holds for facebook.com. The pixel may also set its own cookie on agentavow.com, <code>_fbp</code>, which Meta uses to recognize the same browser later. We do not send Meta your name, email address or any other contact details (no Advanced Matching), we turn off its automatic collection of button clicks and page details, and we send Meta nothing from our servers. Meta uses this data under its own <a href=\"https://www.facebook.com/privacy/policy/\">privacy policy</a>, including to measure and improve ads, and may use it to choose ads it shows you. <strong>To opt out:</strong> turn on Global Privacy Control or Do Not Track in your browser and the pixel is not loaded at all; or block connect.facebook.net with your browser or a content blocker; or turn off activity from ad partners in your Meta <a href=\"https://www.facebook.com/adpreferences/\">ad preferences</a>. Clearing your cookies for agentavow.com removes <code>_fbp</code>.</li><li><strong>Error reports</strong> are sent to our error-tracking provider (Sentry) to fix bugs.</li></ul>" },
  { h: "6. How we use data", html: "To run the checks and features you request, send the alerts you subscribe to, secure the service against abuse, and understand aggregate usage, including which pages and campaigns bring people to the site. We do not sell personal data or use it to train AI models. We do not use it for advertising, except that the Meta Pixel on /claude-code (section 5) tells Meta about visits to that page so we can measure our ads." },
  { h: "7. Sharing", html: "We share data only with service providers that run parts of the service for us (Amazon Web Services for hosting, Resend for email delivery, Sentry for error tracking, Cloudflare for website analytics, Meta Platforms for measuring our ads on /claude-code only (section 5), and Google or GitHub only if you choose to sign in with them), and when the law requires it. When we check a tool, we contact that tool's public source (GitHub, a package registry, or the MCP server you named)." },
  { h: "8. Retention and your rights", html: "Account data is kept while your account is active and deleted on request. Logs, metrics and analytics records are kept as described in section 5. You may ask for access to, correction of, or deletion of your personal data at <a href=\"mailto:privacy@agentavow.com\">privacy@agentavow.com</a>." },
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
    description: 'AgentAvow Privacy Policy: checking a tool needs no account. What we collect for accounts, watch alerts and site analytics, how we use it, and your rights.' },
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
