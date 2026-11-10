import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'

import SEOHead from '../../components/SEOHead'
import api from '../../lib/api'
import { trackContactSubmit } from '../../lib/analytics'
import { rp } from '../basePath'

/**
 * /teams: for a security or platform lead choosing what agents may connect to. No paid
 * traffic. Held back until their inputs exist (docs/internal/website-build-spec-2026-11-07.md):
 * the NSA guidance table (waits on a read of the PDF), accuracy numbers (the December
 * benchmark), a calendar link, and an ERC-8004 line (until it is used in an answer).
 * A2A says only what ships: grading an agent card in the public check (live since
 * 2026-11-07). There is no contact backend, so
 * "Talk to us" opens an email.
 */

const CONTACT = 'kenne@agentavow.com'

const CAPABILITIES: { h: string; p: string; pre?: string }[] = [
  { h: 'Gate CI on the answer', p: 'Fail the build on Do not connect. Works on GitHub, GitLab, Bitbucket and Azure DevOps.', pre: '- uses: AgentAvow/AgentAvow/github-action@main\n  with:\n    fail_on: do_not_connect' },
  { h: 'Get an alert when a tool changes', p: "Watch the tools you depend on. An HMAC-signed webhook fires when a score drops or a signed tool definition changes, the rug-pull you'd otherwise miss." },
  { h: 'Verify every result offline', p: "Recompute a result byte for byte and check its Ed25519 signature against our public keys. Your auditors don't have to trust us." },
  { h: 'Scan private code', p: 'Pass a GitHub token for one scan (signed in) and we never store it. Or run the scanner in your own CI, where your code stays on your runner.' },
  { h: 'Use the API', p: 'The answer, the trust score, the findings and the Certified mark come back as JSON (adoption from its own endpoint), so a policy can require any of them.' },
  { h: 'Gate agents at runtime', p: 'Check each tool before the call with npm gates for the Vercel AI SDK, Flue, the Claude Agent SDK and the OpenAI Agents SDK. LangChain, Google ADK, Open Policy Agent and LiteLLM integrations are in the repo.' },
]

const STANDARDS: [string, React.ReactNode][] = [
  ['TRACE spec', <>Our tool-definition digest derivation is in the TRACE runtime-attestation spec, under its own label <code className="font-mono text-[13px]">trace.mcp-tool-definition.v1</code>. Change alerts use our digest, so a pinned tool can be re-checked by anyone.</>],
  ['Linux Foundation Decentralized Trust lab', 'An outside party reproduced our conformance test vectors byte for byte. The vectors are Apache-2.0.'],
  ['IETF', 'Our founder co-authors the action-ref Internet-Draft, an individual submission.'],
  ['W3C', 'Contributed to the AI Knowledge Representation Community Group.'],
  ['Signatures', <>Ed25519 / JWS (RFC 7515) over RFC 8785 canonical JSON. Public keys at a <a href="/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:underline">fixed URL</a>.</>],
  ['MCP Registry', <>Our own server is listed in the <a href="https://registry.modelcontextprotocol.io/v0/servers?search=agentavow" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:underline">official MCP Registry</a>.</>],
]

const X402_FALLBACK = 26302

const h2 = 'text-[clamp(25px,3.4vw,33px)] font-bold tracking-tight leading-tight'
const section = 'relative z-[2] py-[60px] border-t border-border/60'
const field = 'w-full bg-[#0c1414] border border-border rounded-[10px] px-3 py-2.5 text-[15px] text-text focus:outline-none focus:border-primary focus:shadow-[0_0_0_3px_#0D948880]'

function TalkForm() {
  const [email, setEmail] = useState('')
  const [company, setCompany] = useState('')
  const [gate, setGate] = useState('')
  const [msg, setMsg] = useState('')
  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    // Counts the submit only: what was typed goes into the email, never into analytics.
    trackContactSubmit()
    const body = `Work email: ${email}\nCompany: ${company}\n\nWhat we want to gate:\n${gate}\n`
    const subject = company ? `AgentAvow for teams: ${company}` : 'AgentAvow for teams'
    window.location.href = `mailto:${CONTACT}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`
    setMsg(`Your email app should open with this filled in. If it doesn't, write to ${CONTACT}.`)
  }
  return (
    <form onSubmit={submit} className="glass rounded-2xl border border-white/10 grid gap-3 p-[22px] max-w-[560px]">
      <label className="grid gap-[5px] text-[13.5px] text-text-muted">Work email
        <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" className={field} />
      </label>
      <label className="grid gap-[5px] text-[13.5px] text-text-muted">Company
        <input value={company} onChange={(e) => setCompany(e.target.value)} autoComplete="organization" className={field} />
      </label>
      <label className="grid gap-[5px] text-[13.5px] text-text-muted">What do you want to gate?
        <textarea rows={3} value={gate} onChange={(e) => setGate(e.target.value)} className={field} />
      </label>
      <button type="submit" className="justify-self-start font-semibold text-[15px] px-5 py-[11px] rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Talk to us</button>
      <p className="text-[12.5px] text-text-muted" role="status">{msg || <>Opens an email to {CONTACT}.</>}</p>
    </form>
  )
}

export default function RebrandTeams() {
  const { data: x402 } = useQuery({
    queryKey: ['rebrand-catalog', 'teams-x402'],
    queryFn: async () => (await api.get<{ summary?: { x402_endpoints_total?: number } }>('/public/scan-catalog', { params: { limit: 1 } })).data,
    staleTime: 3_600_000,
  })
  const x402Total = x402?.summary?.x402_endpoints_total ?? X402_FALLBACK

  return (
    <div>
      <SEOHead
        title="For teams: a signed safety check in front of agent tools"
        description="Gate CI, agents and developers on one signed answer per tool: Safe to connect, Review before you connect, or Do not connect, with a trust score and an adoption score you can verify offline."
        path="/teams"
      />
      <div className="relative pt-14 pb-10">
        <div className="relative z-[2] max-w-[1080px] mx-auto px-6">
          <div className="font-mono text-[12px] tracking-[.16em] uppercase text-primary-light font-semibold">For teams</div>
          <h1 className="mt-3 max-w-[21em] text-[clamp(30px,4.6vw,46px)] font-extrabold leading-[1.1] tracking-[-.025em] [text-wrap:balance]">Put a signed safety check in front of every tool your agents and developers connect to.</h1>
          <p className="mt-[18px] max-w-[58ch] text-[18px] font-light text-text-muted">
            Each tool gets one answer, <b className="font-medium text-text">Safe to connect</b>, <b className="font-medium text-text">Review before you connect</b>, or <b className="font-medium text-text">Do not connect</b>, with a signed 0-100 trust score and an adoption score your CI, gateway or agent can act on.
          </p>
          <div className="flex flex-wrap gap-3 mt-7">
            <a href="#talk" className="inline-flex items-center font-semibold text-[15px] px-5 py-[11px] rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark shadow-lg shadow-primary/25 hover:shadow-primary/40 transition-shadow">Talk to us</a>
            <Link to={rp('/rebrand/check')} className="inline-flex items-center font-semibold text-[15px] px-5 py-[11px] rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Check a tool</Link>
          </div>
          <p className="mt-3.5 text-[13px] text-text-muted">Public scanning is free forever. Team pilots are free through Q1 2027.</p>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2}>Why a separate check.</h2>
          <figure className="mt-3.5 max-w-[68ch]">
            <blockquote className="border-l-2 border-primary-light pl-4 text-[16px] text-text">
              “Anthropic does not control what MCP servers, files, or other software are included in plugins and cannot verify that they will work as intended or that they won’t change.”
            </blockquote>
            <figcaption className="mt-2 pl-4 text-[13px] text-text-muted">
              Claude Code’s plugin trust warning,{' '}
              <a href="https://code.claude.com/docs/en/plugins/security" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:underline">Plugin security and trust</a>
            </figcaption>
          </figure>
          <p className="mt-4 max-w-[68ch] text-[15px] text-text-muted">
            The platforms your teams use say it plainly: checking what a tool does, and noticing when it changes after you approved it, is left to you. AgentAvow does that check, and signs the answer. AgentAvow is independent and not affiliated with or endorsed by Anthropic.
          </p>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2}>What you can put in place this week.</h2>
          <div className="grid md:grid-cols-2 gap-3.5 mt-[26px]">
            {CAPABILITIES.map((c) => (
              <div key={c.h} className="glass rounded-2xl border border-white/10 p-5 flex flex-col gap-[7px] min-w-0">
                <h3 className="text-[16.5px] font-bold">{c.h}</h3>
                <p className="text-text-muted text-[14.5px]">{c.p}</p>
                {c.pre && <pre className="mt-[7px] bg-[#0c1414] border border-border rounded-[9px] px-3 py-2.5 font-mono text-[12.5px] overflow-x-auto">{c.pre}</pre>}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2}>Straight answers for your review.</h2>
          <div className="grid gap-[7px] mt-3.5 text-[15px] max-w-[68ch]">
            <p><b className="font-semibold">Certified.</b> <span className="text-text-muted">The top mark. It sits beside Safe to connect, and it comes off at the next scan that fails a check.</span> <Link to={rp('/rebrand/certified')} className="text-primary-light hover:underline">What Certified means →</Link></p>
            <p><b className="font-semibold">SOC 2.</b> <span className="text-text-muted">No SOC 2 yet. Controls shared on request.</span></p>
            <p><b className="font-semibold">Standards.</b> <span className="text-text-muted">Our tool definition digest derivation is in the TRACE spec. An outside party reproduced our conformance vectors in a Linux Foundation Decentralized Trust lab.</span></p>
          </div>
        </div>
      </div>

      <div className={section}>
        <div className="max-w-[1080px] mx-auto px-6">
          <h2 className={h2}>Built on open standards you can check.</h2>
          <p className="mt-2.5 text-text-muted max-w-[60ch]">You don&apos;t have to take a vendor&apos;s word for a safety answer. Here is what others can verify.</p>
          <table className="w-full mt-[18px] text-[14.5px] border-collapse block sm:table">
            <thead className="hidden sm:table-header-group">
              <tr>
                <th className="text-left text-[12px] text-text-muted font-semibold px-2.5 py-2 border-b border-border">What</th>
                <th className="text-left text-[12px] text-text-muted font-semibold px-2.5 py-2 border-b border-border">What it means for your review</th>
              </tr>
            </thead>
            <tbody className="block sm:table-row-group">
              {STANDARDS.map(([what, means]) => (
                <tr key={what} className="block sm:table-row py-2.5 sm:py-0 border-b border-[#1d2d2d]">
                  <td className="block sm:table-cell sm:p-2.5 font-semibold align-top sm:border-b sm:border-[#1d2d2d] sm:w-[34%]">{what}</td>
                  <td className="block sm:table-cell sm:p-2.5 text-text-muted align-top sm:border-b sm:border-[#1d2d2d]">{means}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h3 className="mt-7 text-[18px] font-bold">Works with the protocols your agents use</h3>
          <div className="grid md:grid-cols-3 gap-3.5 mt-3">
            <div className="glass rounded-2xl border border-white/10 p-[22px] flex flex-col gap-[9px]">
              <h3 className="text-[19px] font-bold">MCP</h3>
              <p className="text-text-muted text-[14.5px]">Check live servers by URL, and servers shipped as npm or PyPI packages. Tool definitions are read for poisoning and hidden instructions.</p>
            </div>
            <div className="glass rounded-2xl border border-white/10 p-[22px] flex flex-col gap-[9px]">
              <h3 className="text-[19px] font-bold">A2A</h3>
              <p className="text-text-muted text-[14.5px]">Paste any A2A Agent Card URL for an answer, findings and a signed attestation, including whether the card&apos;s own signature verifies.</p>
            </div>
            <div className="glass rounded-2xl border border-white/10 p-[22px] flex flex-col gap-[9px]">
              <h3 className="text-[19px] font-bold">x402</h3>
              <p className="text-text-muted text-[14.5px]"><span className="tabular-nums">{x402Total.toLocaleString('en-US')}</span> x402 payment endpoints indexed, and a wallet address resolves to the tool it&apos;s linked to.</p>
            </div>
          </div>
        </div>
      </div>

      <div id="talk" className={`${section} scroll-mt-[70px]`}>
        <div className="max-w-[1080px] mx-auto px-6 grid md:grid-cols-2 gap-5 md:gap-[34px] items-start">
          <div>
            <h2 className={h2}>Talk to us.</h2>
            <p className="mt-2.5 text-text-muted max-w-[60ch]">Tell us what you want to gate. We&apos;ll reply with a pilot plan.</p>
          </div>
          <TalkForm />
        </div>
      </div>
    </div>
  )
}
