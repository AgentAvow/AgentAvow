import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { rp } from '../basePath'
import { unsupportedRepoHost, unsupportedRepoHostMessage } from '../lib/unsupportedHost'
import { NoticeText } from './NoticeText'
import { parseCoordinate } from '../lib/listCoordinate'
import { publicApi } from '../../lib/scanApi'
import { decide, decisionPhrase } from '../../components/trust/gradeSystem'

/**
 * The "add a tool to the catalog" form: POST /public/scan/submit scans a coordinate and
 * lists it in Browse. It was the /submit page until 2026-11-11; it lives in the
 * /for-developers page now (#list), and /submit redirects there.
 */

/** score-page path for a listed coordinate. */
function scorePath(surface: string, identifier: string): string {
  if (surface === 'github') return rp(`/rebrand/check/${identifier}`)
  if (surface === 'openclaw') return rp(`/rebrand/check/skill/${identifier}`)
  if (surface === 'mcp') return rp(`/rebrand/check/mcp`) + '?endpoint=' + encodeURIComponent(identifier)
  return rp(`/rebrand/check/pkg/${surface}/${identifier}`)
}

/** The My Tools claim box takes the same coordinates as the Check page. */
function claimCoord(surface: string, identifier: string): string | null {
  if (surface === 'github') return identifier
  if (surface === 'openclaw') return `skill:${identifier}`
  if (surface === 'npm' || surface === 'pypi' || surface === 'crates' || surface === 'mcp') return `${surface}:${identifier}`
  return null // Hugging Face and Docker can't be claimed yet
}

type Listed = { surface: string; identifier: string; grade: string; trust_score: number; decision?: string | null; decision_reason?: string | null }

const EXAMPLES: Array<[string, string]> = [
  ['MCP server', 'https://your-server/mcp'],
  ['GitHub repo', 'github.com/owner/repo'],
  ['Docker image', 'docker:nginx'],
  ['HF model', 'hf:org/model'],
]

export default function ListToolForm() {
  const navigate = useNavigate()
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [listed, setListed] = useState<Listed | null>(null)

  async function submit() {
    setError(null)
    const host = unsupportedRepoHost(value)
    if (host) { setError(unsupportedRepoHostMessage(host)); return }
    const coord = parseCoordinate(value)
    if (!coord) { setError("We couldn't read that. Try github.com/owner/repo, npm:chalk, hf:org/model, docker:nginx, or an MCP URL."); return }
    setBusy(true)
    try {
      const { data } = await publicApi.post<Listed & { listed: boolean }>('/public/scan/submit', coord)
      setListed({ surface: data.surface, identifier: data.identifier, grade: data.grade, trust_score: data.trust_score, decision: data.decision, decision_reason: data.decision_reason })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Something went wrong listing that tool. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  if (listed) {
    const p = decisionPhrase(listed.decision ?? decide({ trust_score: listed.trust_score }).decision)
    const claim = claimCoord(listed.surface, listed.identifier)
    return (
      <div className="glass rounded-2xl p-6 sm:p-8 text-center border-l-4 border-success/60">
        <div className="text-success font-mono text-[12px] uppercase tracking-wide">✓ Listed in the catalog</div>
        <div className="mt-2 text-2xl font-extrabold tracking-tight break-all">{listed.identifier}</div>
        <div className="mt-2 text-[15px] text-text-muted">
          <span className="font-bold" style={{ color: p.color }}>{p.phrase}</span>
          {listed.decision_reason && <span> — {listed.decision_reason}</span>}
          <span> · trust {listed.trust_score}/100 — now in Browse.</span>
        </div>
        <div className="mt-6 flex gap-3 justify-center flex-wrap">
          <button type="button" onClick={() => navigate(scorePath(listed.surface, listed.identifier))} className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">View the listing →</button>
          {claim
            ? <Link to={rp('/rebrand/tools') + '?coord=' + encodeURIComponent(claim)} className="font-semibold px-5 py-2.5 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Claim it</Link>
            : <Link to={scorePath(listed.surface, listed.identifier) + '#watch'} className="font-semibold px-5 py-2.5 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Watch it</Link>}
        </div>
        <button type="button" onClick={() => { setListed(null); setValue('') }} className="mt-5 text-[13px] text-text-muted hover:text-text">Add another tool</button>
      </div>
    )
  }

  return (
    <div>
      <form onSubmit={(e) => { e.preventDefault(); submit() }} className="flex gap-2 rounded-xl border border-border bg-surface p-1.5 pl-3">
        <input
          value={value} onChange={(e) => setValue(e.target.value)} aria-label="Tool to add to the catalog"
          placeholder="MCP URL · owner/repo · npm:name · docker:image · hf:org/model"
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[13px] text-text placeholder:text-text-muted"
        />
        <button type="submit" disabled={busy} className="shrink-0 font-semibold text-[13px] px-3 py-1.5 rounded-lg text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 whitespace-nowrap">
          {busy ? 'Adding…' : 'Add it'}
        </button>
      </form>
      {error && <p className="mt-3 text-[13px] text-danger"><NoticeText text={error} /></p>}
      <div className="mt-3 flex items-center gap-2 flex-wrap">
        <span className="text-[11.5px] text-text-muted/70">Try:</span>
        {EXAMPLES.map(([label, coord]) => (
          <button key={coord} type="button" onClick={() => setValue(coord)}
            className="font-mono text-[11.5px] px-2.5 py-1 rounded-full border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors [overflow-wrap:anywhere]">
            {coord}<span className="ml-1.5 text-text-muted/50">{label}</span>
          </button>
        ))}
      </div>
    </div>
  )
}
