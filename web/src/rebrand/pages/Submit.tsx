import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { rp } from '../basePath'
import { publicApi } from '../../lib/scanApi'
import SEOHead from '../../components/SEOHead'

/** Parse a pasted coordinate into {surface, identifier} for the submit endpoint —
 * mirrors the Check page's router logic, but returns the coordinate instead of routing. */
function parseCoordinate(raw: string): { surface: string; identifier: string } | null {
  const v = raw.trim()
  if (!v) return null
  const pkg = v.match(/^(npm|pypi|python|crates|cargo|rust|hf|huggingface|docker|container|oci)\s*:\s*(.+)$/i)
  if (pkg) {
    const k = pkg[1].toLowerCase()
    const surface = k === 'python' ? 'pypi'
      : (k === 'cargo' || k === 'rust') ? 'crates'
      : k === 'hf' ? 'huggingface'
      : (k === 'container' || k === 'oci') ? 'docker' : k
    return { surface, identifier: pkg[2].trim() }
  }
  let m
  if ((m = v.match(/^https?:\/\/(?:www\.)?crates\.io\/crates\/([\w-]+)/i))) return { surface: 'crates', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/(?:www\.)?npmjs\.com\/package\/((?:@[\w.-]+\/)?[\w.-]+)/i))) return { surface: 'npm', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/pypi\.org\/project\/([\w.-]+)/i))) return { surface: 'pypi', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/huggingface\.co\/([\w.-]+\/[\w.-]+)(?:$|[/?#])/i)) &&
      !/^(datasets|spaces|models|organizations|settings)\//i.test(m[1])) return { surface: 'huggingface', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/hub\.docker\.com\/_\/([\w.-]+)/i))) return { surface: 'docker', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/hub\.docker\.com\/r\/([\w.-]+\/[\w.-]+)/i))) return { surface: 'docker', identifier: m[1] }
  if ((m = v.match(/^https?:\/\/ghcr\.io\/([\w.-]+\/[\w.-]+)/i))) return { surface: 'docker', identifier: `ghcr.io/${m[1]}` }
  // A bare non-GitHub URL → a live MCP endpoint.
  if (/^https?:\/\/\S+$/i.test(v) && !/^https?:\/\/(www\.)?(github|gitlab)\.com\//i.test(v)) {
    return { surface: 'mcp', identifier: v }
  }
  // owner/repo (optionally a github URL) → a repo.
  const g = v.match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
  if (g) return { surface: 'github', identifier: `${g[1]}/${g[2]}` }
  return null
}

/** score-page path for a listed coordinate. */
function scorePath(surface: string, identifier: string): string {
  if (surface === 'github') return rp(`/rebrand/check/${identifier}`)
  if (surface === 'openclaw') return rp(`/rebrand/check/skill/${identifier}`)
  if (surface === 'mcp') return rp(`/rebrand/check/mcp`) + '?endpoint=' + encodeURIComponent(identifier)
  return rp(`/rebrand/check/pkg/${surface}/${identifier}`)
}

type Listed = { surface: string; identifier: string; grade: string; trust_score: number }

export default function Submit() {
  const navigate = useNavigate()
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [listed, setListed] = useState<Listed | null>(null)

  async function submit() {
    setError(null)
    const coord = parseCoordinate(value)
    if (!coord) { setError("We couldn't read that. Try github.com/owner/repo, npm:chalk, hf:org/model, docker:nginx, or an MCP URL."); return }
    setBusy(true)
    try {
      const { data } = await publicApi.post<{ listed: boolean; surface: string; identifier: string; grade: string; trust_score: number }>(
        '/public/scan/submit', coord,
      )
      setListed({ surface: data.surface, identifier: data.identifier, grade: data.grade, trust_score: data.trust_score })
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Something went wrong listing that tool. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  const EXAMPLES: Array<[string, string]> = [
    ['GitHub repo', 'github.com/owner/repo'],
    ['npm package', 'npm:your-package'],
    ['MCP server', 'mcp:https://your-server/mcp'],
    ['HF model', 'hf:org/model'],
  ]

  return (
    <div className="max-w-[720px] mx-auto px-6 py-20">
      <SEOHead
        title="List your tool — AgentAvow"
        description="Add your tool to the AgentAvow catalog: get a signed safety grade, appear in Browse, and claim it for change alerts."
        path="/submit"
      />
      <div className="text-center">
        <div className="font-mono text-[12px] uppercase tracking-wide text-primary-light">For authors</div>
        <h1 className="mt-2 text-3xl md:text-4xl font-extrabold tracking-tight">List your tool</h1>
        <p className="mt-4 text-text-muted max-w-[52ch] mx-auto">Add your tool to the catalog. We scan it, give it a <span className="text-text">signed safety grade</span>, and list it in Browse so agents can find and trust it. Free, no account.</p>
      </div>

      {!listed ? (
        <>
          <form onSubmit={(e) => { e.preventDefault(); submit() }} className="glass mt-8 mx-auto max-w-[560px] flex gap-2.5 rounded-2xl p-2 pl-4 shadow-lg shadow-primary/10">
            <input
              value={value} onChange={(e) => setValue(e.target.value)}
              placeholder="github.com/owner/repo · npm:chalk · hf:org/model · docker:nginx · mcp:https://…"
              className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[14px] text-text placeholder:text-text-muted"
            />
            <button type="submit" disabled={busy} className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60 whitespace-nowrap">
              {busy ? 'Listing…' : 'List it'}
            </button>
          </form>
          {error && <p className="mt-3 text-center text-[13px] text-danger max-w-[52ch] mx-auto">{error}</p>}
          <div className="mt-4 flex items-center justify-center gap-2 flex-wrap">
            <span className="text-[11.5px] text-text-muted/70">Try:</span>
            {EXAMPLES.map(([label, coord]) => (
              <button key={coord} type="button" onClick={() => setValue(coord)}
                className="font-mono text-[11.5px] px-2.5 py-1 rounded-full border border-border text-text-muted hover:border-primary-light hover:text-primary-light transition-colors">
                {coord}<span className="ml-1.5 text-text-muted/50">{label}</span>
              </button>
            ))}
          </div>

          <div className="mt-12 grid sm:grid-cols-3 gap-4">
            {[
              ['① Scanned', 'We statically grade the real artifact — a signed A+→F you can verify offline.'],
              ['② Listed', 'It appears in Browse under its surface, with your grade and a live adoption signal.'],
              ['③ Claim it', 'Prove ownership to get change-alerts, control how it appears, and a maintainer badge.'],
            ].map(([h, b]) => (
              <div key={h} className="glass rounded-xl p-5">
                <div className="font-semibold text-[14px]">{h}</div>
                <p className="mt-1.5 text-[13px] text-text-muted">{b}</p>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="glass mt-8 rounded-2xl p-8 text-center border-l-4 border-success/60">
          <div className="text-success font-mono text-[12px] uppercase tracking-wide">✓ Listed in the catalog</div>
          <h2 className="mt-2 text-2xl font-extrabold tracking-tight break-all">{listed.identifier}</h2>
          <div className="mt-2 text-[15px] text-text-muted">Scored <span className="font-bold text-text">{listed.trust_score}/100</span> — now in Browse.</div>
          <div className="mt-6 flex gap-3 justify-center flex-wrap">
            <button onClick={() => navigate(scorePath(listed.surface, listed.identifier))} className="font-semibold px-5 py-2.5 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark">View your listing →</button>
            <Link to={rp('/rebrand/tools')} className="font-semibold px-5 py-2.5 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors">Claim it</Link>
          </div>
          <button onClick={() => { setListed(null); setValue('') }} className="mt-5 text-[13px] text-text-muted hover:text-text">List another tool</button>
        </div>
      )}
    </div>
  )
}
