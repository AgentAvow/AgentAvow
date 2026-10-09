import { useState } from 'react'
import { Reveal } from './motion'

/**
 * Evidence panels shared by every score page (repo, package, MCP server, skill), so a
 * package or an MCP endpoint shows the same facts a repo page does whenever the scan
 * API already returns them: what the tool can do, its own past advisories, the MCP
 * tool list with per-tool digests, package facts, the README badge, and a way to
 * verify the signed result offline. Each panel renders nothing when its data is absent.
 */

type Capability = { capability?: string; label?: string; count?: number; files?: string[] }
type Advisory = { id?: string; aliases?: string[]; summary?: string; severity?: string; fixed_in?: string | null; affects_scanned_version?: boolean }
type ScanLike = {
  repo?: string
  jws?: string
  key_id?: string
  jwks_url?: string
  capabilities?: Capability[] | null
  advisories?: Advisory[] | null
  incident_history?: { advisories?: Advisory[] } | null
  env_reads?: string[] | null
  published_at?: string | null
  package_version?: string | null
  tool_digests?: Record<string, string> | null
  tool_manifest_digest?: string | null
  surface_detail?: Record<string, unknown> | null
}

const SEV: Record<string, string> = {
  critical: 'text-danger bg-danger/15',
  high: 'text-danger bg-danger/10',
  medium: 'text-warning bg-warning/15',
  moderate: 'text-warning bg-warning/15',
  low: 'text-text-muted bg-surface-hover',
}

const H3 = 'text-[13px] font-mono uppercase tracking-wide text-text-muted'

function CopyButton({ text, label = 'copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      onClick={() => { void navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400) }}
      className="font-mono text-[10.5px] px-2 py-0.5 rounded bg-surface-hover border border-border text-text-muted hover:text-primary-light shrink-0"
    >{done ? 'copied ✓' : label}</button>
  )
}

function CodeLine({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2">
      <pre className="flex-1 min-w-0 font-mono text-[11px] bg-surface border border-border rounded-lg px-3 py-2 text-text-muted overflow-x-auto whitespace-pre-wrap break-all">{text}</pre>
      <CopyButton text={text} />
    </div>
  )
}

/** "What it can do" — the capability surface the scanner found in shipped code
 * (writes files, runs commands, opens sockets…). Context for the score, not a finding. */
export function CapabilitiesPanel({ scan: raw }: { scan: unknown }) {
  const scan = raw as ScanLike
  const caps = (scan.capabilities ?? []).filter((c) => c && (c.label || c.capability))
  if (caps.length === 0) return null
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h3 className={H3}>What it can do</h3>
        <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">Capabilities found in the code it ships. A capability is not a finding: it tells you what the tool could do with the access you give it.</p>
        <ul className="mt-3 space-y-2">
          {caps.map((c, i) => (
            <li key={`${c.capability}-${i}`} className="text-[13px]">
              <div className="flex flex-wrap items-center gap-x-2">
                <span className="text-text">{c.label || c.capability}</span>
                {(c.count ?? 0) > 1 && <span className="font-mono text-[11px] text-text-muted">· {c.count} places</span>}
              </div>
              {(c.files?.length ?? 0) > 0 && (
                <div className="mt-0.5 font-mono text-[11px] text-text-muted/80 break-all">{c.files!.slice(0, 4).join(', ')}{c.files!.length > 4 ? ` +${c.files!.length - 4} more` : ''}</div>
              )}
            </li>
          ))}
        </ul>
      </div>
    </Reveal>
  )
}

/** The target's own published advisories (OSV/GHSA for this package), split into the
 * ones that hit the scanned version and the ones already fixed in it. */
export function AdvisoriesPanel({ scan: raw }: { scan: unknown }) {
  const scan = raw as ScanLike
  const all = (scan.advisories?.length ? scan.advisories : scan.incident_history?.advisories) ?? []
  if (all.length === 0) return null
  const open = all.filter((a) => a.affects_scanned_version)
  const fixed = all.filter((a) => !a.affects_scanned_version)
  const version = scan.package_version ? ` ${scan.package_version}` : ''
  const row = (a: Advisory, i: number) => (
    <li key={`${a.id}-${i}`} className="text-[13px] flex gap-3 items-start">
      <span className={`font-mono text-[10.5px] uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 mt-0.5 ${SEV[(a.severity || '').toLowerCase()] || SEV.low}`}>{a.severity || 'n/a'}</span>
      <div className="min-w-0">
        <div className="text-text">{a.summary || a.id}</div>
        <div className="font-mono text-[11px] text-text-muted break-all">
          {a.id}{a.aliases?.length ? ` · ${a.aliases.join(', ')}` : ''}{a.fixed_in ? ` · fixed in ${a.fixed_in}` : ''}
        </div>
      </div>
    </li>
  )
  return (
    <Reveal>
      <div className={`mt-4 glass rounded-2xl p-6 ${open.length ? 'border-l-4 border-danger/50' : ''}`}>
        {open.length > 0 && (
          <>
            <h3 className={`${H3} text-danger`}>Advisories that affect this version{version}</h3>
            <ul className="mt-3 space-y-2.5">{open.map(row)}</ul>
          </>
        )}
        {fixed.length > 0 && (
          <>
            <h3 className={`${H3} ${open.length ? 'mt-5' : ''}`}>{open.length ? 'Past advisories, fixed in this version' : `Past advisories, all fixed in this version${version}`}</h3>
            {!open.length && <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">Security advisories were published against older releases. None of them affects the version we scanned.</p>}
            <ul className="mt-3 space-y-2.5">{fixed.map(row)}</ul>
          </>
        )}
      </div>
    </Reveal>
  )
}

/** The tools a live MCP server serves, each with the digest of its signed definition.
 * A consumer recomputes a tool's digest from tools/list to detect a silent change. */
export function McpToolList({ scan: raw }: { scan: unknown }) {
  const scan = raw as ScanLike
  const entries = Object.entries(scan.tool_digests ?? {}).filter(([k]) => k.startsWith('tool:'))
  if (entries.length === 0) return null
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h3 className={H3}>Tools it serves ({entries.length})</h3>
        <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">Each tool&apos;s definition (name, description, input schema, annotations) is hashed and signed into this result. If the server later changes a tool, its digest changes, which is how a watch catches a silent swap. <a className="underline" href="/docs/verify-attestations">How to recompute it</a></p>
        <ul className="mt-3 divide-y divide-border/50">
          {entries.map(([k, digest]) => (
            <li key={k} className="py-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-0.5 sm:gap-3">
              <span className="font-mono text-[13px] text-text break-all">{k.slice(5)}</span>
              <span className="font-mono text-[11px] text-text-muted break-all" title={digest}>{digest.slice(0, 23)}…</span>
            </li>
          ))}
        </ul>
        {scan.tool_manifest_digest && (
          <div className="mt-3 flex flex-col sm:flex-row sm:justify-between gap-0.5 sm:gap-3 text-[12px]">
            <span className="text-text-muted">Whole tool set</span>
            <span className="font-mono text-text-muted break-all">{scan.tool_manifest_digest.slice(0, 23)}…</span>
          </div>
        )}
      </div>
    </Reveal>
  )
}

function fmtBytes(n?: number): string | null {
  if (typeof n !== 'number' || n <= 0) return null
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

/** Registry facts for a published package: when it was published, how big it is,
 * whether it runs an install hook, and which environment variables its code reads. */
export function PackageFacts({ scan: raw, surface }: { scan: unknown; surface: string }) {
  const scan = raw as ScanLike
  const sd = (scan.surface_detail ?? {}) as { file_count?: number; unpacked_size?: number; has_install_hook?: boolean; published_at?: string | null; version?: string; kind?: string }
  const env = scan.env_reads ?? []
  const [showEnv, setShowEnv] = useState(false)
  const published = (scan.published_at || sd.published_at || '').slice(0, 10)
  const size = fmtBytes(sd.unpacked_size)
  const rows: [string, string, string?][] = []
  if (scan.package_version || sd.version) rows.push(['Version scanned', String(scan.package_version || sd.version)])
  if (published) rows.push(['Published', published])
  if (size || sd.file_count) rows.push([surface === 'docker' ? 'Image config scanned' : 'Size', [size, sd.file_count ? `${sd.file_count} file${sd.file_count === 1 ? '' : 's'}` : ''].filter(Boolean).join(' · ')])
  if (typeof sd.has_install_hook === 'boolean' && surface !== 'docker' && surface !== 'huggingface') {
    rows.push(['Install hook', sd.has_install_hook ? 'yes, runs code on install' : 'none', sd.has_install_hook ? 'text-warning' : 'text-success'])
  }
  if (rows.length === 0 && env.length === 0) return null
  const shownEnv = showEnv ? env : env.slice(0, 12)
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h3 className={H3}>Package facts</h3>
        {rows.length > 0 && (
          <div className="mt-3 flex flex-col gap-2 text-[13px]">
            {rows.map(([k, v, cls]) => (
              <div key={k} className="flex justify-between gap-3"><span className="text-text-muted shrink-0">{k}</span><span className={`font-mono text-right break-all ${cls ?? ''}`}>{v}</span></div>
            ))}
          </div>
        )}
        {env.length > 0 && (
          <div className="mt-4">
            <div className="font-mono text-[11px] uppercase tracking-wide text-text-muted mb-1.5">Environment variables it reads ({env.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {shownEnv.map((e) => <span key={e} className="font-mono text-[11.5px] px-2 py-0.5 rounded-md bg-surface border border-border text-text-muted">{e}</span>)}
              {env.length > 12 && (
                <button type="button" onClick={() => setShowEnv((s) => !s)} className="text-[11.5px] text-text-muted hover:text-text underline underline-offset-2">{showEnv ? 'show fewer' : `+${env.length - 12} more`}</button>
              )}
            </div>
            <p className="mt-1.5 text-[11.5px] text-text-muted/80">Names only, read from the shipped code. Anything you set under these names is visible to the package.</p>
          </div>
        )}
      </div>
    </Reveal>
  )
}

/** README badge for a published package. The badge route takes a single path segment
 * for the name, so scoped npm names (@scope/name) have no badge URL yet. */
export function PackageBadge({ surface, name }: { surface: string; name: string }) {
  if (!name || name.includes('/')) return null
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const img = `${origin}/api/v1/public/scan/${surface}/${encodeURIComponent(name)}/badge`
  const link = `${origin}/check/pkg/${surface}/${encodeURIComponent(name)}`
  const md = `[![AgentAvow Trust](${img})](${link})`
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h3 className={H3}>README badge</h3>
        <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">Maintain this package? Show its current signed result in your README. The image regenerates from the live result on every view.</p>
        <a href={link} className="mt-3 inline-block"><img src={img} alt="AgentAvow Trust" className="h-[22px]" loading="lazy" /></a>
        <div className="mt-3"><CodeLine text={md} /></div>
      </div>
    </Reveal>
  )
}

// A self-contained offline check: Ed25519 over `<header>.<payload>`, key matched by kid
// from a JWKS saved beforehand. Needs only Python 3 and the `cryptography` package.
const VERIFY_PY = `python3 -c "import json,base64 as b;from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as K;d=lambda s:b.urlsafe_b64decode(s+'='*(-len(s)%4));h,p,s=open('scan.jws').read().strip().split('.');kid=json.loads(d(h))['kid'];x=next(k['x'] for k in json.load(open('jwks.json'))['keys'] if k['kid']==kid);K.from_public_bytes(d(x)).verify(d(s),(h+'.'+p).encode());v=json.loads(d(p));print('verified',v['subject']['id'],v['scan']['trustScore'])"`

/** "Verify this result" — the signed scan attestation, on every score page. */
export function VerifyPanel({ scan: raw }: { scan: unknown }) {
  const scan = raw as ScanLike
  if (!scan.jws) return null
  const jwks = scan.jwks_url || 'https://agentgraph.co/.well-known/jwks.json'
  const download = () => {
    const url = URL.createObjectURL(new Blob([scan.jws!], { type: 'application/jose' }))
    const a = document.createElement('a')
    a.href = url; a.download = 'scan.jws'; a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return (
    <Reveal>
      <div className="mt-6 glass rounded-2xl p-6 border-l-4 border-primary/60">
        <div className="flex items-center gap-2 text-success font-mono text-[12.5px]">
          <svg viewBox="0 0 24 24" fill="none" className="w-[18px] h-[18px]" aria-hidden="true"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" /><path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
          Signed · Ed25519 / JWS{scan.key_id ? <span className="text-text-muted"> · key {scan.key_id}</span> : null}
        </div>
        <h3 className="mt-2 text-lg font-bold">Verify this result</h3>
        <p className="mt-1 text-text-muted text-[13.5px] max-w-[62ch]">The score, tier and findings on this page are signed. Check the signature yourself, offline, against our public keys. If anything was changed, verification fails.</p>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <CopyButton text={scan.jws} label="copy JWS" />
          <button type="button" onClick={download} className="font-mono text-[10.5px] px-2 py-0.5 rounded bg-surface-hover border border-border text-text-muted hover:text-primary-light">download scan.jws</button>
          <a href={jwks} target="_blank" rel="noopener noreferrer" className="font-mono text-[10.5px] px-2 py-0.5 rounded bg-surface-hover border border-border text-text-muted hover:text-primary-light">public keys (JWKS) ↗</a>
        </div>
        <div className="mt-4 space-y-2">
          <div className="text-[12px] text-text-muted">1 · Save the keys once (the only network step):</div>
          <CodeLine text={`curl -s ${jwks} -o jwks.json`} />
          <div className="text-[12px] text-text-muted">2 · With <span className="font-mono">scan.jws</span> next to it, check the signature (<span className="font-mono">pip install cryptography</span>):</div>
          <CodeLine text={VERIFY_PY} />
        </div>
        <a href="/docs/verify-attestations" className="mt-3 inline-block text-[13px] font-semibold text-primary-light hover:text-primary">Verify in Python or JavaScript, step by step →</a>
      </div>
    </Reveal>
  )
}
