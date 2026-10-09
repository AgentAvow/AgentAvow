import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Reveal } from './motion'
import { publicApi } from '../../lib/scanApi'
import { rp } from '../basePath'

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
  tool_list?: ToolRow[] | null
  surface_detail?: Record<string, unknown> | null
  behavioral?: {
    tool_list?: ToolRow[] | null
    exercise?: { tools?: { name?: string; annotations?: Record<string, unknown> | null }[] | null } | null
  } | null
}

type ToolSource = 'live' | 'sandbox' | 'source'
type ToolRow = {
  name: string
  title?: string
  annotations?: Record<string, unknown> | null
  digest?: string
  source?: ToolSource
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

/** Pick the best tool list we hold for this result: the live endpoint's tools/list, else
 * what the sandbox saw the package's server serve, else registrations found in its code,
 * else the bare signed digests (older cached results). */
function pickTools(scan: ScanLike): { rows: ToolRow[]; source: ToolSource } | null {
  const live = (scan.tool_list ?? []).filter((t) => t?.name)
  if (live.length && live[0].source !== 'source') return { rows: live, source: live[0].source ?? 'live' }
  const sb = (scan.behavioral?.tool_list ?? []).filter((t) => t?.name)
  if (sb.length) return { rows: sb, source: 'sandbox' }
  const ex = (scan.behavioral?.exercise?.tools ?? []).filter((t) => t?.name)
  if (ex.length) return { rows: ex.map((t) => ({ name: String(t.name), annotations: t.annotations ?? {} })), source: 'sandbox' }
  if (live.length) return { rows: live, source: 'source' }
  const dig = Object.entries(scan.tool_digests ?? {}).filter(([k]) => k.startsWith('tool:'))
  if (dig.length) return { rows: dig.map(([k, d]) => ({ name: k.slice(5), digest: d })), source: 'live' }
  return null
}

const TOOL_NOTE: Record<ToolSource, string> = {
  live: 'Each tool\'s definition (name, description, input schema, annotations) is hashed and signed into this result. If the server later changes a tool, its digest changes, which is how a watch catches a silent swap.',
  sandbox: 'Listed by the server itself when we started the published package in the sandbox. Each digest pins the definition as the sandbox recorded it, so a later run can catch a changed tool.',
  source: 'Found in the package\'s published code, not from a running server. Annotations are the ones written literally in the code; the sandbox run lists the served definitions.',
}

/** The declared MCP safety hints, as chips. Only hints the tool actually declares are
 * shown: an undeclared hint is unknown, not false. */
function AnnotationChips({ a }: { a?: Record<string, unknown> | null }) {
  const chips: { label: string; cls: string; title: string }[] = []
  if (a?.readOnlyHint === true) chips.push({ label: 'read-only', cls: 'text-success bg-success/10', title: 'readOnlyHint: true' })
  if (a?.readOnlyHint === false) chips.push({ label: 'writes', cls: 'text-warning bg-warning/10', title: 'readOnlyHint: false' })
  if (a?.destructiveHint === true) chips.push({ label: 'destructive', cls: 'text-danger bg-danger/10', title: 'destructiveHint: true' })
  if (a?.destructiveHint === false && a?.readOnlyHint !== true) chips.push({ label: 'non-destructive', cls: 'text-text-muted bg-surface-hover', title: 'destructiveHint: false' })
  if (a?.idempotentHint === true) chips.push({ label: 'idempotent', cls: 'text-text-muted bg-surface-hover', title: 'idempotentHint: true' })
  if (a?.openWorldHint === true) chips.push({ label: 'open world', cls: 'text-text-muted bg-surface-hover', title: 'openWorldHint: true (reaches outside systems)' })
  if (a?.openWorldHint === false) chips.push({ label: 'closed world', cls: 'text-text-muted bg-surface-hover', title: 'openWorldHint: false' })
  if (!chips.length) return <span className="font-mono text-[10.5px] text-text-muted/70">no annotations</span>
  return (
    <span className="flex flex-wrap gap-1">
      {chips.map((c) => <span key={c.label} title={c.title} className={`font-mono text-[10.5px] px-1.5 py-0.5 rounded ${c.cls}`}>{c.label}</span>)}
    </span>
  )
}

/** The tools an MCP server serves: name, its declared safety annotations, and (where we
 * hold the full definition) the digest of that definition. Live endpoints, sandbox runs
 * of published packages, and code registrations are labelled differently. */
export function McpToolList({ scan: raw }: { scan: unknown }) {
  const scan = raw as ScanLike
  const picked = pickTools(scan)
  if (!picked) return null
  const { rows, source } = picked
  const annotated = rows.filter((r) => r.annotations && Object.keys(r.annotations).length).length
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <h3 className={H3}>Tools it serves ({rows.length})</h3>
        <p className="mt-1.5 text-[13px] text-text-muted max-w-[64ch]">{TOOL_NOTE[source]}{' '}{source === 'live' && <a className="underline" href="/docs/verify-attestations">How to recompute it</a>}</p>
        {rows.length > 0 && annotated === 0 && <p className="mt-1.5 text-[12px] text-text-muted/80 max-w-[64ch]">None of these tools declares safety annotations (read-only, destructive), so an agent can&apos;t tell from the definitions which ones change things.</p>}
        <ul className="mt-3 divide-y divide-border/50">
          {rows.map((t) => (
            <li key={t.name} className="py-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 sm:gap-3">
              <span className="min-w-0 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2.5">
                <span className="font-mono text-[13px] text-text break-all">{t.name}</span>
                <AnnotationChips a={t.annotations} />
              </span>
              {t.digest && <span className="font-mono text-[11px] text-text-muted break-all shrink-0" title={t.digest}>{t.digest.slice(0, 23)}…</span>}
            </li>
          ))}
        </ul>
        {source === 'live' && scan.tool_manifest_digest && (
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
  const sd = (scan.surface_detail ?? {}) as { file_count?: number; unpacked_size?: number; has_install_hook?: boolean; published_at?: string | null; version?: string; kind?: string; repository?: string | null; model_card?: { license?: string | null; gated?: boolean | string; pipeline_tag?: string | null; library_name?: string | null; safetensors?: boolean; pickle_weights?: number; raw_weights?: number; custom_code?: number } }
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
  const mc = sd.model_card
  if (mc) {
    if (mc.license) rows.push(['License', mc.license])
    if (mc.pipeline_tag || mc.library_name) rows.push(['Task', [mc.pipeline_tag, mc.library_name].filter(Boolean).join(' · ')])
    rows.push(['Access', mc.gated ? `gated (${typeof mc.gated === 'string' ? mc.gated : 'request access'})` : 'open'])
    rows.push(['Weights', mc.pickle_weights
      ? `${mc.pickle_weights} pickle file${mc.pickle_weights === 1 ? '' : 's'} (runs code on load)${mc.safetensors ? '; safetensors copy also published' : ''}`
      : mc.safetensors ? 'safetensors (no code runs on load)' : 'no pickle weights',
      mc.pickle_weights && !mc.safetensors ? 'text-warning' : mc.pickle_weights ? '' : 'text-success'])
    if (mc.custom_code) rows.push(['Custom model code', `${mc.custom_code} .py file${mc.custom_code === 1 ? '' : 's'} (run with trust_remote_code)`, 'text-warning'])
  }
  const repoUrl = sd.repository && /^https:\/\//.test(sd.repository) ? sd.repository : null
  if (rows.length === 0 && env.length === 0 && !repoUrl) return null
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
            {repoUrl && (
              <div className="flex justify-between gap-3"><span className="text-text-muted shrink-0">Source repository</span><a href={repoUrl} target="_blank" rel="noopener noreferrer" className="font-mono text-right break-all text-primary-light hover:text-primary">{repoUrl.replace(/^https:\/\//, '')} ↗</a></div>
            )}
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

/** The badge URL for a published package. ``/package/<surface>/<name>/badge`` takes
 * names with a slash too (scoped npm ``@scope/name``, Hugging Face ``org/model``). */
export function packageBadgeUrl(origin: string, surface: string, name: string): string {
  return `${origin}/api/v1/public/scan/package/${surface}/${name.split('/').map(encodeURIComponent).join('/')}/badge`
}

/** README badge for a published package. */
export function PackageBadge({ surface, name }: { surface: string; name: string }) {
  if (!name) return null
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://agentavow.com'
  const img = packageBadgeUrl(origin, surface, name)
  const link = `${origin}/check/pkg/${surface}/${name.split('/').map(encodeURIComponent).join('/')}`
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

type DriftPoint = { scanned_at: string | null; trust_score: number | null; score_delta: number | null; manifest_drift: boolean }

/** Score history for a published package, from the signed drift feed. Self-hides
 * until there is recorded history. */
export function PackageHistory({ surface, name }: { surface: string; name: string }) {
  const path = `/public/drift/pkg/${surface}/${name.split('/').map(encodeURIComponent).join('/')}`
  const { data } = useQuery({
    queryKey: ['pkg-drift', surface, name],
    retry: false,
    queryFn: async () => {
      try {
        return (await publicApi.get<{ summary: { points: number }; history: DriftPoint[] }>(path)).data
      } catch { return null }
    },
  })
  if (!data || !data.history?.length) return null
  const pts = data.history.slice(0, 8)
  const drift = data.history.filter((h) => h.manifest_drift).length
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className={H3}>Score history</h3>
          <a href={`/api/v1${path}`} target="_blank" rel="noopener noreferrer" className="font-mono text-[11px] text-primary-light hover:text-primary">signed feed ↗</a>
        </div>
        <p className="mt-1.5 text-[13px] text-text-muted">{data.summary.points} recorded change{data.summary.points === 1 ? '' : 's'}{drift ? <>; the signed contents changed <span className="text-warning font-semibold">{drift}×</span></> : null}. A point is added when the score moves or the published contents change.</p>
        <div className="mt-3 flex flex-col gap-1.5 text-[12.5px]">
          {pts.map((p, i) => (
            <div key={i} className="flex justify-between gap-3">
              <span className="font-mono text-text-muted">{(p.scanned_at || '').slice(0, 10)}</span>
              <span className="font-mono">{p.trust_score ?? '–'}/100{p.score_delta ? <span className={p.score_delta > 0 ? 'text-success' : 'text-danger'}> ({p.score_delta > 0 ? '+' : ''}{p.score_delta})</span> : null}{p.manifest_drift ? <span className="text-warning"> · contents changed</span> : null}</span>
            </div>
          ))}
        </div>
      </div>
    </Reveal>
  )
}

/** "Maintain this package?" — claim it via the registry proof on My Tools. */
export function PackageClaim({ surface, name }: { surface: string; name: string }) {
  if (!name || !['npm', 'pypi', 'crates'].includes(surface)) return null
  return (
    <Reveal>
      <div className="mt-4 glass rounded-2xl p-6 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h3 className="text-[15px] font-bold">Maintain this package?</h3>
          <p className="text-text-muted text-[13.5px] mt-0.5">Claim it to get alerts when its result changes. Proof is a link to a GitHub repo you&apos;ve claimed, or a keyword you publish in a new version.</p>
        </div>
        <Link to={rp(`/rebrand/tools?coord=${encodeURIComponent(`${surface}:${name}`)}`)} className="text-[13.5px] font-semibold px-4 py-2 rounded-xl border border-border text-text hover:border-primary-light hover:text-primary-light transition-colors shrink-0">Claim this package</Link>
      </div>
    </Reveal>
  )
}
