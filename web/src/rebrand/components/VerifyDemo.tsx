import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { publicApi } from '../../lib/scanApi'

/**
 * A REAL, live verification — not a mock. Pulls a signed attestation (EdDSA JWS)
 * for a sample tool, fetches our public JWKS, and verifies the signature in your
 * browser with Web Crypto. "Tamper with it" flips a byte so you can watch
 * verification fail — that's the whole point: you can check the math yourself.
 */

const DEFAULT = 'agenttrust/mcp-server'

function b64urlToBytes(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

type State = { status: 'idle' | 'working' | 'ok' | 'fail' | 'unsupported'; detail?: string }

export function VerifyDemo() {
  const [state, setState] = useState<State>({ status: 'idle' })
  const [input, setInput] = useState('')
  const [target, setTarget] = useState(DEFAULT)

  const { data: scan, isFetching } = useQuery({
    queryKey: ['verify-sample', target],
    queryFn: async () => (await publicApi.get<{ jws: string; key_id: string; jwks_url: string }>(`/public/scan/${target}`)).data,
    retry: 0,
  })

  const loadTarget = () => {
    const m = input.trim().match(/(?:github\.com\/)?([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/)
    if (m) { setTarget(`${m[1]}/${m[2]}`); setState({ status: 'idle' }) }
  }

  const run = async (tamper: boolean) => {
    if (!scan?.jws) return
    setState({ status: 'working' })
    try {
      if (!crypto.subtle || !('importKey' in crypto.subtle)) {
        setState({ status: 'unsupported' }); return
      }
      const [h, p, s] = scan.jws.split('.')
      // tamper: flip a character in the payload so the signature no longer matches
      const payload = tamper ? (p[0] === 'A' ? 'B' : 'A') + p.slice(1) : p
      const signingInput = new TextEncoder().encode(`${h}.${payload}`)
      const sig = b64urlToBytes(s)

      const jwks = await fetch('/.well-known/jwks.json').then((r) => r.json())
      const jwk = (jwks.keys || []).find((k: { kid?: string }) => k.kid === scan.key_id) || jwks.keys?.[0]
      if (!jwk) { setState({ status: 'fail', detail: 'no matching key in JWKS' }); return }

      const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, { name: 'Ed25519' }, false, ['verify'])
      const ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, sig as BufferSource, signingInput as BufferSource)
      setState(ok ? { status: 'ok', detail: scan.key_id } : { status: 'fail', detail: tamper ? 'signature no longer matches the tampered payload' : 'signature did not verify' })
    } catch (e) {
      // Older browsers may not support Ed25519 in Web Crypto.
      setState({ status: 'unsupported', detail: String((e as Error).message || e) })
    }
  }

  return (
    <div className="glass rounded-2xl p-6">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-wide text-primary-light">Live verification</div>
          <h3 className="mt-1 text-lg font-bold">Verify a real attestation, right here.</h3>
          <p className="text-text-muted text-[13.5px] mt-1 max-w-[54ch]">This runs entirely in your browser against our public keys — no server round-trip for the check. Try any tool:</p>
        </div>
      </div>

      {/* pick a tool to verify */}
      <form onSubmit={(e) => { e.preventDefault(); loadTarget() }} className="mt-3 flex gap-2 items-center rounded-xl border border-border bg-surface p-1.5 pl-3 max-w-[440px]">
        <span className="font-mono text-[12.5px] text-text-muted shrink-0">github.com/</span>
        <input value={input} onChange={(e) => setInput(e.target.value)} placeholder={target}
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[13px] text-text placeholder:text-text-muted" />
        <button type="submit" className="text-[12px] font-semibold px-3 py-1.5 rounded-lg text-white bg-primary/80 hover:bg-primary shrink-0">Load</button>
      </form>
      <div className="mt-1.5 font-mono text-[11.5px] text-text-muted">verifying: {target}{isFetching && ' · loading…'}</div>

      <div className="mt-4 flex gap-2 flex-wrap">
        <button onClick={() => run(false)} disabled={!scan || state.status === 'working'} className="text-[13px] font-semibold px-4 py-2 rounded-xl text-white bg-gradient-to-r from-primary to-primary-dark disabled:opacity-60">
          {state.status === 'working' ? 'Verifying…' : 'Verify the signature'}
        </button>
        <button onClick={() => run(true)} disabled={!scan || state.status === 'working'} className="text-[13px] font-semibold px-4 py-2 rounded-xl border border-border text-text-muted hover:border-danger hover:text-danger transition-colors disabled:opacity-60">
          Tamper with it →
        </button>
      </div>

      {state.status === 'ok' && (
        <div className="mt-4 rounded-xl p-4 bg-success/10 border border-success/40">
          <div className="flex items-center gap-2 text-success font-semibold text-[14px]">
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" /><path d="M7.5 12.4l3 3 6-6.4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
            Verified ✓
          </div>
          <p className="text-[13px] text-text-muted mt-1">The signature is valid — this attestation was signed by AgentAvow's key <span className="font-mono">{state.detail}</span> and hasn't been altered.</p>
        </div>
      )}
      {state.status === 'fail' && (
        <div className="mt-4 rounded-xl p-4 bg-danger/10 border border-danger/40">
          <div className="flex items-center gap-2 text-danger font-semibold text-[14px]">
            <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5"><circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.6" /><path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
            NOT verified ✗
          </div>
          <p className="text-[13px] text-text-muted mt-1">Verification failed — {state.detail}. This is exactly what you'd see if someone faked or edited the grade: the math doesn't lie.</p>
        </div>
      )}
      {state.status === 'unsupported' && (
        <p className="mt-4 text-[13px] text-text-muted">Your browser doesn't expose Ed25519 in Web Crypto. You can still verify from the command line or our SDK against the <a href="/.well-known/jwks.json" target="_blank" rel="noopener noreferrer" className="text-primary-light hover:text-primary">public JWKS</a>.</p>
      )}
    </div>
  )
}
