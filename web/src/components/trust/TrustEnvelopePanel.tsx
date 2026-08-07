/**
 * TrustEnvelopePanel — presentational render of a signed Trust Score v2 envelope.
 *
 * Shared by the Profile page (fetches by DID via VerifiedTrustEnvelope) and the
 * /check page (uses the envelope embedded in the scan response). Shows each
 * contribution's source + weighted share + contested flag, plus download/verify/
 * JWKS links. Pure presentational — no data fetching.
 */
import { useState } from 'react'

export interface EnvelopeContribution {
  source: string
  raw_signal: number
  weighted_contribution: number
  claim_type?: string
  source_provider_did?: string
  contested_signal?: boolean
  _metadata?: { v1_component?: string; v1_weight?: number }
}

export interface TrustEnvelope {
  subject_did: string
  trust_score: number
  score_version: string
  computed_at: string
  freshness_ttl_seconds: number
  contributions: EnvelopeContribution[]
  issuer: string
  proof?: { verificationMethod?: string; jws?: string }
}

const SOURCE_LABEL: Record<string, string> = {
  scan_corpus: 'AgentAvow security scan',
  erc8004_reputation: 'On-chain reputation (ERC-8004)',
  ctef_attestation: 'CTEF attestation',
  community_signal: 'Community signals',
  self_attested: 'Identity verification',
  third_party_observer: 'Third-party evaluation',
}

function sourceLabel(c: EnvelopeContribution): string {
  return SOURCE_LABEL[c.source] ?? c.source
}

export default function TrustEnvelopePanel({
  env,
  verifyHref,
  defaultOpen = false,
}: {
  env: TrustEnvelope
  verifyHref?: string
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)

  if (!env || !env.contributions?.length) return null

  const downloadEnvelope = () => {
    const blob = new Blob([JSON.stringify(env, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `trust-envelope-${env.subject_did.replace(/[:/]/g, '_')}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mb-4 rounded-xl border border-border bg-surface-1 p-4">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between text-left"
      >
        <span className="text-sm font-medium text-text-primary">Verified methodology</span>
        <span className="text-xs text-text-muted">
          {open ? 'Hide' : 'Show'} · {env.contributions.length} sources
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-2">
          {env.contributions.map((c, i) => (
            <div key={i} className="flex items-baseline justify-between gap-2">
              <div className="min-w-0">
                <span className="text-sm text-text-primary">{sourceLabel(c)}</span>
                {c.contested_signal && (
                  <span className="ml-2 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-500">
                    contested
                  </span>
                )}
                {c.source_provider_did && (
                  <p className="truncate text-xs text-text-muted">{c.source_provider_did}</p>
                )}
              </div>
              <span className="shrink-0 tabular-nums text-sm text-text-secondary">
                +{Math.round(c.weighted_contribution * 100)}%
              </span>
            </div>
          ))}

          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border pt-3 text-xs">
            <button type="button" onClick={downloadEnvelope} className="text-accent hover:underline">
              Download signed envelope ↓
            </button>
            {verifyHref && (
              <a href={verifyHref} target="_blank" rel="noreferrer" className="text-accent hover:underline">
                Verify ↗
              </a>
            )}
            <a
              href="/.well-known/jwks.json"
              target="_blank"
              rel="noreferrer"
              className="text-accent hover:underline"
            >
              Public key (JWKS) ↗
            </a>
            <span className="text-text-muted">Signed {env.score_version} · refreshes hourly</span>
          </div>
        </div>
      )}
    </div>
  )
}
