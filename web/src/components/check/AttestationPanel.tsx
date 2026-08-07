/**
 * AttestationPanel — makes the "signed & verifiable" story real in the UI.
 *
 * Every scan is returned as a signed JWS (EdDSA) verifiable against the public JWKS.
 * This surfaces the algorithm / key id, lets you copy or download the attestation, and
 * links to the JWKS so a third party can verify it independently — no trust in us.
 */
import { useState } from 'react'

interface Props {
  jws?: string
  keyId?: string
  algorithm?: string
  jwksUrl?: string
  owner: string
  repo: string
}

export default function AttestationPanel({ jws, keyId, algorithm, jwksUrl, owner, repo }: Props) {
  const [copied, setCopied] = useState(false)
  if (!jws) return null

  const copy = () => {
    navigator.clipboard.writeText(jws).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const download = () => {
    const blob = new Blob([jws], { type: 'application/jose' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${owner}-${repo}.attestation.jws`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="rounded-lg border border-border bg-surface p-4">
      <div className="flex items-start gap-3">
        <span className="text-lg leading-none mt-0.5" aria-hidden="true">
          ✍️
        </span>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-text-primary">Signed &amp; verifiable</h3>
          <p className="text-xs text-text-muted mt-0.5">
            This result is a signed attestation ({algorithm || 'EdDSA'}). Anyone can verify it
            against AgentAvow&rsquo;s public keys — no need to trust this page.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-text-muted font-mono">
            {algorithm && <span>alg: {algorithm}</span>}
            {keyId && <span>kid: {keyId}</span>}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-3 text-xs">
            <button
              onClick={copy}
              className="text-primary-light hover:text-primary transition-colors cursor-pointer"
            >
              {copied ? 'Copied!' : 'Copy attestation (JWS)'}
            </button>
            <button
              onClick={download}
              className="text-primary-light hover:text-primary transition-colors cursor-pointer"
            >
              Download
            </button>
            {jwksUrl && (
              <a
                href={jwksUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary-light hover:text-primary transition-colors"
              >
                Public keys (JWKS) ↗
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
