/**
 * Generates a fun, branded share card as an SVG (NOT the README badge) that a
 * developer can download and post on their site — the hero score, dual axes, and
 * the AgentAvow checkmark. 1200×630 (og-image proportions).
 */
export interface ScoreCardData {
  repo: string
  grade: string
  score: number
  tier: string
  gradeHex: string
  attestation: number
  adoption: string        // compact value: "1.2k" or "New"
  adoptionSub?: string    // unit next to the adoption number: "stars" / "checks"
  adoptionPct?: number    // 0–100 log-scaled traction bar fill
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

const ADOPTION_HEX = '#F59E0B'

export function scoreCardSvg(d: ScoreCardData): string {
  const R = 100
  const circ = 2 * Math.PI * R
  const dash = (Math.max(d.score, 0) / 100) * circ
  const hasAdoption = d.adoption.toLowerCase() !== 'new'
  const aHex = hasAdoption ? ADOPTION_HEX : '#5c6370'
  const barW = 300
  const barFill = hasAdoption ? Math.max((d.adoptionPct ?? 0) / 100, 0.05) * barW : 0
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" font-family="Geist, system-ui, -apple-system, sans-serif">
  <defs>
    <radialGradient id="glow" cx="0.5" cy="0.42" r="0.7">
      <stop stop-color="#123" stop-opacity="0.9"/><stop offset="1" stop-color="#0B1220" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="brand" x1="0" y1="0" x2="1" y2="1">
      <stop stop-color="#2DD4BF"/><stop offset="1" stop-color="#E879F9"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="#0B1220"/>
  <rect width="1200" height="630" fill="url(#glow)"/>

  <!-- brand lockup -->
  <g transform="translate(70,66)">
    <circle cx="20" cy="20" r="18" fill="none" stroke="url(#brand)" stroke-width="3.4"/>
    <path d="M12 21l6 6 12-13" fill="none" stroke="url(#brand)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="52" y="30" fill="#F8FAFC" font-size="30" font-weight="700" letter-spacing="-0.5">AgentAvow</text>
  </g>
  <text x="1130" y="88" text-anchor="end" fill="#94A3B8" font-size="24" font-family="monospace">${esc(d.repo)}</text>

  <!-- verdict / tier, centered -->
  <text x="600" y="176" text-anchor="middle" fill="#CBD5E1" font-size="34" font-weight="800">${esc(d.tier)}</text>

  <!-- two co-equal rings -->
  <!-- Attestation Trust -->
  <g transform="translate(415,360)">
    <circle r="${R}" fill="none" stroke="#1b2b2b" stroke-width="20"/>
    <circle r="${R}" fill="none" stroke="${d.gradeHex}" stroke-width="20" stroke-linecap="round"
      stroke-dasharray="${dash.toFixed(1)} ${circ.toFixed(1)}" transform="rotate(-90)"/>
    <text x="0" y="18" text-anchor="middle" fill="${d.gradeHex}" font-size="86" font-weight="800">${esc(d.grade)}</text>
    <text x="0" y="52" text-anchor="middle" fill="#94A3B8" font-size="24" font-family="monospace">${d.score}/100</text>
  </g>
  <text x="415" y="500" text-anchor="middle" fill="${d.gradeHex}" font-size="18" font-weight="700" font-family="monospace" letter-spacing="1">ATTESTATION TRUST</text>
  <text x="415" y="528" text-anchor="middle" fill="#94A3B8" font-size="18">signed · verifiable now</text>

  <!-- Adoption (progress bar — reads distinct from the trust gauge) -->
  <text x="785" y="342" text-anchor="middle" fill="${aHex}" font-size="76" font-weight="800">${esc(d.adoption)}</text>
  ${d.adoptionSub ? `<text x="785" y="378" text-anchor="middle" fill="#94A3B8" font-size="24" font-family="monospace">${esc(d.adoptionSub)}</text>` : ''}
  <rect x="${785 - barW / 2}" y="405" width="${barW}" height="16" rx="8" fill="#2a2620"/>
  <rect x="${785 - barW / 2}" y="405" width="${barFill.toFixed(1)}" height="16" rx="8" fill="${aHex}"/>
  <text x="785" y="500" text-anchor="middle" fill="${aHex}" font-size="18" font-weight="700" font-family="monospace" letter-spacing="1">ADOPTION</text>
  <text x="785" y="528" text-anchor="middle" fill="#94A3B8" font-size="18">${hasAdoption ? 'ecosystem usage' : 'be the first'}</text>

  <!-- footer -->
  <text x="600" y="596" text-anchor="middle" fill="#64748B" font-size="18" font-family="monospace">Signed · Ed25519 · verify offline at agentavow.com</text>
</svg>`
}

/** Trigger a client-side download of the score card SVG. */
export function downloadScoreCard(d: ScoreCardData): void {
  const blob = new Blob([scoreCardSvg(d)], { type: 'image/svg+xml' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `agentavow-${d.repo.replace('/', '-')}.svg`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
