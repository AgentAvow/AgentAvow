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
  adoption: string
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

export function scoreCardSvg(d: ScoreCardData): string {
  const ring = 2 * Math.PI * 90
  const dash = (Math.max(d.score, 0) / 100) * ring
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" font-family="Geist, system-ui, -apple-system, sans-serif">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1200" y2="630" gradientUnits="userSpaceOnUse">
      <stop stop-color="#0A0F0F"/><stop offset="1" stop-color="#0F1B1B"/>
    </linearGradient>
    <linearGradient id="brand" x1="0" y1="0" x2="1" y2="1">
      <stop stop-color="#2DD4BF"/><stop offset="1" stop-color="#E879F9"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <circle cx="1050" cy="90" r="360" fill="${d.gradeHex}" opacity="0.10"/>
  <!-- brand -->
  <g transform="translate(64,60)">
    <circle cx="18" cy="18" r="16" fill="none" stroke="url(#brand)" stroke-width="3"/>
    <path d="M11 18.5l4.5 4.5 9-9.5" fill="none" stroke="#2DD4BF" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="46" y="26" fill="#CDD6F4" font-size="26" font-weight="700">AgentAvow</text>
  </g>
  <!-- grade ring -->
  <g transform="translate(230,340)">
    <circle r="100" fill="none" stroke="#1e2b2b" stroke-width="18"/>
    <circle r="90" fill="none" stroke="${d.gradeHex}" stroke-width="18" stroke-linecap="round"
      stroke-dasharray="${dash.toFixed(1)} ${ring.toFixed(1)}" transform="rotate(-90)"/>
    <text x="0" y="6" text-anchor="middle" fill="${d.gradeHex}" font-size="88" font-weight="800">${esc(d.grade)}</text>
    <text x="0" y="52" text-anchor="middle" fill="#9399b2" font-size="26" font-family="monospace">${d.score}/100</text>
  </g>
  <!-- right column -->
  <g transform="translate(400,230)">
    <text x="0" y="0" fill="#9399b2" font-size="24" font-family="monospace">${esc(d.repo)}</text>
    <text x="0" y="52" fill="#CDD6F4" font-size="40" font-weight="800">${esc(d.tier)}</text>
    <!-- dual score -->
    <g transform="translate(0,96)">
      <rect x="0" y="0" width="330" height="96" rx="14" fill="#111B1B" stroke="#2A4040"/>
      <text x="20" y="32" fill="#6C7086" font-size="15" font-family="monospace" letter-spacing="1">ATTESTATION TRUST</text>
      <text x="20" y="70" fill="#2DD4BF" font-size="34" font-weight="800">${d.attestation}/100</text>
      <rect x="350" y="0" width="330" height="96" rx="14" fill="#111B1B" stroke="#2A4040"/>
      <text x="370" y="32" fill="#6C7086" font-size="15" font-family="monospace" letter-spacing="1">ADOPTION</text>
      <text x="370" y="66" fill="#F59E0B" font-size="26" font-weight="700">${esc(d.adoption)}</text>
    </g>
  </g>
  <!-- footer -->
  <g transform="translate(64,566)">
    <path d="M10 10 m-9 0 a9 9 0 1 0 18 0 a9 9 0 1 0 -18 0" fill="none" stroke="#a6e3a1" stroke-width="1.6"/>
    <path d="M6 10.5l3 3 6-6.5" fill="none" stroke="#a6e3a1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="30" y="16" fill="#a6e3a1" font-size="19" font-family="monospace">Signed · Ed25519 · verify offline at agentavow.com</text>
  </g>
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
