/**
 * Short adoption units, one table for every adoption display on the site, so a tool
 * reads the same everywhere ("867M dl/wk", "12k ★"). Twin of src/adoption_units.py
 * and the MCP trust card's shortUnit; keep the three tables identical. The full unit
 * stays in titles and aria labels.
 */
const SHORT_UNITS: Record<string, string> = {
  'downloads/wk': 'dl/wk',
  'downloads/mo': 'dl/mo',
  'downloads/yr': 'dl/yr',
  'downloads/90d': 'dl/90d',
  downloads: 'dl',
  stars: '★',
  'stars (linked repo)': '★',
  pulls: 'pulls',
  dependents: 'deps',
  installs: 'installs',
  likes: 'likes',
}

export function shortUnit(unit?: string | null): string {
  const u = (unit || '').trim()
  if (!u) return ''
  return SHORT_UNITS[u.toLowerCase()] ?? u.replace(/downloads/g, 'dl')
}
