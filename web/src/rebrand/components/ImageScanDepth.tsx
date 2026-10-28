/** Container-image rows for the "chain we verified" card: how much of the image the
 * scan actually read (layers, app files, packages) and what the CVE check found. Reads
 * surface_detail.image (set by the layer walk); older results without it keep the
 * config-only wording, which was true for them. */

type ImageVulns = {
  ok?: boolean
  os?: string | null
  packages_checked?: number
  fixable?: number
  unfixed?: number
  note?: string
  error?: string
}

type ImageDetail = {
  depth?: 'full' | 'partial' | 'config'
  layers_total?: number
  layers_scanned?: number
  app_files?: number
  packages?: number
  reason?: string | null
  os?: string | null
  vulnerabilities?: ImageVulns
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

export function imageDetail(scan: unknown): ImageDetail | null {
  const sd = (scan as { surface_detail?: { image?: ImageDetail } }).surface_detail
  return sd?.image ?? null
}

export default function ImageScanDepth({ scan }: { scan: unknown }) {
  const img = imageDetail(scan)
  if (!img) {
    return (
      <div className="flex justify-between gap-3"><span className="text-text-muted">Scan depth</span>
        <span className="font-mono text-warning text-right">image config &amp; metadata only (layers not scanned)</span></div>
    )
  }
  const total = img.layers_total ?? 0
  const read = img.layers_scanned ?? 0
  const files = img.app_files ?? 0
  const depthText = img.depth === 'config'
    ? `image config & metadata only${img.reason ? ` (${img.reason})` : ''}`
    : img.depth === 'partial'
      ? `${read} of ${plural(total, 'layer')} read${img.reason ? ` (${img.reason})` : ''} · ${plural(files, 'app file')}`
      : `all ${plural(total, 'layer')} read · ${plural(files, 'app file')}`
  const v = img.vulnerabilities
  let pkgText = '—'
  if (v?.ok) {
    const fixable = v.fixable ?? 0
    pkgText = `${plural(v.packages_checked ?? 0, 'package')} checked · ${fixable === 0 ? 'no known CVEs with a released fix' : `${plural(fixable, 'CVE')} with a released fix`}`
  } else if (v?.note) {
    pkgText = v.note
  } else if (img.packages) {
    pkgText = `${plural(img.packages, 'package')} found · CVE lookup unavailable`
  }
  return (
    <>
      <div className="flex justify-between gap-3"><span className="text-text-muted">Scan depth</span>
        <span className={`font-mono text-right ${img.depth === 'full' ? 'text-success' : 'text-warning'}`}>{depthText}</span></div>
      {img.os && <div className="flex justify-between gap-3"><span className="text-text-muted">Base OS</span><span className="font-mono text-right">{img.os}</span></div>}
      <div className="flex justify-between gap-3"><span className="text-text-muted">Image packages</span><span className="font-mono text-right">{pkgText}</span></div>
    </>
  )
}
