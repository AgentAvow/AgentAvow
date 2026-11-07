/**
 * Build-time snapshot of a page (web/scripts/prerender.mjs).
 *
 * A prerendered page ships its HTML in <div id="prerender">, beside an empty #root.
 * The app mounts into #root as usual, hidden by CSS (index.css) while the snapshot
 * stays on screen, and takes over once the page's code has loaded. Nothing is
 * hydrated, so the app is free to differ from the snapshot (signed-in header, live
 * numbers) without a mismatch. Routes with no snapshot never see any of this.
 *
 * While inSnapshot() is true, entrance animations must not start from opacity 0:
 * in the build that would ship invisible text, and in the browser the visible
 * snapshot would blink out when the app takes over.
 */
export function inSnapshot(): boolean {
  return import.meta.env.SSR || document.getElementById('prerender') !== null
}

/** Hand the screen to the app. index.css unhides #root when the snapshot is gone. */
export function dropSnapshot(): void {
  if (!import.meta.env.SSR) document.getElementById('prerender')?.remove()
}

/** Query results the build fetched, so live figures don't blink back to their fallbacks. */
export function snapshotQueryState(): unknown {
  const el = document.getElementById('prerender-state')
  if (!el?.textContent) return undefined
  try {
    return JSON.parse(el.textContent)
  } catch {
    return undefined
  }
}
