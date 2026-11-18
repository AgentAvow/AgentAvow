/**
 * Force-directed graph visualization using react-force-graph.
 * 2D Canvas (default, handles 5000+ nodes) with optional 3D WebGL toggle.
 * Nodes sized by trust score, colored by cluster_id.
 * Trust edges pulse with directional particles.
 * LOD: labels at zoom > 1.5, details at zoom > 2.5.
 */
import { useRef, useState, useCallback, useEffect, useMemo, useSyncExternalStore } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { lazy, Suspense } from 'react'
const ForceGraph3D = lazy(() => import('react-force-graph-3d'))
import type { GraphData, GraphNode, GraphEdge } from '../../hooks/useGraphData'
import { useTheme } from '../../hooks/useTheme'
import {
  clusterColorThemed,
  edgeColor,
  nodeRadius,
  nodeTypeColor,
  GRAPH_BG,
  GRAPH_BG_LIGHT,
  GRAPH_LABEL_DARK,
  GRAPH_LABEL_LIGHT,
  GRAPH_BADGE_DARK,
  GRAPH_BADGE_LIGHT,
  GRAPH_NODE_STROKE_DARK,
  GRAPH_NODE_STROKE_LIGHT,
  ZOOM_THRESHOLDS,
  CLUSTER_GLOW_ALPHA,
  PARTICLE_CONFIG,
  DEFAULT_PARTICLE_COUNT,
} from '../../lib/graphTheme'

// Pause/resume force simulation when browser tab is hidden/visible
function subscribeVisibility(cb: () => void) {
  document.addEventListener('visibilitychange', cb)
  return () => document.removeEventListener('visibilitychange', cb)
}
function getTabHidden() { return document.hidden }

// Internal node shape used by react-force-graph (adds x, y, etc.)
interface FGNode extends GraphNode {
  x?: number
  y?: number
  z?: number
  vx?: number
  vy?: number
  vz?: number
}

// react-force-graph resolves source/target to node objects at runtime
type FGLink = GraphEdge

interface ForceGraphData {
  nodes: FGNode[]
  links: FGLink[]
}

interface ForceGraphProps {
  graphData: GraphData
  is3D: boolean
  searchTerm: string
  activeCluster: number | null
  onNodeClick?: (node: GraphNode) => void
  onNodeHover?: (node: GraphNode | null, position: { x: number; y: number }) => void
  onBackgroundClick?: () => void
}

/** Convert API GraphData (edges) to react-force-graph format (links) */
function toForceGraphData(
  data: GraphData,
  filterType: string,
  activeCluster: number | null,
): ForceGraphData {
  let nodes = [...data.nodes]
  if (filterType !== 'all') {
    nodes = nodes.filter((n) => n.type === filterType)
  }
  if (activeCluster !== null) {
    nodes = nodes.filter((n) => n.cluster_id === activeCluster)
  }

  const nodeIds = new Set(nodes.map((n) => n.id))
  const links = data.edges.filter(
    (e) => nodeIds.has(e.source) && nodeIds.has(e.target),
  )

  return { nodes, links }
}

export default function ForceGraph({
  graphData,
  is3D,
  searchTerm,
  activeCluster,
  onNodeClick,
  onNodeHover,
  onBackgroundClick,
}: ForceGraphProps) {
  const { theme } = useTheme()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fgRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  // Use a ref for zoom level to avoid triggering React re-renders from the
  // onZoom callback (which fires synchronously inside d3-zoom's handler and
  // causes "Cannot update a component while rendering" errors).
  const currentZoomRef = useRef(1)
  const [currentZoom, setCurrentZoom] = useState(1)
  const zoomRAFRef = useRef(0)

  // Pause/resume force simulation when tab is hidden — saves significant CPU
  const tabHidden = useSyncExternalStore(subscribeVisibility, getTabHidden, () => false)
  useEffect(() => {
    const fg = fgRef.current
    if (!fg) return
    if (tabHidden) {
      fg.pauseAnimation?.()
    } else {
      fg.resumeAnimation?.()
    }
  }, [tabHidden])

  // Track dimensions
  useEffect(() => {
    if (!containerRef.current) return
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        setDimensions({ width: Math.floor(width), height: Math.floor(height) })
      }
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  // Prevent wheel events from propagating beyond the graph container.
  // This is a belt-and-suspenders measure: d3-zoom already calls preventDefault()
  // and stopImmediatePropagation(), but in some browsers (especially Safari on macOS),
  // the compositor may intercept wheel events for page scroll/navigation before
  // JavaScript handlers fire. This explicit handler on the container ensures the
  // browser knows this area handles wheel events.
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const handler = (e: WheelEvent) => {
      // Only prevent default if the event target is inside the graph
      // (not on control buttons at the bottom)
      const target = e.target as HTMLElement
      if (target.tagName === 'CANVAS' || target.closest('.force-graph-container')) {
        e.preventDefault()
      }
    }
    el.addEventListener('wheel', handler, { passive: false })
    return () => el.removeEventListener('wheel', handler)
  }, [])

  // Cancel pending zoom rAF on unmount to prevent setState after unmount
  useEffect(() => {
    return () => cancelAnimationFrame(zoomRAFRef.current)
  }, [])

  // Zoom tracking — use ref + debounced state to avoid re-render during d3 handler
  const handleZoom = useCallback((transform: { k: number }) => {
    currentZoomRef.current = transform.k
    // Batch the state update via rAF to avoid updating state during render
    cancelAnimationFrame(zoomRAFRef.current)
    zoomRAFRef.current = requestAnimationFrame(() => {
      setCurrentZoom(transform.k)
    })
  }, [])

  // Search term lowered for matching
  const searchLower = searchTerm.toLowerCase().trim()

  // Build the data for react-force-graph
  const fgData = useMemo(
    () => toForceGraphData(graphData, 'all', activeCluster),
    [graphData, activeCluster],
  )

  // Node color callback
  const getNodeColor = useCallback(
    (node: object) => {
      const n = node as FGNode
      // Search highlight
      if (searchLower && n.label.toLowerCase().includes(searchLower)) {
        return '#f38ba8'
      }
      // Cluster color
      if (n.cluster_id != null) {
        return clusterColorThemed(n.cluster_id, theme)
      }
      // Fallback: type-based color
      return nodeTypeColor(n.type, theme)
    },
    [searchLower, theme],
  )

  // Node size callback
  const getNodeVal = useCallback((node: object) => {
    const n = node as FGNode
    const r = nodeRadius(n.trust_score)
    // react-force-graph uses val as area-proportional; we square the radius
    return r * r * 0.5
  }, [])

  // Custom 2D canvas node painting — semantic zoom like iOS:
  // d3-zoom scales the canvas uniformly, so we compensate by drawing nodes
  // smaller in graph-space as zoom increases. On screen, nodes grow mildly
  // (pow 0.2) instead of linearly. At 2x zoom, nodes are 1.15x bigger, not 2x.
  const paintNode = useCallback(
    (node: object, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as FGNode
      if (n.x == null || n.y == null) return

      // Semantic zoom compensation: shrink graph-space sizes so on-screen
      // size = graphSize * globalScale / pow(gs, 0.8) = graphSize * pow(gs, 0.2)
      const sem = 1 / Math.pow(globalScale, 0.8)
      const r = nodeRadius(n.trust_score) * sem
      const color = getNodeColor(n)

      // Cluster glow ring
      if (n.cluster_id != null) {
        const glowR = r + 3 * sem
        ctx.beginPath()
        ctx.arc(n.x, n.y, glowR, 0, 2 * Math.PI)
        const cc = clusterColorThemed(n.cluster_id, theme)
        ctx.fillStyle = cc + Math.round(CLUSTER_GLOW_ALPHA * 255).toString(16).padStart(2, '0')
        ctx.fill()
      }

      // Node circle
      ctx.beginPath()
      ctx.arc(n.x, n.y, r, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
      ctx.strokeStyle = theme === 'light' ? GRAPH_NODE_STROKE_LIGHT : GRAPH_NODE_STROKE_DARK
      ctx.lineWidth = 1 * sem
      ctx.stroke()

      // Search highlight ring
      if (searchLower && n.label.toLowerCase().includes(searchLower)) {
        ctx.beginPath()
        ctx.arc(n.x, n.y, r + 2 * sem, 0, 2 * Math.PI)
        ctx.strokeStyle = '#f38ba8'
        ctx.lineWidth = 2 * sem
        ctx.stroke()
      }

      // LOD: Labels — fixed screen-pixel size
      if (globalScale >= ZOOM_THRESHOLDS.showLabels) {
        const fontSize = Math.min(12, 11) / globalScale
        ctx.font = `${fontSize}px Geist, sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        ctx.fillStyle = theme === 'light' ? GRAPH_LABEL_LIGHT : GRAPH_LABEL_DARK
        ctx.fillText(n.label, n.x, n.y + r + 2 * sem)
      }

      // LOD: Trust score badge — fixed screen-pixel size
      if (globalScale >= ZOOM_THRESHOLDS.showDetails && n.trust_score != null) {
        const trustLabel = `${(n.trust_score * 100).toFixed(0)}%`
        const fontSize = 9 / globalScale
        ctx.font = `${fontSize}px Geist, sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'bottom'
        ctx.fillStyle = theme === 'light' ? GRAPH_BADGE_LIGHT : GRAPH_BADGE_DARK
        ctx.fillText(trustLabel, n.x, n.y - r - 2 * sem)
      }
    },
    [getNodeColor, searchLower, theme],
  )

  // Edge color
  const getLinkColor = useCallback((link: object) => {
    const l = link as FGLink
    return edgeColor(l.type, theme)
  }, [theme])

  // Directional particle count per edge type
  const getLinkParticles = useCallback((link: object) => {
    const l = link as FGLink
    return PARTICLE_CONFIG.count[l.type] ?? DEFAULT_PARTICLE_COUNT
  }, [])

  // Semantic edge width — shrinks in graph-space as zoom increases, thicker in light mode
  const getLinkWidth = useCallback(() => {
    const gs = currentZoomRef.current
    const base = theme === 'light' ? 2 : 1.5
    return base / Math.pow(gs, 0.8)
  }, [theme])

  // Particle width — the library already divides by sqrt(globalScale) internally,
  // so we do NOT apply our own semantic zoom compensation here.
  const getParticleWidth = useCallback(() => {
    return theme === 'light' ? PARTICLE_CONFIG.width * 1.4 : PARTICLE_CONFIG.width
  }, [theme])

  // Custom particle paint — radial gradient glow effect.
  // Draws a bright center with a soft transparent halo around it,
  // giving the appearance of a glowing dot without increasing the perceived size.
  const paintParticle = useCallback(
    (x: number, y: number, link: object, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const l = link as FGLink
      const color = edgeColor(l.type, theme)
      // 50% smaller: 0.434 * 0.5 ≈ 0.217
      const r = (theme === 'light' ? PARTICLE_CONFIG.width * 1.4 : PARTICLE_CONFIG.width) / 2 / Math.sqrt(globalScale) * 0.217
      const glowR = r * 2.5

      // Compute edge angle so the oval's long axis aligns with the line
      const src = l.source as unknown as FGNode
      const tgt = l.target as unknown as FGNode
      const angle = (src.x != null && src.y != null && tgt.x != null && tgt.y != null)
        ? Math.atan2(tgt.y - src.y, tgt.x - src.x)
        : 0

      // Oval shape — rotate to edge direction, stretch 2.4x along it
      ctx.save()
      ctx.translate(x, y)
      ctx.rotate(angle)
      ctx.scale(2.4, 1)

      // Outer glow — soft transparent halo
      const gradient = ctx.createRadialGradient(0, 0, r * 0.3, 0, 0, glowR)
      gradient.addColorStop(0, color)
      gradient.addColorStop(0.4, color + '80')
      gradient.addColorStop(1, color + '00')
      ctx.beginPath()
      ctx.arc(0, 0, glowR, 0, 2 * Math.PI)
      ctx.fillStyle = gradient
      ctx.fill()

      ctx.restore()
    },
    [theme],
  )

  // Handle node click
  const handleNodeClick = useCallback(
    (node: object) => {
      onNodeClick?.(node as FGNode)
    },
    [onNodeClick],
  )

  // Handle node hover
  const handleNodeHover = useCallback(
    (node: object | null, previousNode?: object | null) => {
      void previousNode
      if (node == null) {
        onNodeHover?.(null, { x: 0, y: 0 })
        return
      }
      const n = node as FGNode
      // Estimate screen position from node coords
      // The actual screen position is approximate; for the tooltip we rely
      // on the mouse event position captured by the container overlay.
      onNodeHover?.(n, { x: 0, y: 0 })
    },
    [onNodeHover],
  )

  // 3D node color (THREE.js compatible — just a hex string)
  const getNodeColor3D = useCallback(
    (node: object) => {
      return getNodeColor(node)
    },
    [getNodeColor],
  )

  // Common props for both 2D and 3D
  const commonProps = {
    graphData: fgData,
    nodeId: 'id' as const,
    nodeLabel: 'label' as const,
    nodeColor: is3D ? getNodeColor3D : undefined,
    nodeVal: getNodeVal,
    linkSource: 'source' as const,
    linkTarget: 'target' as const,
    linkColor: getLinkColor,
    linkDirectionalParticles: getLinkParticles,
    linkDirectionalParticleWidth: is3D ? PARTICLE_CONFIG.width : getParticleWidth,
    linkDirectionalParticleSpeed: PARTICLE_CONFIG.speed,
    linkOpacity: is3D ? (theme === 'light' ? 0.7 : 0.45) : undefined, // 2D canvas ignores this prop
    linkWidth: is3D ? 1.5 : getLinkWidth,
    onNodeClick: handleNodeClick,
    onNodeHover: handleNodeHover,
    onBackgroundClick: onBackgroundClick,
    backgroundColor: theme === 'light' ? GRAPH_BG_LIGHT : GRAPH_BG,
    width: dimensions.width,
    height: dimensions.height,
    warmupTicks: 50,
    cooldownTime: 3000,
  }

  return (
    <div ref={containerRef} className="w-full h-full relative" style={{ touchAction: 'none', overscrollBehavior: 'contain' }}>
      {is3D ? (
        <Suspense fallback={<div className="w-full h-full flex items-center justify-center text-text-muted">Loading 3D engine...</div>}>
          <ForceGraph3D
            ref={fgRef as React.MutableRefObject<never>}
            {...commonProps}
            nodeOpacity={0.9}
            linkDirectionalParticleColor={getLinkColor}
          />
        </Suspense>
      ) : (
        <ForceGraph2D
          ref={fgRef as React.MutableRefObject<never>}
          {...commonProps}
          nodeCanvasObject={paintNode}
          nodeCanvasObjectMode={() => 'replace' as const}
          onZoom={handleZoom}
          linkDirectionalParticleColor={getLinkColor}
          linkDirectionalParticleCanvasObject={paintParticle}
        />
      )}

      {/* Controls hint + actions */}
      <div className="absolute bottom-3 left-3 flex items-center gap-3">
        <span className="text-[10px] text-text-muted/50 pointer-events-none">
          Scroll to zoom &middot; Drag to pan &middot; Click node for actions
          {!is3D && ` · Zoom: ${currentZoom.toFixed(1)}x`}
        </span>
      </div>
      <div className="absolute bottom-3 right-3 flex items-center gap-1.5">
        <button
          onClick={() => fgRef.current?.zoomToFit(400, 40)}
          className="px-2 py-1 rounded text-[10px] bg-surface/80 text-text-muted hover:text-text border border-border/50 cursor-pointer transition-colors"
          title="Fit all nodes in view"
        >
          Fit
        </button>
        <button
          onClick={() => { fgRef.current?.centerAt(0, 0, 400); fgRef.current?.zoom(1, 400) }}
          className="px-2 py-1 rounded text-[10px] bg-surface/80 text-text-muted hover:text-text border border-border/50 cursor-pointer transition-colors"
          title="Reset zoom and center"
        >
          Reset
        </button>
      </div>
    </div>
  )
}
