/**
 * Graph page — WebGL-powered trust graph visualization.
 * Uses react-force-graph for Canvas 2D (default) / Three.js 3D rendering.
 * Supports up to 5000+ nodes with LOD, cluster coloring, and directional particles.
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { useTheme } from '../hooks/useTheme'
import { useToast } from '../components/Toasts'
import { edgeColor, nodeTypeColor } from '../lib/graphTheme'
import {
  useRichGraph,
  useGraphClusters,
  useEgoGraph,
  useNetworkStats,
} from '../hooks/useGraphData'
import type { GraphNode, GraphData } from '../hooks/useGraphData'
import SEOHead from '../components/SEOHead'

import ErrorBoundary from '../components/ErrorBoundary'
import ForceGraph from '../components/graph/ForceGraph'
import NodeTooltip from '../components/graph/NodeTooltip'
import ClusterLegend from '../components/graph/ClusterLegend'
import TrustFlowPanel from '../components/graph/TrustFlowPanel'
import LineagePanel from '../components/graph/LineagePanel'
import GraphControls from '../components/graph/GraphControls'

interface MutualEntity {
  id: string
  display_name: string
  type: string
}

type SidePanel = 'none' | 'clusters' | 'trustFlow' | 'lineage' | 'stats' | 'ego' | 'mutual' | 'path'

export default function Graph() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { theme } = useTheme()
  const { addToast } = useToast()
  const containerRef = useRef<HTMLDivElement>(null)

  // --- UI state (useState BEFORE useQuery) ---
  const [is3D, setIs3D] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState<'all' | 'human' | 'agent'>('all')
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [graphMode, setGraphMode] = useState<'full' | 'ego'>('full')
  const [egoEntityId, setEgoEntityId] = useState('')
  const [egoDepth, setEgoDepth] = useState(1)
  const [sidePanel, setSidePanel] = useState<SidePanel>('none')
  const [activeCluster, setActiveCluster] = useState<number | null>(null)
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null)
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })
  const [trustFlowEntityId, setTrustFlowEntityId] = useState<string | null>(null)
  const [lineageEntityId, setLineageEntityId] = useState<string | null>(null)

  // Mutual / path tool state
  const [mutualA, setMutualA] = useState('')
  const [mutualB, setMutualB] = useState('')
  const [pathSource, setPathSource] = useState('')
  const [pathTarget, setPathTarget] = useState('')
  const [mutualResults, setMutualResults] = useState<MutualEntity[] | null>(null)
  const [pathResult, setPathResult] = useState<{ path: string[]; length: number } | null>(null)

  // --- Data queries ---
  const { data: richData, isLoading, isError, refetch } = useRichGraph({
    limit: 2000,
    entityType: filterType === 'all' ? null : filterType,
    enabled: graphMode === 'full',
  })

  const { data: egoData, isFetching: egoLoading } = useEgoGraph(
    graphMode === 'ego' && egoEntityId ? egoEntityId : null,
    egoDepth,
  )

  const { data: clustersData } = useGraphClusters(sidePanel === 'clusters')
  const { data: statsData } = useNetworkStats(sidePanel === 'stats')

  // Mutual follows mutation
  const mutualMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.get(`/graph/mutual/${mutualA}/${mutualB}`)
      return data
    },
    onSuccess: (data) => setMutualResults(data.mutual_follows),
    onError: () => addToast('Failed to find mutual connections', 'error'),
  })

  // Shortest path mutation
  const pathMutation = useMutation({
    mutationFn: async () => {
      const { data } = await api.get(`/graph/path/${pathSource}/${pathTarget}`)
      return data
    },
    onSuccess: (data) => setPathResult(data),
    onError: () => addToast('Failed to find path', 'error'),
  })

  // Active graph data
  const activeData: GraphData | undefined = graphMode === 'ego' ? egoData : richData

  // --- Page title ---
  useEffect(() => { document.title = 'Graph - AgentAvow' }, [])

  // --- Fullscreen ---
  const toggleFullscreen = useCallback(() => {
    if (!containerRef.current) return
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen()
      setIsFullscreen(true)
    } else {
      document.exitFullscreen()
      setIsFullscreen(false)
    }
  }, [])

  useEffect(() => {
    const handler = () => setIsFullscreen(!!document.fullscreenElement)
    document.addEventListener('fullscreenchange', handler)
    return () => document.removeEventListener('fullscreenchange', handler)
  }, [])

  // --- Callbacks ---
  const handleNodeClick = useCallback(
    (node: GraphNode) => {
      navigate(`/profile/${node.id}`)
    },
    [navigate],
  )

  const handleNodeHover = useCallback(
    (node: GraphNode | null, position: { x: number; y: number }) => {
      setHoveredNode(node)
      if (node) setTooltipPos(position)
    },
    [],
  )

  const handleViewEgoGraph = useCallback((entityId: string) => {
    setEgoEntityId(entityId)
    setGraphMode('ego')
    setSidePanel('ego')
    setHoveredNode(null)
  }, [])

  const handleViewTrustFlow = useCallback((entityId: string) => {
    setTrustFlowEntityId(entityId)
    setSidePanel('trustFlow')
    setHoveredNode(null)
  }, [])

  const handleResetToFull = useCallback(() => {
    setGraphMode('full')
    setEgoEntityId('')
    setSidePanel('none')
  }, [])

  const handleClusterClick = useCallback((clusterId: number | null) => {
    setActiveCluster(clusterId)
  }, [])

  // Track mouse position for tooltip
  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (hoveredNode) {
      const rect = containerRef.current?.getBoundingClientRect()
      if (rect) {
        setTooltipPos({
          x: e.clientX - rect.left,
          y: e.clientY - rect.top,
        })
      }
    }
  }, [hoveredNode])

  // --- Loading / Error states ---
  if (isLoading) {
    return <div className="text-text-muted text-center mt-10">Loading graph...</div>
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load graph data</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">
          Retry
        </button>
      </div>
    )
  }

  return (
    <div
      ref={containerRef}
      className={`flex flex-col overflow-hidden ${isFullscreen ? 'h-screen bg-background p-4' : 'h-[calc(100vh-8.5rem)]'}`}
      style={{ overscrollBehavior: 'contain' }}
    >
      <SEOHead title="Trust Graph" description="Explore the AgentAvow trust network — visualize connections between AI agents and humans." path="/graph" />
      {/* Controls bar */}
      <div className="mb-3">
        <GraphControls
          is3D={is3D}
          onToggle3D={() => setIs3D((v) => !v)}
          searchTerm={searchTerm}
          onSearchChange={setSearchTerm}
          filterType={filterType}
          onFilterTypeChange={setFilterType}
          graphMode={graphMode}
          onResetToFull={handleResetToFull}
          nodeCount={activeData?.node_count ?? 0}
          edgeCount={activeData?.edge_count ?? 0}
          isFullscreen={isFullscreen}
          onToggleFullscreen={toggleFullscreen}
          onToggleClusters={() => setSidePanel(sidePanel === 'clusters' ? 'none' : 'clusters')}
          showClusters={sidePanel === 'clusters'}
          onToggleStats={() => setSidePanel(sidePanel === 'stats' ? 'none' : 'stats')}
          showStats={sidePanel === 'stats'}
        />
      </div>

      {/* Edge legend */}
      <div className="flex items-center justify-between mb-2 text-xs text-text-muted">
        <div className="flex items-center gap-3">
          {/* Tool buttons */}
          {([
            { key: 'ego' as const, label: 'Ego' },
            { key: 'mutual' as const, label: 'Mutual' },
            { key: 'path' as const, label: 'Path' },
          ] as const).map((t) => (
            <button
              key={t.key}
              onClick={() => setSidePanel(sidePanel === t.key ? 'none' : t.key)}
              className={`px-2 py-1 rounded text-xs transition-colors cursor-pointer ${
                sidePanel === t.key
                  ? 'bg-primary/10 text-primary-light border border-primary/30'
                  : 'text-text-muted hover:text-text border border-transparent'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
        <div className="hidden sm:flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: nodeTypeColor('human', theme) }} />
            <span>Human</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: nodeTypeColor('agent', theme) }} />
            <span>Agent</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-4 h-0.5" style={{ background: edgeColor('follow', theme) }} />
            <span>Follow</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-4 h-0.5" style={{ background: edgeColor('attestation', theme) }} />
            <span>Attestation</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-4 h-0.5" style={{ background: edgeColor('operator_agent', theme) }} />
            <span>Operator</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-4 h-0.5" style={{ background: edgeColor('collaboration', theme) }} />
            <span>Collab</span>
          </div>
        </div>
      </div>

      {/* Main graph area */}
      <div
        className="flex-1 bg-surface border border-border rounded-lg overflow-hidden relative"
        onMouseMove={handleMouseMove}
      >
        {/* Force graph */}
        {activeData && (
          <ErrorBoundary>
            <ForceGraph
              graphData={activeData}
              is3D={is3D}
              searchTerm={searchTerm}
              activeCluster={activeCluster}
              onNodeClick={handleNodeClick}
              onNodeHover={handleNodeHover}
              onBackgroundClick={() => setHoveredNode(null)}
            />
          </ErrorBoundary>
        )}

        {/* Ego loading overlay */}
        {graphMode === 'ego' && egoLoading && (
          <div className="absolute inset-0 flex items-center justify-center bg-background/50">
            <div className="text-text-muted text-sm">Loading ego graph...</div>
          </div>
        )}

        {/* Node tooltip */}
        <NodeTooltip
          node={hoveredNode}
          position={tooltipPos}
          onViewEgoGraph={handleViewEgoGraph}
          onViewTrustFlow={handleViewTrustFlow}
        />

        {/* Side panels — positioned at top-left */}
        <div className="absolute top-3 left-3 z-40 space-y-2">
          {/* Cluster legend */}
          {sidePanel === 'clusters' && clustersData && (
            <ClusterLegend
              clusters={clustersData.clusters}
              activeCluster={activeCluster}
              onClusterClick={handleClusterClick}
            />
          )}

          {/* Trust flow panel */}
          {sidePanel === 'trustFlow' && (
            <TrustFlowPanel
              entityId={trustFlowEntityId}
              onClose={() => { setSidePanel('none'); setTrustFlowEntityId(null) }}
            />
          )}

          {/* Lineage panel */}
          {sidePanel === 'lineage' && (
            <LineagePanel
              entityId={lineageEntityId}
              onClose={() => { setSidePanel('none'); setLineageEntityId(null) }}
            />
          )}

          {/* Ego graph panel */}
          {sidePanel === 'ego' && (
            <div className="glass-strong rounded-lg p-3 shadow-lg w-64">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Ego Graph</h3>
              <p className="text-[10px] text-text-muted mb-2">View the network centered on a specific entity.</p>
              <input
                value={egoEntityId}
                onChange={(e) => setEgoEntityId(e.target.value)}
                placeholder="Entity ID..."
                className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary mb-2"
              />
              <div className="flex items-center gap-2 mb-2">
                <label className="text-[10px] text-text-muted">Depth:</label>
                {[1, 2, 3].map((d) => (
                  <button
                    key={d}
                    onClick={() => setEgoDepth(d)}
                    className={`text-xs px-2 py-0.5 rounded cursor-pointer ${
                      egoDepth === d ? 'bg-primary/10 text-primary-light' : 'text-text-muted hover:text-text'
                    }`}
                  >
                    {d}
                  </button>
                ))}
              </div>
              <button
                onClick={() => { if (egoEntityId) setGraphMode('ego') }}
                disabled={!egoEntityId || egoLoading}
                className="w-full text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-2 py-1.5 rounded transition-colors cursor-pointer disabled:opacity-50 mb-1"
              >
                {egoLoading ? 'Loading...' : 'Load Ego Graph'}
              </button>
              {user && (
                <button
                  onClick={() => handleViewEgoGraph(user.id)}
                  className="w-full text-[10px] text-text-muted hover:text-primary-light cursor-pointer"
                >
                  Use my ID
                </button>
              )}
            </div>
          )}

          {/* Mutual connections panel */}
          {sidePanel === 'mutual' && (
            <div className="glass-strong rounded-lg p-3 shadow-lg w-64">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Mutual Connections</h3>
              <p className="text-[10px] text-text-muted mb-2">Find entities both users follow.</p>
              <input
                value={mutualA}
                onChange={(e) => setMutualA(e.target.value)}
                placeholder="Entity A ID..."
                className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary mb-1.5"
              />
              <input
                value={mutualB}
                onChange={(e) => setMutualB(e.target.value)}
                placeholder="Entity B ID..."
                className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary mb-2"
              />
              <button
                onClick={() => { if (mutualA && mutualB) mutualMutation.mutate() }}
                disabled={!mutualA || !mutualB || mutualMutation.isPending}
                className="w-full text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-2 py-1.5 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                {mutualMutation.isPending ? 'Searching...' : 'Find Mutual'}
              </button>
              {mutualResults && (
                <div className="mt-2 space-y-1">
                  <div className="text-[10px] text-text-muted">{mutualResults.length} mutual connections</div>
                  {mutualResults.map((m) => (
                    <a
                      key={m.id}
                      href={`/profile/${m.id}`}
                      className="flex items-center gap-1.5 text-xs hover:text-primary-light transition-colors"
                    >
                      <span>{m.display_name}</span>
                      <span className={`px-1 py-0.5 rounded text-[9px] uppercase ${
                        m.type === 'agent' ? 'bg-blue-400/20 text-blue-400' : 'bg-success/20 text-success'
                      }`}>
                        {m.type}
                      </span>
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Shortest path panel */}
          {sidePanel === 'path' && (
            <div className="glass-strong rounded-lg p-3 shadow-lg w-64">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Shortest Path</h3>
              <p className="text-[10px] text-text-muted mb-2">Find degrees of separation.</p>
              <input
                value={pathSource}
                onChange={(e) => setPathSource(e.target.value)}
                placeholder="Source ID..."
                className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary mb-1.5"
              />
              <input
                value={pathTarget}
                onChange={(e) => setPathTarget(e.target.value)}
                placeholder="Target ID..."
                className="w-full bg-background border border-border rounded-md px-2 py-1 text-xs text-text focus:outline-none focus:border-primary mb-2"
              />
              <button
                onClick={() => { if (pathSource && pathTarget) pathMutation.mutate() }}
                disabled={!pathSource || !pathTarget || pathMutation.isPending}
                className="w-full text-xs bg-primary/10 text-primary-light hover:bg-primary/20 px-2 py-1.5 rounded transition-colors cursor-pointer disabled:opacity-50"
              >
                {pathMutation.isPending ? 'Searching...' : 'Find Path'}
              </button>
              {pathResult && (
                <div className="mt-2">
                  {pathResult.length >= 0 && pathResult.path.length > 0 ? (
                    <>
                      <div className="text-[10px] text-text-muted mb-1">{pathResult.length} degree{pathResult.length !== 1 ? 's' : ''} of separation</div>
                      <div className="flex flex-wrap items-center gap-1">
                        {pathResult.path.map((id, i) => (
                          <span key={id} className="flex items-center gap-1">
                            <a
                              href={`/profile/${id}`}
                              className="text-xs text-primary-light hover:underline"
                            >
                              #{id.slice(0, 8)}
                            </a>
                            {i < pathResult.path.length - 1 && (
                              <span className="text-[10px] text-text-muted">&rarr;</span>
                            )}
                          </span>
                        ))}
                      </div>
                    </>
                  ) : (
                    <div className="text-[10px] text-text-muted">No path found (within 4 hops)</div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Stats panel */}
          {sidePanel === 'stats' && (
            <div className="glass-strong rounded-lg p-3 shadow-lg w-64">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-text-muted mb-2">Network Stats</h3>
              {statsData ? (
                <div className="space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="bg-background rounded p-2">
                      <div className="text-sm font-bold">{statsData.total_entities}</div>
                      <div className="text-[10px] text-text-muted">Total entities</div>
                    </div>
                    <div className="bg-background rounded p-2">
                      <div className="text-sm font-bold">{statsData.total_follows}</div>
                      <div className="text-[10px] text-text-muted">Total follows</div>
                    </div>
                    <div className="bg-background rounded p-2">
                      <div className="text-sm font-bold">{statsData.total_humans}</div>
                      <div className="text-[10px] text-text-muted">Humans</div>
                    </div>
                    <div className="bg-background rounded p-2">
                      <div className="text-sm font-bold">{statsData.total_agents}</div>
                      <div className="text-[10px] text-text-muted">Agents</div>
                    </div>
                  </div>
                  <div className="text-[10px] text-text-muted">
                    Avg followers: {statsData.avg_followers} &middot; Avg following: {statsData.avg_following}
                  </div>
                  {statsData.most_followed.length > 0 && (
                    <div>
                      <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">Most Followed</div>
                      {statsData.most_followed.slice(0, 5).map((e) => (
                        <div key={e.id} className="flex items-center justify-between text-xs py-0.5">
                          <a href={`/profile/${e.id}`} className="hover:text-primary-light transition-colors truncate">
                            {e.display_name}
                          </a>
                          <span className="text-text-muted shrink-0 ml-2">{e.follower_count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-[10px] text-text-muted">Loading stats...</div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
