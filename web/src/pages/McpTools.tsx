import { useState, useEffect, type FormEvent } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import api from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { timeAgo } from '../lib/formatters'
import { McpToolSkeleton } from '../components/Skeleton'

interface ToolInputProperty {
  type: string
  description?: string
  default?: unknown
  enum?: string[]
}

interface ToolInputSchema {
  type: string
  properties?: Record<string, ToolInputProperty>
  required?: string[]
}

interface McpTool {
  name: string
  description: string
  inputSchema: ToolInputSchema
}

interface ToolCallResult {
  tool_name: string
  result: unknown
  error: { code: string; message: string } | null
  is_error: boolean
}

export default function McpTools() {
  const { user } = useAuth()
  const [expandedTool, setExpandedTool] = useState<string | null>(null)
  const [toolArgs, setToolArgs] = useState<Record<string, Record<string, string>>>({})
  const [results, setResults] = useState<Record<string, ToolCallResult>>({})
  const [search, setSearch] = useState('')
  const [callHistory, setCallHistory] = useState<Array<{
    tool: string
    args: Record<string, string>
    result: ToolCallResult
    timestamp: string
  }>>([])

  useEffect(() => { document.title = 'MCP Tools - AgentAvow' }, [])

  const [didUri, setDidUri] = useState('')
  const [didResult, setDidResult] = useState<unknown>(null)
  const [didError, setDidError] = useState('')

  const resolveDid = useMutation({
    mutationFn: async (uri: string) => {
      const { data } = await api.get('/did/resolve', { params: { uri } })
      return data
    },
    onSuccess: (data) => {
      setDidResult(data)
      setDidError('')
    },
    onError: (err: unknown) => {
      setDidResult(null)
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setDidError(msg || 'Failed to resolve DID')
    },
  })

  const handleResolve = (e: FormEvent) => {
    e.preventDefault()
    if (didUri.trim()) {
      resolveDid.mutate(didUri.trim())
    }
  }

  const { data, isLoading, isError, refetch } = useQuery<{ tools: McpTool[] }>({
    queryKey: ['mcp-tools'],
    queryFn: async () => {
      const { data } = await api.get('/mcp/tools')
      return data
    },
    staleTime: 5 * 60_000,
  })

  const callTool = useMutation({
    mutationFn: async ({ name, args }: { name: string; args: Record<string, string> }) => {
      // Clean empty string values
      const cleanArgs: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(args)) {
        if (v !== '') {
          // Try to parse numbers and booleans
          if (v === 'true') cleanArgs[k] = true
          else if (v === 'false') cleanArgs[k] = false
          else if (/^\d+$/.test(v)) cleanArgs[k] = parseInt(v, 10)
          else cleanArgs[k] = v
        }
      }
      const { data } = await api.post('/mcp/tools/call', {
        name,
        arguments: cleanArgs,
      })
      return data as ToolCallResult
    },
    onSuccess: (data, variables) => {
      setResults((prev) => ({ ...prev, [variables.name]: data }))
      setCallHistory((prev) => [
        {
          tool: variables.name,
          args: variables.args,
          result: data,
          timestamp: new Date().toISOString(),
        },
        ...prev,
      ].slice(0, 50))
    },
  })

  const handleCall = (toolName: string, e?: FormEvent) => {
    e?.preventDefault()
    callTool.mutate({ name: toolName, args: toolArgs[toolName] || {} })
  }

  const setArg = (toolName: string, key: string, value: string) => {
    setToolArgs((prev) => ({
      ...prev,
      [toolName]: { ...prev[toolName], [key]: value },
    }))
  }

  const tools = data?.tools || []
  const filtered = search
    ? tools.filter(
        (t) =>
          t.name.toLowerCase().includes(search.toLowerCase()) ||
          t.description.toLowerCase().includes(search.toLowerCase())
      )
    : tools

  if (isLoading) {
    return (
      <div className="max-w-3xl mx-auto space-y-3 mt-6">
        {Array.from({ length: 6 }).map((_, i) => (
          <McpToolSkeleton key={i} />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="text-center py-10">
        <p className="text-danger mb-2">Failed to load tools</p>
        <button onClick={() => refetch()} className="text-sm text-primary-light hover:underline cursor-pointer">Retry</button>
      </div>
    )
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-xl font-bold">MCP Tools</h1>
          <p className="text-xs text-text-muted mt-1">
            {tools.length} tools available via the Agent Interaction Protocol
          </p>
        </div>
      </div>

      {/* DID Resolver */}
      <div className="bg-surface border border-border rounded-lg p-4 mb-6">
        <h2 className="text-sm font-semibold mb-2">DID Resolver</h2>
        <p className="text-xs text-text-muted mb-3">
          Resolve a Decentralized Identifier to view its DID document.
        </p>
        <form onSubmit={handleResolve} className="flex gap-2">
          <input
            type="text"
            value={didUri}
            onChange={(e) => setDidUri(e.target.value)}
            placeholder="did:agentgraph:abc123..."
            required
            className="flex-1 bg-background border border-border rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-primary"
          />
          <button
            type="submit"
            disabled={resolveDid.isPending || !didUri.trim()}
            className="bg-primary hover:bg-primary-dark text-white px-4 py-1.5 rounded-md text-sm transition-colors disabled:opacity-50 cursor-pointer shrink-0"
          >
            {resolveDid.isPending ? 'Resolving...' : 'Resolve'}
          </button>
        </form>
        {didError && (
          <div className="mt-3 bg-danger/10 border border-danger/30 rounded-md p-3 text-xs text-danger">
            {didError}
          </div>
        )}
        {didResult !== null && (
          <div className="mt-3 bg-success/10 border border-success/30 rounded-md p-3">
            <pre className="text-xs text-text whitespace-pre-wrap break-words max-h-60 overflow-y-auto">
              {JSON.stringify(didResult, null, 2)}
            </pre>
          </div>
        )}
      </div>

      <input
        type="search"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search tools..."
        aria-label="Search MCP tools"
        className="w-full bg-surface border border-border rounded-md px-3 py-2 text-sm text-text focus:outline-none focus:border-primary mb-4"
      />

      <div className="space-y-2">
        {filtered.map((tool) => {
          const isExpanded = expandedTool === tool.name
          const props = tool.inputSchema.properties || {}
          const required = tool.inputSchema.required || []
          const result = results[tool.name]
          const shortName = tool.name.replace('agentgraph_', '')

          return (
            <div
              key={tool.name}
              className="bg-surface border border-border rounded-lg overflow-hidden"
            >
              <button
                onClick={() => setExpandedTool(isExpanded ? null : tool.name)}
                className="w-full px-4 py-3 flex items-center justify-between text-left cursor-pointer hover:bg-surface-hover transition-colors"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <code className="text-sm font-medium text-primary-light shrink-0">
                    {shortName}
                  </code>
                  <span className="text-xs text-text-muted truncate">
                    {tool.description}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-2">
                  {Object.keys(props).length > 0 && (
                    <span className="text-[10px] text-text-muted bg-surface-hover px-1.5 py-0.5 rounded">
                      {Object.keys(props).length} params
                    </span>
                  )}
                  <span className="text-text-muted text-xs">
                    {isExpanded ? '\u25B2' : '\u25BC'}
                  </span>
                </div>
              </button>

              {isExpanded && (
                <div className="border-t border-border px-4 py-3 space-y-3">
                  <p className="text-sm text-text-muted">{tool.description}</p>

                  {Object.keys(props).length > 0 && (
                    <form onSubmit={(e) => handleCall(tool.name, e)} className="space-y-2">
                      <div className="text-xs font-semibold text-text-muted uppercase tracking-wider">
                        Parameters
                      </div>
                      {Object.entries(props).map(([key, prop]) => (
                        <div key={key}>
                          <label className="flex items-center gap-1.5 text-xs mb-1">
                            <code className="text-text">{key}</code>
                            <span className="text-text-muted">({prop.type})</span>
                            {required.includes(key) && (
                              <span className="text-danger text-[10px]">required</span>
                            )}
                          </label>
                          {prop.description && (
                            <p className="text-[11px] text-text-muted mb-1">{prop.description}</p>
                          )}
                          {prop.enum ? (
                            <select
                              value={toolArgs[tool.name]?.[key] || ''}
                              onChange={(e) => setArg(tool.name, key, e.target.value)}
                              className="w-full bg-background border border-border rounded-md px-2 py-1.5 text-xs text-text focus:outline-none focus:border-primary"
                            >
                              <option value="">Select...</option>
                              {prop.enum.map((v) => (
                                <option key={v} value={v}>{v}</option>
                              ))}
                            </select>
                          ) : (
                            <input
                              type="text"
                              value={toolArgs[tool.name]?.[key] || ''}
                              onChange={(e) => setArg(tool.name, key, e.target.value)}
                              placeholder={prop.default !== undefined ? String(prop.default) : ''}
                              required={required.includes(key)}
                              className="w-full bg-background border border-border rounded-md px-2 py-1.5 text-xs text-text focus:outline-none focus:border-primary"
                            />
                          )}
                        </div>
                      ))}
                      {user && (
                        <button
                          type="submit"
                          disabled={callTool.isPending}
                          className="bg-primary hover:bg-primary-dark text-white px-3 py-1.5 rounded-md text-xs transition-colors disabled:opacity-50 cursor-pointer"
                        >
                          {callTool.isPending ? 'Calling...' : 'Execute'}
                        </button>
                      )}
                    </form>
                  )}

                  {Object.keys(props).length === 0 && user && (
                    <button
                      onClick={() => handleCall(tool.name)}
                      disabled={callTool.isPending}
                      className="bg-primary hover:bg-primary-dark text-white px-3 py-1.5 rounded-md text-xs transition-colors disabled:opacity-50 cursor-pointer"
                    >
                      {callTool.isPending ? 'Calling...' : 'Execute'}
                    </button>
                  )}

                  {!user && (
                    <p className="text-xs text-text-muted italic">
                      Sign in to execute tools
                    </p>
                  )}

                  {result && (
                    <div className={`rounded-md p-3 text-xs ${
                      result.is_error
                        ? 'bg-danger/10 border border-danger/30'
                        : 'bg-success/10 border border-success/30'
                    }`}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`font-semibold ${
                          result.is_error ? 'text-danger' : 'text-success'
                        }`}>
                          {result.is_error ? 'Error' : 'Success'}
                        </span>
                      </div>
                      {result.is_error && result.error ? (
                        <pre className="text-danger/80 whitespace-pre-wrap break-words">
                          {result.error.code}: {result.error.message}
                        </pre>
                      ) : (
                        <pre className="text-text whitespace-pre-wrap break-words max-h-60 overflow-y-auto">
                          {JSON.stringify(result.result, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}

        {filtered.length === 0 && (
          <div className="text-center text-text-muted py-10 text-sm">
            {search ? 'No tools match your search' : 'No tools available'}
          </div>
        )}
      </div>

      {/* Call History */}
      {callHistory.length > 0 && (
        <div className="mt-8">
          <h2 className="text-sm font-semibold text-text-muted uppercase tracking-wider mb-3">
            Recent Calls ({callHistory.length})
          </h2>
          <div className="space-y-2">
            {callHistory.map((entry, i) => (
              <div
                key={i}
                className="bg-surface border border-border rounded-lg px-3 py-2 text-xs"
              >
                <div className="flex items-center justify-between mb-1">
                  <code className="font-medium text-primary-light">
                    {entry.tool.replace('agentgraph_', '')}
                  </code>
                  <div className="flex items-center gap-2">
                    <span className={entry.result.is_error ? 'text-danger' : 'text-success'}>
                      {entry.result.is_error ? 'failed' : 'ok'}
                    </span>
                    <span className="text-text-muted">{timeAgo(entry.timestamp)}</span>
                  </div>
                </div>
                {Object.keys(entry.args).filter((k) => entry.args[k]).length > 0 && (
                  <div className="text-text-muted">
                    args: {JSON.stringify(
                      Object.fromEntries(
                        Object.entries(entry.args).filter(([, v]) => v)
                      )
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
