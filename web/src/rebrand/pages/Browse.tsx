import { useState } from 'react'
import { Link } from 'react-router-dom'

/**
 * The "Yelp" browse catalog (prototype). Reskins the /scans idea: browse tools
 * by grade, expander = "Why this grade" (signed evidence), NOT star reviews.
 * Static fixture data — wire to the live scan-catalog API in a later pass.
 */

const TABS = ['MCP servers', 'npm packages', 'Python packages', 'Agent skills']

type Tool = { name: string; grade: string; cls: string; why: string[] }
const TOOLS: Tool[] = [
  { name: 'acme/filesystem-mcp', grade: 'A', cls: 'text-success bg-success/15', why: ['Scoped file access, no shell exec', 'No secrets or network exfiltration', 'Dependencies clean'] },
  { name: 'openmcp/fetch-server', grade: 'A', cls: 'text-success bg-success/15', why: ['Read-only HTTP, allow-listed hosts', 'No credential handling', 'Signed release provenance'] },
  { name: 'acme/mcp-server', grade: 'B', cls: 'text-warning bg-warning/15', why: ['Hardcoded API token in config', 'Unsafe shell exec in a handler', 'Otherwise clean'] },
  { name: 'labs/sql-tools', grade: 'B', cls: 'text-warning bg-warning/15', why: ['Query builder allows raw string interpolation', 'Broad filesystem read scope', 'Deps up to date'] },
  { name: 'community/web-agent', grade: 'C', cls: 'text-warning bg-warning/15', why: ['Reads environment variables broadly', 'Outbound network to non-declared host', 'One high-severity dep advisory'] },
  { name: 'unknown/agent-bridge', grade: 'D', cls: 'text-danger bg-danger/15', why: ['Reads env + posts to an external host', 'Obfuscated payload in build step', 'Known-vulnerable dependency'] },
]

function ToolCard({ tool }: { tool: Tool }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="glass card-hover rounded-xl p-[18px]">
      <div className="flex items-center justify-between gap-2.5">
        <span className="font-mono text-[13.5px] break-all">{tool.name}</span>
        <span className={`font-extrabold text-[13px] px-2.5 py-0.5 rounded-lg shrink-0 ${tool.cls}`}>{tool.grade}</span>
      </div>
      <button onClick={() => setOpen(!open)} className="mt-3 text-[12.5px] text-primary-light hover:text-primary">
        {open ? 'Hide' : 'Why this grade'} {open ? '▴' : '▾'}
      </button>
      {open && (
        <ul className="mt-2 pl-4 list-disc text-[12.5px] text-text-muted space-y-1">
          {tool.why.map((w) => <li key={w}>{w}</li>)}
        </ul>
      )}
      <div className="mt-3">
        <Link to="/rebrand/check" className="text-[12.5px] font-semibold text-primary-light hover:text-primary">Full report →</Link>
      </div>
    </div>
  )
}

export default function RebrandBrowse() {
  const [tab, setTab] = useState(0)
  return (
    <div className="max-w-[1080px] mx-auto px-6 py-14">
      <div className="max-w-[60ch]">
        <span className="font-mono text-[12px] tracking-[0.16em] uppercase text-primary-light font-semibold">Browse</span>
        <h1 className="mt-3 text-3xl md:text-4xl font-extrabold tracking-tight">The trust catalog</h1>
        <p className="mt-3 text-text-muted">
          Every tool, graded and signed. The "review" of a tool is its scan evidence — recomputable, not a
          star rating. Sorted safest-first.
        </p>
      </div>

      {/* search */}
      <div className="glass mt-7 flex gap-2.5 rounded-xl p-2 pl-4 max-w-[520px]">
        <svg viewBox="0 0 24 24" fill="none" className="w-5 h-5 self-center text-text-muted shrink-0">
          <path d="M11 19a8 8 0 1 1 5.7-2.3L21 21" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
        </svg>
        <input
          placeholder="Search a tool, MCP server, or package…"
          className="flex-1 min-w-0 bg-transparent outline-none font-mono text-[14px] text-text placeholder:text-text-muted"
        />
      </div>

      {/* tabs */}
      <div className="flex flex-wrap gap-2 mt-6 mb-5">
        {TABS.map((t, i) => (
          <button
            key={t}
            onClick={() => setTab(i)}
            className={`text-[13.5px] px-4 py-1.5 rounded-full border transition-colors ${
              tab === i
                ? 'text-white border-transparent bg-gradient-to-r from-primary to-primary-dark'
                : 'text-text-muted border-border bg-surface hover:border-primary-light'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="grid md:grid-cols-3 gap-3.5">
        {TOOLS.map((tool) => <ToolCard key={tool.name} tool={tool} />)}
      </div>

      <div className="mt-8 text-center font-mono text-[12px] text-text-muted/70">
        prototype — this grid will be wired to the live scan catalog (~35k tools)
      </div>
    </div>
  )
}
