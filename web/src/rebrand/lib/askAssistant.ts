/**
 * "Ask about this in ChatGPT / Claude" on a public report page: a link that opens the
 * assistant with a prompt that asks it to run the AgentAvow connector on this tool.
 *
 * Only the public tool identifier goes into the link. Nothing about the visitor, and
 * nothing from a private scan (the caller passes no target for those). An MCP URL is
 * cut to scheme, host and path, so a key someone pasted into a query string or the
 * userinfo never reaches the assistant.
 *
 * ChatGPT prefills its message box from `q` and waits for the person to press send.
 * Claude gets no `q`: claude.ai shows a warning on a prefilled prompt, which reads like
 * a prompt-injection alert on a security product's page. So the Claude link copies the
 * same prompt to the clipboard and opens a blank chat for the person to paste into.
 */

export type AskTarget =
  | { kind: 'package'; surface: string; name: string; version?: string | null }
  | { kind: 'mcp'; endpoint: string }
  | { kind: 'repo'; owner: string; repo: string }
  | { kind: 'skill'; owner: string; repo: string; skill?: string | null }

const PKG_WORDS: Record<string, string> = {
  npm: 'npm package',
  pypi: 'PyPI package',
  crates: 'crates.io package',
  docker: 'Docker image',
  huggingface: 'Hugging Face model',
}

/** An MCP endpoint as a public identifier: scheme, host, port and path only. */
export function publicEndpoint(endpoint: string): string | null {
  try {
    const u = new URL(endpoint.trim())
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
    const path = u.pathname === '/' ? '' : u.pathname
    return `${u.protocol}//${u.host}${path}`
  } catch {
    return null
  }
}

/** The tool as the prompt names it, e.g. "npm package gadgethumans-mcp 1.0.15". */
export function askTargetText(t: AskTarget): string | null {
  switch (t.kind) {
    case 'package': {
      const name = t.name.trim()
      if (!name) return null
      const what = PKG_WORDS[t.surface.toLowerCase()] ?? `${t.surface} package`
      const v = (t.version || '').trim()
      return `${what} ${name}${v ? ` ${v}` : ''}`
    }
    case 'mcp': {
      const ep = publicEndpoint(t.endpoint)
      return ep ? `MCP server ${ep}` : null
    }
    case 'repo':
      return t.owner && t.repo ? `GitHub repo ${t.owner}/${t.repo}` : null
    case 'skill': {
      if (!t.owner || !t.repo) return null
      const s = (t.skill || '').trim()
      return s ? `the Agent Skill ${s} in GitHub repo ${t.owner}/${t.repo}` : `the Agent Skill in GitHub repo ${t.owner}/${t.repo}`
    }
  }
}

export function askPrompt(targetText: string): string {
  return `Use AgentAvow to check ${targetText} and tell me if it's safe to connect.`
}

export const CLAUDE_NEW_CHAT = 'https://claude.ai/new'

export interface AskLink {
  assistant: 'ChatGPT' | 'Claude'
  label: string
  href: string
  /** set when the prompt goes by clipboard instead of the URL: copy this, then open href */
  copy?: string
}

export function askLinks(t: AskTarget): AskLink[] {
  const text = askTargetText(t)
  if (!text) return []
  const prompt = askPrompt(text)
  return [
    { assistant: 'ChatGPT', label: 'Ask about this in ChatGPT', href: `https://chatgpt.com/?q=${encodeURIComponent(prompt)}` },
    { assistant: 'Claude', label: 'Ask about this in Claude', href: CLAUDE_NEW_CHAT, copy: prompt },
  ]
}
