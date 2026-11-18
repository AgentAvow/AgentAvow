import { type ReactNode } from 'react'

/**
 * URL regex: matches http(s) URLs with common path/query/fragment characters.
 * Deliberately strict to avoid false positives on partial strings.
 */
const URL_REGEX = /https?:\/\/[^\s<>"{}|\\^`[\]]+[^\s<>"{}|\\^`[\].,;:!?)]/g

/**
 * Renders text with auto-linked URLs.
 * - URLs become clickable <a> tags with safety attributes
 * - rel="nofollow noopener noreferrer" prevents tab-nabbing and SEO spam
 * - target="_blank" opens in new tab
 * - Shows the domain visually so users know where they're going
 * - All non-URL text remains plain text (no XSS risk)
 */
export default function LinkedContent({ text, className }: { text: string; className?: string }) {
  const parts: ReactNode[] = []
  let lastIndex = 0
  let match: RegExpExecArray | null

  // Fresh copy per render: a /g regex carries lastIndex state, so don't share it
  const urlRegex = new RegExp(URL_REGEX)

  while ((match = urlRegex.exec(text)) !== null) {
    // Add text before this URL
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index))
    }

    const url = match[0]
    parts.push(
      <a
        key={match.index}
        href={url}
        target="_blank"
        rel="nofollow noopener noreferrer"
        className="text-primary-light hover:underline break-all"
      >
        {url}
      </a>
    )

    lastIndex = match.index + url.length
  }

  // Add remaining text
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex))
  }

  // No URLs found — return plain text
  if (parts.length === 0) {
    return <p className={className}>{text}</p>
  }

  return <p className={className}>{parts}</p>
}
