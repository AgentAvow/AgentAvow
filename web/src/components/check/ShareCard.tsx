/**
 * ShareCard — social sharing and engagement CTAs for the /check page.
 * Consumer CTAs: notify, rate, report.
 * Developer CTAs: claim, badge, CI.
 */

import { useState } from 'react'
import { Link } from 'react-router-dom'
import type { LetterGrade } from '../trust/gradeSystem'

interface ShareCardProps {
  owner: string
  repo: string
  grade: LetterGrade
  score: number
}

function CopyLinkButton({ url }: { url: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(url).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <button
      onClick={handleCopy}
      className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-surface border border-border text-xs text-text-muted hover:text-text hover:border-primary/30 transition-colors cursor-pointer"
    >
      <svg className="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
        <path d="M12.232 4.232a2.5 2.5 0 013.536 3.536l-1.225 1.224a.75.75 0 001.061 1.06l1.224-1.224a4 4 0 00-5.656-5.656l-3 3a4 4 0 00.225 5.865.75.75 0 00.977-1.138 2.5 2.5 0 01-.142-3.667l3-3z" />
        <path d="M11.603 7.963a.75.75 0 00-.977 1.138 2.5 2.5 0 01.142 3.667l-3 3a2.5 2.5 0 01-3.536-3.536l1.225-1.224a.75.75 0 00-1.061-1.06l-1.224 1.224a4 4 0 105.656 5.656l3-3a4 4 0 00-.225-5.865z" />
      </svg>
      {copied ? 'Copied!' : 'Copy link'}
    </button>
  )
}

export default function ShareCard({ owner, repo, grade, score }: ShareCardProps) {
  const checkUrl = `https://agentavow.com/check/${owner}/${repo}`
  const shareText = `Is ${owner}/${repo} safe? Trust Score: ${grade} (${score}/100) — checked on AgentAvow`
  const twitterUrl = `https://twitter.com/intent/tweet?text=${encodeURIComponent(shareText)}&url=${encodeURIComponent(checkUrl)}`
  const blueskyUrl = `https://bsky.app/intent/compose?text=${encodeURIComponent(`${shareText} ${checkUrl}`)}`

  return (
    <div className="space-y-4">
      {/* Share */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
          Share This Report
        </h3>
        <div className="flex flex-wrap gap-2">
          <a
            href={twitterUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-surface border border-border text-xs text-text-muted hover:text-text hover:border-primary/30 transition-colors"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
            </svg>
            Share on X
          </a>
          <a
            href={blueskyUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-surface border border-border text-xs text-text-muted hover:text-text hover:border-primary/30 transition-colors"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 10.8c-1.087-2.114-4.046-6.053-6.798-7.995C2.566.944 1.561 1.266.902 1.565.139 1.908 0 3.08 0 3.768c0 .69.378 5.65.624 6.479.785 2.627 3.6 3.476 6.18 3.232-4.165.712-8.232 2.625-4.412 8.51C5.777 26.373 11.268 21.248 12 17.04c.732 4.208 6.13 9.282 9.608 4.95 3.82-5.886-.247-7.799-4.412-8.511 2.58.244 5.395-.605 6.18-3.232.246-.828.624-5.79.624-6.479 0-.688-.139-1.86-.902-2.203-.659-.299-1.664-.621-4.3 1.24C16.046 4.748 13.087 8.687 12 10.8z" />
            </svg>
            Share on Bluesky
          </a>
          <CopyLinkButton url={checkUrl} />
        </div>
      </div>

      {/* Consumer CTAs */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
          Stay Informed
        </h3>
        <div className="space-y-2">
          <Link
            to={`/register?ref=check&agent=${owner}/${repo}`}
            className="flex items-center gap-2 text-sm text-primary-light hover:underline"
          >
            <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 2a6 6 0 00-6 6c0 1.887-.454 3.665-1.257 5.234a.75.75 0 00.515 1.076 32.91 32.91 0 003.256.508 3.5 3.5 0 006.972 0 32.903 32.903 0 003.256-.508.75.75 0 00.515-1.076A11.448 11.448 0 0116 8a6 6 0 00-6-6zM8.05 14.943a33.54 33.54 0 003.9 0 2 2 0 01-3.9 0z" clipRule="evenodd" />
            </svg>
            Get notified if this score changes
          </Link>
          <Link
            to={`/register?ref=check&agent=${owner}/${repo}&action=rate`}
            className="flex items-center gap-2 text-sm text-primary-light hover:underline"
          >
            <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10.868 2.884c-.321-.772-1.415-.772-1.736 0l-1.83 4.401-4.753.381c-.833.067-1.171 1.107-.536 1.651l3.62 3.102-1.106 4.637c-.194.813.691 1.456 1.405 1.02L10 15.591l4.069 2.485c.713.436 1.598-.207 1.404-1.02l-1.106-4.637 3.62-3.102c.635-.544.297-1.584-.536-1.65l-4.752-.382-1.831-4.401z" clipRule="evenodd" />
            </svg>
            Rate this agent
          </Link>
        </div>
      </div>

      {/* Developer CTAs */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
          For Developers
        </h3>
        <div className="space-y-2">
          <Link
            to={`/register?ref=claim&agent=${owner}/${repo}`}
            className="flex items-center gap-2 text-sm text-primary-light hover:underline"
          >
            <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.403 12.652a3 3 0 000-5.304 3 3 0 00-3.75-3.751 3 3 0 00-5.305 0 3 3 0 00-3.751 3.75 3 3 0 000 5.305 3 3 0 003.75 3.751 3 3 0 005.305 0 3 3 0 003.751-3.75zm-2.546-4.46a.75.75 0 00-1.214-.883l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clipRule="evenodd" />
            </svg>
            Claim this agent
          </Link>
          <a
            href={`https://github.com/${owner}/${repo}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-sm text-text-muted hover:text-text transition-colors"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
            </svg>
            View on GitHub
          </a>
        </div>
      </div>
    </div>
  )
}
