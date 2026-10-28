import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { HOST_DOCS } from '../lib/unsupportedHost'

/** Render a notice, turning the docs pointer in the unsupported-host message into a link. */
export function NoticeText({ text }: { text: string }) {
  for (const [label, href] of Object.values(HOST_DOCS)) {
    const at = text.indexOf(label)
    if (at < 0) continue
    return (
      <>
        {text.slice(0, at)}
        <Link to={rp(href)} className="underline hover:text-text">{label}</Link>
        {text.slice(at + label.length)}
      </>
    )
  }
  return <>{text}</>
}
