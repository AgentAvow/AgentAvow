import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { DOCS_HREF, DOCS_LABEL } from '../lib/unsupportedHost'

/** Render a notice, turning the docs pointer in the unsupported-host message into a link. */
export function NoticeText({ text }: { text: string }) {
  const at = text.indexOf(DOCS_LABEL)
  if (at < 0) return <>{text}</>
  return (
    <>
      {text.slice(0, at)}
      <Link to={rp(DOCS_HREF)} className="underline hover:text-text">{DOCS_LABEL}</Link>
      {text.slice(at + DOCS_LABEL.length)}
    </>
  )
}
