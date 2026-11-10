import { Helmet } from 'react-helmet-async'
import { Link } from 'react-router-dom'
import { rp } from '../basePath'
import { Reveal } from '../components/motion'

/**
 * B14: a real 404 for the cutover site. Previously the catch-all route rendered
 * the homepage for any unknown URL, which is confusing and bad for SEO. This page
 * says plainly that the URL doesn't exist, is marked noindex, and points people
 * back to the two things they most likely wanted: the homepage and a scan.
 */
export default function NotFound() {
  return (
    <>
      <Helmet>
        <title>Page not found · AgentAvow</title>
        <meta name="robots" content="noindex" />
      </Helmet>
      <div className="mx-auto max-w-xl px-6 py-28 text-center">
        <Reveal>
          <div className="font-mono text-6xl font-extrabold tracking-tight text-primary-light">
            404
          </div>
          <h1 className="mt-5 text-2xl font-bold text-text">Page not found</h1>
          <p className="mt-3 leading-relaxed text-text-muted">
            The page you're looking for doesn't exist or may have moved. If you followed a
            link here, it may be out of date.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link
              to={rp('/rebrand')}
              className="rounded-xl bg-gradient-to-r from-primary to-primary-dark px-6 py-3 font-semibold text-white shadow-lg shadow-primary/25"
            >
              Back to home
            </Link>
            <Link
              to={rp('/rebrand/check')}
              className="rounded-xl border border-border px-6 py-3 font-semibold text-text transition-colors hover:border-primary-light hover:text-primary-light"
            >
              Check a tool
            </Link>
          </div>
        </Reveal>
      </div>
    </>
  )
}
