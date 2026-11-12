/** Admin vs read-only admin viewer, for the rebrand admin pages.
 *
 * A viewer (`is_admin_viewer` without `is_admin`) sees the Metrics tab and nothing
 * else: no Marketing / Posts / Radar tabs, no Replies or Posts pages, no button that
 * changes state. This is convenience only: the server answers 403 to a viewer on every
 * admin endpoint except the read-only metrics GETs, and masks personal data in those
 * (src/api/deps.py require_admin_or_viewer, src/api/redaction.py). */
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'

import { useAuth } from '../../hooks/useAuth'
import api from '../../lib/api'
import { rp } from '../basePath'

export function useAdminAccess() {
  const { user, isLoading } = useAuth()
  const isAdmin = !!user?.is_admin
  const isViewer = !isAdmin && !!user?.is_admin_viewer
  return { user, isLoading, isAdmin, isViewer, canView: isAdmin || isViewer }
}

export function ViewOnlyNotice() {
  return (
    <div className="max-w-[560px] mx-auto px-6 py-24 text-center">
      <h1 className="text-2xl font-extrabold tracking-tight">View-only access</h1>
      <p className="mt-3 text-text-muted text-[14px]">
        Your account can read the admin metrics, not this page.{' '}
        <Link to={rp('/rebrand/admin-dashboard')} className="text-primary-light hover:text-primary font-semibold">Go to the metrics →</Link>
      </p>
    </div>
  )
}

interface AccessRow { id: string; display_name: string; email: string | null; role: 'Admin' | 'Viewer'; is_active: boolean; created_at: string | null }

/** Who has admin or viewer access. Full admins only (the endpoint 403s viewers). */
export function AdminAccessPanel() {
  const { data, isLoading, isError } = useQuery<{ accounts: AccessRow[] }>({
    queryKey: ['admin-access-list'],
    queryFn: async () => (await api.get('/admin/access')).data,
  })
  const rows = data?.accounts || []
  return (
    <section className="mt-10">
      <h2 className="text-lg font-bold">Who has admin access</h2>
      <p className="mt-1 text-text-muted text-[13px] max-w-[72ch]">
        Admins can change everything. Viewers can read the Metrics tab only, with emails and IPs masked. Grant or revoke a viewer with scripts/set_admin_viewer.py.
      </p>
      <div className="glass rounded-2xl p-5 mt-4 overflow-x-auto">
        {rows.length ? (
          <table className="w-full text-[12.5px]">
            <thead><tr className="text-left font-mono text-[11px] uppercase tracking-wide text-text-muted/70">
              <th className="py-1.5 pr-3">Name</th><th className="py-1.5 pr-3">Email</th><th className="py-1.5 pr-3">Role</th><th className="py-1.5 pr-3">Created</th>
            </tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className={`border-t border-border/40${r.is_active ? '' : ' opacity-50'}`}>
                  <td className="py-1.5 pr-3">{r.display_name}{r.is_active ? '' : ' (inactive)'}</td>
                  <td className="py-1.5 pr-3 font-mono">{r.email || '—'}</td>
                  <td className="py-1.5 pr-3"><span className={`text-[11px] px-1.5 py-0.5 rounded ${r.role === 'Admin' ? 'bg-primary/15 text-primary-light' : 'bg-surface text-text-muted'}`}>{r.role}</span></td>
                  <td className="py-1.5 pr-3 tabular-nums text-text-muted">{r.created_at ? r.created_at.slice(0, 10) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="text-[12.5px] text-text-muted/70">{isLoading ? 'Loading…' : isError ? 'Could not load the list.' : 'No accounts found.'}</p>}
      </div>
    </section>
  )
}
