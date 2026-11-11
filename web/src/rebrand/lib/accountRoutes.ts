import { rp } from '../basePath'

/**
 * The four signed-in tabs. They share one persistent layout (AccountLayout in
 * AccountBits), so this list is tiny and dependency-free: RebrandLayout reads it to
 * keep one route key for the whole account area, and it must not pull the account
 * code into the main bundle.
 */
export type AccountTab = 'tools' | 'watch' | 'notif' | 'settings'

export const ACCOUNT_TABS: [AccountTab, string, string][] = [
  ['tools', 'My Tools', '/rebrand/tools'],
  ['watch', 'Watches & alerts', '/rebrand/account'],
  ['notif', 'Notifications', '/rebrand/notifications'],
  ['settings', 'Settings', '/rebrand/settings'],
]

/** The tab a pathname belongs to, or null outside the account area. */
export function accountTabFor(pathname: string): AccountTab | null {
  const p = pathname.replace(/\/+$/, '') || '/'
  const hit = ACCOUNT_TABS.find(([, , to]) => rp(to) === p)
  return hit ? hit[0] : null
}
