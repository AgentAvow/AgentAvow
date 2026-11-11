import { useQuery } from '@tanstack/react-query'
import api from '../../lib/api'
import { RELEVANT_KIND_PARAM } from './notifKinds'

/** Query key for the unread watch-alert count, shared by the bell and the account tabs. */
export const UNREAD_ALERTS_KEY = ['rebrand-unread-watch']

/** Every query that lists or counts alerts: invalidate them all after a change. */
export const ALERT_QUERY_KEYS = ['rebrand-all-notifs', 'rebrand-notifs', 'rebrand-notif-list', UNREAD_ALERTS_KEY[0]]

/**
 * Unread alerts of the kinds the site lists (watch alerts and good news), so the bell
 * and the Notifications tab count exactly what their lists show. The account-wide
 * unread count also holds old social-era notifications, which the site never shows.
 */
export function useUnreadAlertCount(enabled: boolean): number {
  const { data } = useQuery({
    queryKey: UNREAD_ALERTS_KEY,
    queryFn: async () => {
      const r = await api.get<{ notifications: unknown[] }>('/notifications', { params: { kind: RELEVANT_KIND_PARAM, unread_only: true, limit: 100 } })
      return r.data.notifications.length
    },
    enabled,
    refetchInterval: 60_000,
  })
  return data ?? 0
}
