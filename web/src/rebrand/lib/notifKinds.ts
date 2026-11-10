/** The notification kinds the tool-safety site shows (watch alerts and good news).
 * The account can also hold old social-era kinds (follow/reply/vote/…), which it hides.
 * The API's `kind` filter takes the comma-separated form, so lists are fetched by kind
 * server-side instead of filtering a page of mixed rows on the client. */
export const RELEVANT_KIND_LIST = ['watch_alert', 'watch_good_news'] as const
export const RELEVANT_KIND_PARAM = RELEVANT_KIND_LIST.join(',')
