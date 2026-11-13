/** One definition per term on the admin Metrics tab. Shown as an (i) tooltip next to a
 *  label and in the "What these numbers mean" section. The machine vocabulary is
 *  anchored on ONE word, "machine"; every other machine count is defined against it. */
export interface GlossaryEntry { term: string; def: string }

export const GLOSSARY = {
  machine: {
    term: 'Machine',
    def: 'One computer, known by its internet address (IP). Counted once over the period named next to it, e.g. "unique machines, 7 days". If a computer changes address it counts again; owner test machines are left out where it says so.',
  },
  daily_machines: {
    term: 'Machines per day',
    def: 'Machines seen on one UTC day. A chart of machines per day can\'t be added up across days, so its legend shows the last day and the daily average, never a total.',
  },
  days_of_use: {
    term: 'Days of use',
    def: 'Machines per day added up across the period: a machine seen on 5 days counts 5. It measures how much the product was used, not how many machines used it, so it is never smaller than the unique machines for the same period.',
  },
  protected: {
    term: 'Machines protected',
    def: 'Unique machines where the Claude Code plugin checked a tool on its own (at session start or when a tool was being installed) at least once in the 7 days. Hand-run checks and the npm / Python gates are not in it.',
  },
  active_installs: {
    term: 'Machines protected (active installs)',
    def: 'Plugin installs that sent the once-a-day active signal: the plugin (0.1.41 and later) sends its anonymous install ID, version and app type on the first session start of each UTC day, even when it has nothing new to check. Counted by install ID, not internet address, so a laptop that moves networks counts once. Counting starts the day the first signal arrived; installs that have not updated to 0.1.41 are not in it yet, so it grows as people update. Owner machines are left out. An Anthropic cloud session starts on a fresh machine, so each one can count as its own install.',
  },
  connecting: {
    term: 'Machines connecting',
    def: 'Unique machines that opened the plugin\'s connection from Claude Code. A machine connecting has the plugin installed; it is protected once a check runs.',
  },
  new_installs: {
    term: 'New plugin installs',
    def: 'Machines connecting for the first time in 30 days that the plugin also checked something for on that first day. Each machine is new on one day only, so these add up across days.',
  },
  claude_ai_users: {
    term: 'Claude.ai users',
    def: 'Distinct callers per day of the AgentAvow connector in claude.ai, averaged over the period. claude.ai calls arrive through Anthropic\'s servers, which share a few addresses, so this is a floor: there are at least this many.',
  },
  hand_run: {
    term: 'Hand-run check',
    def: 'A check someone asked for on purpose: a tool call from Claude Code, claude.ai, ChatGPT, Cursor, VS Code or Codex, leaving out the about_agentavow overview and owner machines.',
  },
  visit: {
    term: 'Visit',
    def: 'One browser session on agentavow.com (a visitor\'s tab, until it closes). Bots are left out. A visit on two days counts on each day.',
  },
  landed: {
    term: 'Landed',
    def: 'A visit that opened one of the landing pages (the pages ads and posts link to).',
  },
  copy: {
    term: 'Copied the install command',
    def: 'A visit that clicked "copy" on the /plugin install command. The closest thing to an install the website can see: the install itself happens in Claude Code.',
  },
  install_click: {
    term: 'One-click install click',
    def: 'A click on a one-click install button (Cursor, VS Code, Goose) on a tool\'s page. Not the same as the plugin install command.',
  },
  channel: {
    term: 'Channel',
    def: 'Where a visit came from, from the utm_source tag on the link: reddit, x, google, and so on. Visits with no tag are organic.',
  },
  ad_tag: {
    term: 'Ad (utm_content)',
    def: 'Which ad a visit came from: the utm_content tag on that ad\'s link.',
  },
  cost_per_copy: {
    term: 'Ad cost per copy',
    def: 'Ad spend divided by visits from ads that copied the install command, over the same days. Lower is better.',
  },
  crawler: {
    term: 'Crawlers and monitors',
    def: 'Automated callers (MCP directory crawlers, uptime monitors, scripts). Counted so they can be left out: they are not usage.',
  },
  utc_day: {
    term: 'Day (UTC)',
    def: 'Every day on this page is a UTC day, midnight to midnight UTC (Greenwich time). Today is left out of totals and charts until it is over, unless "Include today so far" is ticked.',
  },
  snapshot: {
    term: 'Snapshot',
    def: 'The nightly job (00:40 UTC) that reads the server log for the day before and keeps one row per day for good. A day without a snapshot shows as a gap, not zero.',
  },
  answer: {
    term: 'Answer',
    def: 'The one-line result every check leads with: Safe to connect, Review before you connect, or Do not connect.',
  },
  certified: {
    term: 'Certified',
    def: 'A separate mark beside the answer for tools that clear the Certified bar. Counted on its own.',
  },
  canary: {
    term: 'Canary',
    def: 'A fake credential planted in the sandbox. A canary leak means a server sent it out over the network. Repeating it in its own reply is flagged but milder: nothing left the sandbox.',
  },
  window: {
    term: 'Time window',
    def: 'The 7, 30 or 90 complete UTC days at the top of the page. Each section says which days its numbers cover; a few can\'t follow the window and say so.',
  },
  change: {
    term: '▲ / ▼ change',
    def: 'Compared with the period of the same length just before (the 7 days before the last 7, and so on). Green is better, whichever way the arrow points.',
  },
} satisfies Record<string, GlossaryEntry>

export type GlossaryKey = keyof typeof GLOSSARY
