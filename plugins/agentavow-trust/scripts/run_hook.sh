#!/bin/sh
# AgentAvow hook launcher. Runs one hook script with the first working Python 3:
# python3, then python, then the Windows launcher (py -3). Each is tried with a
# one-line version check first, because on Windows "python3" is often a Microsoft
# Store stub that exists but does not run. With no working Python, it prints nothing
# and exits 0 (fail-open): the session and the tool call go ahead as if the hook
# were not installed. Arguments after the script path are passed on to it. Sends
# nothing. The only environment settings it reads are for the activity log:
#   - AGENTAVOW_ACTIVITY: unless it is "on" (any case), the activity log script exits
#     here before any Python starts (its --report still runs), so a log that is off
#     costs no process per tool call. This matches _enabled() in agentavow_activity.py;
#     release 2 flips the rule (off only for "off") in both places. One exception:
#     "--session-start" still runs while off if $HOME/.cache/agentavow/activity exists,
#     so logs from when it was on are still deleted after 30 days (it records nothing).
#   - $HOME: "--notes" with no pending note to show starts no Python either.
# Where it exits early it first reads stdin to the end (cat, no Python): the host may
# still be writing a large payload, and exiting unread would give it a broken pipe.
script="$1"
[ -f "$script" ] || exit 0
shift
case "$script" in
  */agentavow_activity.py | agentavow_activity.py)
    if [ "$1" = "--report" ]; then
      :
    elif [ "$1" = "--session-start" ] && [ -d "$HOME/.cache/agentavow/activity" ]; then
      :
    else
      case "$AGENTAVOW_ACTIVITY" in
        [Oo][Nn]) ;;
        *) cat >/dev/null 2>&1; exit 0 ;;
      esac
    fi
    ;;
esac
if [ "$1" = "--notes" ] && [ ! -s "$HOME/.cache/agentavow/activity/pending-notes.json" ]; then
  cat >/dev/null 2>&1
  exit 0
fi
for py in python3 python "py -3"; do
  if $py -c "import sys; sys.exit(sys.version_info[0] != 3)" </dev/null >/dev/null 2>&1; then
    exec $py "$script" "$@"
  fi
done
exit 0
