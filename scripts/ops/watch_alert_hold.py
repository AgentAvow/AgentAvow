"""Set, clear or show the watch score-alert hold (see src/jobs/watch_alert_hold.py).

Run on the host, in the backend's environment (it uses the backend's REDIS_URL):

    python3 scripts/ops/watch_alert_hold.py set --hours 30 --reason "curve re-score"
    python3 scripts/ops/watch_alert_hold.py status
    python3 scripts/ops/watch_alert_hold.py clear

While set, watch re-scans send no score-drop / score-improved alert and absorb the new
score as the baseline. Definition drift and sandbox changes still alert. The hold
expires on its own after --hours (at most 72).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


async def _main(argv: list[str] | None = None) -> int:
    from src.jobs import watch_alert_hold as hold

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set", help="hold score-change alerts")
    s.add_argument("--hours", type=float, default=hold.DEFAULT_HOLD_SECONDS / 3600)
    s.add_argument("--reason", default="planned re-score")
    sub.add_parser("clear", help="release the hold")
    sub.add_parser("status", help="show the hold")
    args = ap.parse_args(argv)

    if args.cmd == "set":
        ttl = await hold.set_hold(int(args.hours * 3600), args.reason)
        print(f"hold set for {ttl}s ({ttl / 3600:.1f}h): {args.reason}")
    elif args.cmd == "clear":
        print("hold cleared" if await hold.clear_hold() else "no hold was set")
    else:
        info = await hold.hold_status()
        print("no hold" if info is None else
              f"hold set at {info.get('set_at')} ({info.get('reason')}), "
              f"{info.get('ttl')}s left")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
