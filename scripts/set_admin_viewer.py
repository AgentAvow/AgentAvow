#!/usr/bin/env python3
"""Grant or revoke read-only admin viewer access for one account, or list who has access.

A viewer can open the admin Metrics pages and nothing else (no posting, replying,
toggles, settings or user management), and sees emails / IPs masked. The script only
ever changes ``entities.is_admin_viewer`` on the one account named; it never touches
``is_admin``. Needs migration t31.

Usage:
    python scripts/set_admin_viewer.py EMAIL --grant
    python scripts/set_admin_viewer.py EMAIL --revoke
    python scripts/set_admin_viewer.py --list

DATABASE_URL must be set explicitly (no default, so it cannot hit a local database by
accident). On prod it comes from .env.production; run it in a one-off container of the
backend image with the script mounted (the image does not ship scripts/):

    cd ~/agentgraph && set -a && source .env.production && set +a && \\
    docker-compose -f docker-compose.prod.yml run --rm --no-deps -T \\
      -v "$PWD/scripts/set_admin_viewer.py:/app/set_admin_viewer.py:ro" \\
      --entrypoint python backend -u /app/set_admin_viewer.py EMAIL --grant

``--entrypoint python`` matters: the image's entrypoint runs migrations and starts the
app. Exit codes: 0 done (or nothing to change), 1 no such account / ambiguous, 2 usage.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

# Local runs: make ``src`` importable from the repo root. In the container the script
# sits in /app next to src/, which is already on sys.path.
_ROOT = Path(__file__).resolve().parent.parent
if (_ROOT / "src").is_dir() and str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _db_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        sys.exit("DATABASE_URL is not set; refusing to guess a database.")
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def _state(e) -> str:
    return f"is_admin_viewer={bool(e.is_admin_viewer)} (is_admin={bool(e.is_admin)}, unchanged)"


def _print_list(rows: list[dict]) -> None:
    if not rows:
        print("No accounts have admin or viewer access.")
        return
    print(f"{len(rows)} account(s) with admin access:")
    for r in rows:
        active = "" if r["is_active"] else "  [inactive]"
        print(f"  {r['role']:<6}  {r['email'] or '(no email)':<40}  {r['display_name']:<30}"
              f"  created {(r['created_at'] or '')[:10]}{active}")


async def run(email: str | None, grant: bool | None, list_only: bool) -> int:
    from sqlalchemy import func, select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from src.admin_access import list_admin_access
    from src.models import Entity

    engine = create_async_engine(_db_url())
    try:
        async with async_sessionmaker(engine, expire_on_commit=False)() as db:
            if list_only:
                _print_list(await list_admin_access(db))
                return 0

            matches = (await db.execute(
                select(Entity).where(func.lower(Entity.email) == email.strip().lower())
            )).scalars().all()
            if not matches:
                print(f"No account with email {email!r}. Nothing changed.", file=sys.stderr)
                return 1
            if len(matches) > 1:
                print(f"{len(matches)} accounts match {email!r}; refusing to guess. "
                      "Nothing changed.", file=sys.stderr)
                return 1
            e = matches[0]
            print(f"Account: {e.display_name} <{e.email}> id={e.id}")
            print(f"Before:  {_state(e)}")
            if bool(e.is_admin_viewer) == grant:
                print("After:   no change needed")
                return 0
            e.is_admin_viewer = grant
            from src.audit import log_action

            await log_action(
                db, "admin.viewer_granted" if grant else "admin.viewer_revoked",
                resource_type="entity", resource_id=e.id,
                details={"via": "scripts/set_admin_viewer.py"},
            )
            await db.commit()
            await db.refresh(e)
            print(f"After:   {_state(e)}")
            return 0
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("email", nargs="?", help="the account's email address")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--grant", action="store_true", help="make the account a viewer")
    g.add_argument("--revoke", action="store_true", help="remove viewer access")
    g.add_argument("--list", action="store_true", help="list every admin and viewer")
    a = p.parse_args(argv)
    if not a.list and not a.email:
        p.error("EMAIL is required with --grant / --revoke")
    if a.list and a.email:
        p.error("--list takes no EMAIL")
    return asyncio.run(run(a.email, a.grant if not a.list else None, a.list))


if __name__ == "__main__":
    sys.exit(main())
