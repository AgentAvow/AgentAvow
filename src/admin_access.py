"""Who holds admin access: every account with ``is_admin`` or ``is_admin_viewer``.

Shared by ``GET /admin/access`` (full admins only) and ``scripts/set_admin_viewer.py
--list`` so both show the same list.
"""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models import Entity


def access_role(entity: Entity) -> str:
    """``Admin`` for full power (wins if both flags are set), else ``Viewer``."""
    return "Admin" if entity.is_admin else "Viewer"


async def list_admin_access(db: AsyncSession) -> list[dict]:
    """Accounts with admin or viewer access, admins first, then by creation date.

    The account table records no last-login time, so ``created_at`` is the only date.
    """
    rows = (await db.execute(
        select(Entity)
        .where(or_(Entity.is_admin.is_(True), Entity.is_admin_viewer.is_(True)))
        .order_by(Entity.is_admin.desc(), Entity.created_at)
    )).scalars().all()
    return [
        {
            "id": str(e.id),
            "display_name": e.display_name,
            "email": e.email,
            "role": access_role(e),
            "is_active": bool(e.is_active),
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows
    ]
