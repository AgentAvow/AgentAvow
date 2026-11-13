"""Add entities.is_admin_viewer: a read-only admin role.

A viewer can open the admin Metrics pages (read-only GET endpoints that call
``require_admin_or_viewer``) and nothing else: every admin write, Post Studio, Replies,
campaign controls and user management keep ``require_admin``, which checks
``is_admin`` only. Personal data (emails, IPs) is masked server-side in every response a
viewer can reach. ``is_admin`` stays the full-power flag and is not touched here.

Additive and safe on a live table: NOT NULL with a ``false`` server default, so every
existing row reads as "not a viewer".

Revision ID: t31
Revises: t30
Create Date: 2026-11-12
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t31"
down_revision = "t30"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entities",
        sa.Column(
            "is_admin_viewer", sa.Boolean(), nullable=False, server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("entities", "is_admin_viewer")
