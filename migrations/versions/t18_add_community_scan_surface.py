"""Multi-surface catalog — add community_scans.surface ('github' default), widen
repo to 512 (MCP endpoint URLs), and fold surface into the uniqueness key so a
github repo and an openclaw skill sharing owner/repo don't collide. Lets a claimed
npm/PyPI/MCP/skill be published into the browse catalog under its real surface.
Purely additive; existing rows default to github.

Revision ID: t18
Revises: t17
Create Date: 2026-08-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t18"
down_revision = "t17"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "community_scans",
        sa.Column("surface", sa.String(length=16), nullable=False, server_default="github"),
    )
    op.alter_column(
        "community_scans", "repo",
        existing_type=sa.String(length=255), type_=sa.String(length=512),
    )
    op.drop_constraint("uq_community_scan_target", "community_scans", type_="unique")
    op.create_unique_constraint(
        "uq_community_scan_target", "community_scans", ["surface", "owner", "repo"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_community_scan_target", "community_scans", type_="unique")
    op.create_unique_constraint(
        "uq_community_scan_target", "community_scans", ["owner", "repo"],
    )
    op.alter_column(
        "community_scans", "repo",
        existing_type=sa.String(length=512), type_=sa.String(length=255),
    )
    op.drop_column("community_scans", "surface")
