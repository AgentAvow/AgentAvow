"""Multi-surface watches — add tool_watches.surface ('github' default) and widen
repo to 512 so an MCP endpoint URL fits. Purely additive; existing rows default to
github and are unchanged.

Revision ID: t16
Revises: t15
Create Date: 2026-08-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t16"
down_revision = "t15"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tool_watches",
        sa.Column("surface", sa.String(length=16), nullable=False, server_default="github"),
    )
    op.alter_column(
        "tool_watches", "repo",
        existing_type=sa.String(length=255), type_=sa.String(length=512),
    )
    # surface becomes part of the uniqueness key — a github repo and an openclaw
    # skill can share owner/repo, so the old 3-col constraint would wrongly collide.
    op.drop_constraint("uq_tool_watch_target", "tool_watches", type_="unique")
    op.create_unique_constraint(
        "uq_tool_watch_target", "tool_watches", ["watcher_id", "surface", "owner", "repo"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_tool_watch_target", "tool_watches", type_="unique")
    op.create_unique_constraint(
        "uq_tool_watch_target", "tool_watches", ["watcher_id", "owner", "repo"],
    )
    op.drop_column("tool_watches", "surface")
    op.alter_column(
        "tool_watches", "repo",
        existing_type=sa.String(length=512), type_=sa.String(length=255),
    )
