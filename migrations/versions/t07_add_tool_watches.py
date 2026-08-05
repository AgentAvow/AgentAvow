"""Add tool_watches table for tool-watch / grade-change alerts.

One row per (user, owner/repo) the user is watching. The scheduler re-scans
these on a schedule and notifies on a grade drop or a signed-definition change.
Purely additive — creates one new table, touches no existing data.

Revision ID: t07
Revises: t06
Create Date: 2026-08-04
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t07"
down_revision = "t06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tool_watches",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("watcher_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("repo", sa.String(255), nullable=False),
        sa.Column("last_score", sa.Integer(), nullable=True),
        sa.Column("last_manifest_digest", sa.String(128), nullable=True),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["watcher_id"], ["entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("watcher_id", "owner", "repo", name="uq_tool_watch_target"),
    )
    op.create_index("ix_tool_watches_watcher_id", "tool_watches", ["watcher_id"])


def downgrade() -> None:
    op.drop_index("ix_tool_watches_watcher_id", table_name="tool_watches")
    op.drop_table("tool_watches")
