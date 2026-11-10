"""Add last_decision and last_certified to tool_watches.

The watch re-scan loop now alerts when a watched tool's answer gets worse (safe ->
review -> do_not_connect, from src/scanner/verdict.py decide()) or its Certified mark
comes off, and sends a good-news note when either improves. It needs the answer and
the mark it saw last time. Both columns are nullable and purely additive: existing
watches set the baseline silently on their next re-scan and alert only from the
change after that.

Revision ID: t27
Revises: t26
Create Date: 2026-11-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t27"
down_revision = "t26"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tool_watches", sa.Column("last_decision", sa.String(32), nullable=True),
    )
    op.add_column(
        "tool_watches", sa.Column("last_certified", sa.Boolean(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("tool_watches", "last_certified")
    op.drop_column("tool_watches", "last_decision")
