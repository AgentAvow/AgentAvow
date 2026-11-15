"""Add scan_history.tool_digests: the per-tool digests behind each history point.

The public "Definition changes" list could say only that a tool's signed definition
changed. Keeping the per-tool digests on each point lets the drift feed say which
tools were added, removed or changed between two points. Rows written before this
have NULL, and the feed shows no per-tool detail for them.

Additive: one nullable column, nothing existing is touched.

Revision ID: t33
Revises: t32
Create Date: 2026-11-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "t33"
down_revision = "t32"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_history", sa.Column("tool_digests", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("scan_history", "tool_digests")
