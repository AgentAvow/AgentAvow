"""Add community_scans — persist on-demand scans so the catalog grows.

One row per owner/repo (latest scan wins), upserted on every fresh scan.
Purely additive — creates one new table, touches no existing data.

Revision ID: t08
Revises: t07
Create Date: 2026-08-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t08"
down_revision = "t07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "community_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("repo", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(512), nullable=False),
        sa.Column("trust_score", sa.Integer(), nullable=True),
        sa.Column("critical", sa.Integer(), nullable=True),
        sa.Column("high", sa.Integer(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=True),
        sa.Column("primary_language", sa.String(120), nullable=True),
        sa.Column("scan_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "first_scanned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_scanned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner", "repo", name="uq_community_scan_target"),
    )
    op.create_index("ix_community_scans_full_name", "community_scans", ["full_name"])


def downgrade() -> None:
    op.drop_index("ix_community_scans_full_name", table_name="community_scans")
    op.drop_table("community_scans")
