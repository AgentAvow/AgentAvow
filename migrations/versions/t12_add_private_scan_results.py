"""Add private_scan_results — stored results of scheduled PRIVATE-repo scans run
via a connected GitHub App installation. Owner-scoped, never public. Purely
additive — one new table, no existing data touched.

Revision ID: t12
Revises: t11
Create Date: 2026-08-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t12"
down_revision = "t11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "private_scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("repo", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(512), nullable=False),
        sa.Column("trust_score", sa.Integer(), nullable=True),
        sa.Column("grade", sa.String(4), nullable=True),
        sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("prev_score", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(16), server_default="app", nullable=False),
        sa.Column(
            "scanned_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "owner", "repo", name="uq_private_scan_target"),
    )
    op.create_index(
        "ix_private_scan_results_entity_id", "private_scan_results", ["entity_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_private_scan_results_entity_id", table_name="private_scan_results")
    op.drop_table("private_scan_results")
