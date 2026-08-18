"""Append-only scan_history timeline powering the public recompute-on-release drift
feed. One row per material change (score moved or signed definition drifted).
Purely additive.

Revision ID: t20
Revises: t19
Create Date: 2026-08-18
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t20"
down_revision = "t19"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_history",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("surface", sa.String(length=16), nullable=False, server_default="github"),
        sa.Column("owner", sa.String(length=255), nullable=False),
        sa.Column("repo", sa.String(length=512), nullable=False),
        sa.Column("full_name", sa.String(length=512), nullable=False),
        sa.Column("trust_score", sa.Integer(), nullable=True),
        sa.Column("grade", sa.String(length=4), nullable=True),
        sa.Column("certified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("critical", sa.Integer(), nullable=True),
        sa.Column("high", sa.Integer(), nullable=True),
        sa.Column("tool_manifest_digest", sa.String(length=128), nullable=True),
        sa.Column("score_delta", sa.Integer(), nullable=True),
        sa.Column("manifest_drift", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column(
            "scanned_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
    )
    op.create_index("ix_scan_history_full_name", "scan_history", ["full_name"])
    op.create_index("ix_scan_history_scanned_at", "scan_history", ["scanned_at"])
    op.create_index(
        "ix_scan_history_full_name_time", "scan_history", ["full_name", "scanned_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_history_full_name_time", table_name="scan_history")
    op.drop_index("ix_scan_history_scanned_at", table_name="scan_history")
    op.drop_index("ix_scan_history_full_name", table_name="scan_history")
    op.drop_table("scan_history")
