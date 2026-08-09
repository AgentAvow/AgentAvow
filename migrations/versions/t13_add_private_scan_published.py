"""Add private_scan_results.published — owner opt-in to publish a private repo's
grade to the public catalog/search. Purely additive column, defaults false.

Revision ID: t13
Revises: t12
Create Date: 2026-08-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t13"
down_revision = "t12"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "private_scan_results",
        sa.Column("published", sa.Boolean(), server_default="false", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("private_scan_results", "published")
