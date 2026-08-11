"""Persist adoption on community_scans so the browse catalog can filter/sort by
"widely relied upon". Populated by the catalog re-scan loop (not every live capture).
Purely additive, nullable.

Revision ID: t19
Revises: t18
Create Date: 2026-08-11
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t19"
down_revision = "t18"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("community_scans", sa.Column("adoption_score", sa.Integer(), nullable=True))
    op.add_column("community_scans", sa.Column("adoption_count", sa.BigInteger(), nullable=True))
    op.add_column(
        "community_scans", sa.Column("adoption_unit", sa.String(length=24), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("community_scans", "adoption_unit")
    op.drop_column("community_scans", "adoption_count")
    op.drop_column("community_scans", "adoption_score")
