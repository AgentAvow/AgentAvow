"""Add community_scans.grade — the letter grade WITH the A+ certified gate applied
(roadmap §7), stored so Browse shows the accurate grade instead of deriving A+ from
score alone. Purely additive, nullable (old rows get capped-from-score at read time).

Revision ID: t15
Revises: t14
Create Date: 2026-08-10
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t15"
down_revision = "t14"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "community_scans",
        sa.Column("grade", sa.String(length=4), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("community_scans", "grade")
