"""Add analytics_first_touch.

One row per analytics session: the first campaign tags seen for it. The per-campaign view
in the admin attribution tab joins events to this row, so a return visit (which carries no
UTM tags) still counts toward the campaign that first brought the session in. Purely
additive.

Revision ID: t26
Revises: t25
Create Date: 2026-11-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t26"
down_revision = "t25"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analytics_first_touch",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("utm_source", sa.String(200), nullable=True),
        sa.Column("utm_medium", sa.String(200), nullable=True),
        sa.Column("utm_campaign", sa.String(200), nullable=True),
        sa.Column("utm_content", sa.String(200), nullable=True),
        sa.Column("utm_term", sa.String(200), nullable=True),
        sa.Column("landing_page", sa.String(200), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("analytics_first_touch")
