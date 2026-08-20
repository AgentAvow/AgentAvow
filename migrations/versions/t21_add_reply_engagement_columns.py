"""Add our_engagement + error_message to reply_opportunities.

Reply failures were recorded as status='posting_error' with the reason discarded
(168 un-triageable failures), and the reply self-learning loop read engagement_count —
the SOURCE post's likes, not ours. our_engagement holds OUR reply's earned engagement
(filled by the metrics refresh); error_message captures the failure reason. Purely additive.

Revision ID: t21
Revises: t20
Create Date: 2026-08-20
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t21"
down_revision = "t20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "reply_opportunities",
        sa.Column("our_engagement", sa.Integer(), nullable=True, server_default="0"),
    )
    op.add_column(
        "reply_opportunities",
        sa.Column("error_message", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("reply_opportunities", "error_message")
    op.drop_column("reply_opportunities", "our_engagement")
