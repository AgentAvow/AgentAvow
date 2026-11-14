"""Add dnc_reviews: a person's read of a tool's Do not connect answer.

Owner rule 2026-11-11: no Do not connect result is put in front of the public as a
highlight until a person has read its finding. The Trust Index card "Do not connect
this week" lists only rows confirmed here (and only while the tool still reads Do not
connect with the same reason). One row per result page; written by a full admin only.

Additive: a new table, nothing existing is touched.

Revision ID: t32
Revises: t31
Create Date: 2026-11-13
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "t32"
down_revision = "t31"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dnc_reviews",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("page_key", sa.String(1024), nullable=False, unique=True),
        sa.Column("page_path", sa.String(1024), nullable=False),
        sa.Column("surface", sa.String(16), nullable=False),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("decision_at_review", sa.String(16), nullable=False),
        sa.Column("reason_at_review", sa.Text(), nullable=True),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("reviewed_by", UUID(as_uuid=True),
                  sa.ForeignKey("entities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True),
                  server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("verdict IN ('confirmed', 'not_confirmed')",
                           name="ck_dnc_reviews_verdict"),
    )
    op.create_index("ix_dnc_reviews_reviewed_at", "dnc_reviews", ["reviewed_at"])


def downgrade() -> None:
    op.drop_index("ix_dnc_reviews_reviewed_at", table_name="dnc_reviews")
    op.drop_table("dnc_reviews")
