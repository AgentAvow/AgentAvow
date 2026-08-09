"""Add repo_claims.is_private — authoritative public/private flag set at claim
time. Public (topic-proof) claims are false; GitHub-App claims of private repos
are true. Drives the "publish to search" affordance. Purely additive, defaults
false.

Revision ID: t14
Revises: t13
Create Date: 2026-08-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t14"
down_revision = "t13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "repo_claims",
        sa.Column("is_private", sa.Boolean(), server_default="false", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("repo_claims", "is_private")
