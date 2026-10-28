"""Add community_scans.decision + decision_reason — the three-phrase answer
(safe | review | do_not_connect) and its reason, computed by
src.scanner.verdict.decide() over the full scan result when the row is captured.

Browse, the catalog API and the metrics dashboard decided from the stored score and
critical/high counts alone, so a tool with a published advisory or a deprecation read
Safe in Browse and Review on its own page (ledger #17). Purely additive, nullable: old
rows keep the recomputed-from-counts answer until their next scan writes the column.

Revision ID: t24
Revises: t23
Create Date: 2026-10-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "t24"
down_revision = "t23"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("community_scans", sa.Column("decision", sa.String(16), nullable=True))
    op.add_column("community_scans", sa.Column("decision_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("community_scans", "decision_reason")
    op.drop_column("community_scans", "decision")
