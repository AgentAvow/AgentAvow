"""Clear every stored watch answer written before the watch-decision fix.

t27 added ``tool_watches.last_decision`` / ``last_certified``. Until this fix the
watch loop decided the answer over a scan payload with no trust score, findings or
metadata, so every stored answer reads "review" (score 0/100) and no mark, whatever
the tool's real answer is. Kept, the first correct re-scan would compare against it
and send a spurious "answer improved" note or answer alert.

NULL is the loop's "no baseline yet" (src/jobs/scheduler.py AnswerChange): the next
re-scan stores the real answer silently and alerts only from the change after that.
Data only, no schema change. The backend entrypoint runs ``alembic upgrade head``
before the app (and so the re-scan loop) starts, so no re-scan reads an old value.

Revision ID: t28
Revises: t27
Create Date: 2026-11-10
"""
from __future__ import annotations

from alembic import op

revision = "t28"
down_revision = "t27"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "UPDATE tool_watches SET last_decision = NULL, last_certified = NULL "
        "WHERE last_decision IS NOT NULL OR last_certified IS NOT NULL"
    )


def downgrade() -> None:
    # The cleared values were wrong; there is nothing to restore.
    pass
