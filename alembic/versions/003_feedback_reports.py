"""Add feedback_reports table (user-reported false positives/negatives)

Revision ID: 003
Revises: 002
Create Date: 2026-08-17 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Must match the ORM model (src/orm_models.py: Feedback).
    op.create_table(
        "feedback_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("reported_verdict", sa.String(), nullable=True),
        sa.Column("user_label", sa.String(), nullable=True),
        sa.Column("context", sa.String(), nullable=True),
        sa.Column("ext_version", sa.String(), nullable=True),
        sa.Column("client_id_hash", sa.String(), nullable=False),
        sa.Column("review_status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "review_status IN ('pending', 'reviewed', 'applied', 'rejected')",
            name="ck_feedback_reports_review_status",
        ),
    )
    op.create_index(
        op.f("ix_feedback_reports_url"), "feedback_reports", ["url"], unique=False
    )
    op.create_index(
        op.f("ix_feedback_reports_client_id_hash"),
        "feedback_reports",
        ["client_id_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_feedback_reports_client_id_hash"), table_name="feedback_reports"
    )
    op.drop_index(op.f("ix_feedback_reports_url"), table_name="feedback_reports")
    op.drop_table("feedback_reports")
