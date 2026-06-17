"""Initial migration

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create phishingurl table
    op.create_table(
        "phishingurl",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("is_phishing", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detection_time", sa.DateTime(), nullable=False),
        sa.Column("html_content", sa.Text(), nullable=True),
        sa.Column("features", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_phishingurl_id"), "phishingurl", ["id"], unique=False)
    op.create_index(op.f("ix_phishingurl_url"), "phishingurl", ["url"], unique=True)
    op.create_index(
        op.f("ix_phishingurl_detection_time"),
        "phishingurl",
        ["detection_time"],
        unique=False,
    )
    op.create_index(
        op.f("ix_phishingurl_is_phishing"), "phishingurl", ["is_phishing"], unique=False
    )


def downgrade() -> None:
    # Drop phishingurl table
    op.drop_index(op.f("ix_phishingurl_is_phishing"), table_name="phishingurl")
    op.drop_index(op.f("ix_phishingurl_detection_time"), table_name="phishingurl")
    op.drop_index(op.f("ix_phishingurl_url"), table_name="phishingurl")
    op.drop_index(op.f("ix_phishingurl_id"), table_name="phishingurl")
    op.drop_table("phishingurl")
