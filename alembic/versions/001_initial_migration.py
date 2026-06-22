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
    # Create phishing_urls table — must match the ORM model
    # (src/orm_models.py: PhishingURL.__tablename__ = "phishing_urls"), which is
    # also what SQLModel.metadata.create_all() builds at app startup. The index
    # name matches SQLModel's default (ix_<table>_<col>) so the two paths agree.
    op.create_table(
        "phishing_urls",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("is_phishing", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detection_time", sa.DateTime(), nullable=False),
        sa.Column("html_content", sa.Text(), nullable=True),
        sa.Column("features", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_phishing_urls_url"), "phishing_urls", ["url"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_phishing_urls_url"), table_name="phishing_urls")
    op.drop_table("phishing_urls")
